# NetSweepX - Network Scanner and Deauthentication Tool

![Banner](https://img.shields.io/badge/NetSweepX-Wireless%20Network%20Scanner-blue)

## ⚠️ LEGAL DISCLAIMER

**THIS TOOL IS FOR EDUCATIONAL PURPOSES AND AUTHORIZED PENETRATION TESTING ONLY**

Use only on networks you own or have explicit permission to test. Team @Cyber_Squad6351 is not responsible for anything that happens. Use at your own risk.

By using this tool, you agree to use it responsibly and ethically, only on networks you own or have explicit permission to test.

## Description

NetSweepX is an advanced wireless network scanner and deauthentication tool designed for security professionals and network administrators. It allows for the discovery of wireless access points and connected clients, as well as the ability to perform deauthentication attacks for security testing purposes.

## Features

- **Wireless Network Scanning**: Discover nearby wireless networks and their details
- **Client Detection**: Identify devices connected to discovered networks
- **Monitor Mode**: Enable/disable monitor mode on wireless interfaces
- **Deauthentication Attack**: Perform targeted or broadcast deauthentication attacks for security testing
- **Cross-Platform**: Support for both Linux and Windows systems (with limitations on Windows)

## Requirements

- Python 3.6+
- Scapy library
- Wireless network adapter with monitor mode support
- Administrator/root privileges

## Installation

```bash
# Clone the repository
git clone https://github.com/cybersquad6351/NetSweepX.git

# Change to the directory
cd NetSweepX

# Install required dependencies
pip install -r requirements.txt

# Make the script executable
chmod +x NetSweepX.py
```

## Usage

The tool requires administrator/root privileges to enable monitor mode and perform packet injection:

```bash
# On Linux
sudo python3 NetSweepX.py

# On Windows (run as administrator)
python NetSweepX.py
```

### Main Menu Options

1. **Select Wireless Interface**: Choose the wireless adapter to use
2. **Enable Monitor Mode**: Switch the selected interface to monitor mode
3. **Scan for Networks**: Discover nearby wireless networks and connected clients
4. **List Discovered Networks**: View details of discovered access points and clients
5. **Perform Deauthentication Attack**: Execute targeted or broadcast deauthentication
6. **Disable Monitor Mode**: Return the interface to normal managed mode
7. **Exit**: Close the application

## Windows Compatibility Note

Full functionality on Windows requires specialized hardware and drivers. Standard Windows WiFi adapters have limited monitor mode and packet injection support. For best results on Windows:

- Use compatible external wireless adapters designed for penetration testing
- Install appropriate drivers that support monitor mode and packet injection
- Run with administrator privileges

## How It Works

NetSweepX operates by:

1. **Scanning**: Putting the wireless interface in monitor mode to capture all wireless frames
2. **Network Discovery**: Identifying access points through beacon frames
3. **Client Detection**: Monitoring data frames to identify devices connected to networks
4. **Deauthentication**: Sending specially crafted packets to disconnect clients from networks

## Legitimate Use Cases

- Wireless network security auditing
- Testing network access controls
- Identifying unauthorized access points
- Verifying client isolation policies
- Demonstrating wireless vulnerabilities for educational purposes

## Developer Information

- **Developer**: Aditya Mishra
- **Email**: mishraaditya.skm14@gmail.com
- **Website**: [cybersquad6351.netlify.app](https://cybersquad6351.netlify.app)
- **Instagram**: [@cyber__squad6351](https://www.instagram.com/cyber__squad6351/)
- **YouTube**: [Cyber_Squad6351](https://www.youtube.com/channel/Cyber_Squad6351)

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- This tool was created for educational purposes to understand wireless network security
- Thanks to the Scapy project for providing the packet manipulation library
- Thanks to all community members who provided feedback and suggestions

---

⚠️ **Remember**: Always obtain proper authorization before conducting any wireless network testing.

---

© 2025 Cyber Squad | Created for Network Security Education
