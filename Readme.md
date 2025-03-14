# 🚀 NetSweepX - Advanced WiFi Network Scanner & Deauth Tool

## ⚠️ LEGAL DISCLAIMER
**NetSweepX is strictly for educational and authorized penetration testing purposes only.**  
Unauthorized use of this tool to attack networks **without explicit permission** is **illegal** and may lead to severe legal consequences.  
The developers are **not responsible for any misuse** of this tool.  

---

## 📌 About NetSweepX
**NetSweepX** is a powerful Python-based tool designed for **WiFi network scanning and deauthentication attacks**.  
It helps penetration testers and cybersecurity professionals to:  

✔ Scan nearby WiFi networks & connected clients 📡  
✔ Enable **Monitor Mode** on supported wireless interfaces ⚙️  
✔ Perform **Deauthentication Attacks** to test WiFi security 🔥  
✔ Detect & list connected clients on access points 🖥️  

> **Designed By:** [@Cyber_Squad6351](https://cybersquad6351.netlify.app)  
> **Version:** 1.2  
> **Supported OS:** Linux (Kali, Parrot, Ubuntu)  

---

## 🛠️ Installation & Setup  

### **1️⃣ Install Required Dependencies**
Ensure your system has **Python 3** installed. Then, install the required dependencies:    


```bash
sudo apt update && sudo apt install aircrack-ng iw net-tools python3-pip
pip install -r requirements.txt
```

### **2️⃣ Check Wireless Interface**
Before running NetSweepX, confirm that your WiFi adapter supports **Monitor Mode**:  

```bash
sudo airmon-ng
```
If your WiFi card **does not support monitor mode**, you may need an external adapter like **ALFA AWUS036NHA**.

### **3️⃣ Enable Monitor Mode (Optional)**
If NetSweepX does not enable monitor mode automatically, manually enable it:  

```bash
sudo airmon-ng start wlan0
```
This will change the interface to **wlan0mon**.

---

## 🚀 Usage Guide

### **1️⃣ Run NetSweepX**
Use root privileges to start the tool:  
```bash
sudo python3 NetSweepX.py
```

### **2️⃣ Select Wireless Interface**
Pick your **wireless interface** from the available options.

### **3️⃣ Enable Monitor Mode**
Enable **monitor mode** to start network scanning.

### **4️⃣ Scan for Networks**
Find available WiFi networks & connected clients.

### **5️⃣ Perform Deauthentication Attack**
Use **deauth packets** to disconnect clients from a WiFi network (⚠️ **Authorized use only!**).

---

## 🛡️ Security & Ethical Usage
- **For penetration testers:** Use this tool for **authorized security audits** only.
- **For WiFi admins:** Detect deauth attacks using **Wireshark or Kismet**.
- **Prevent deauth attacks:** Use **WPA3 & PMF (Protected Management Frames)**.

---

## 🔧 Troubleshooting

### **❓ Monitor Mode Not Working?**
Try enabling monitor mode manually:
```bash
sudo airmon-ng check kill
sudo airmon-ng start wlan0
```
Then, restart **NetSweepX**.

### **❓ Packet Injection Not Working?**
Run a test:
```bash
sudo aireplay-ng --test wlan0mon
```
If injection **fails**, your adapter **does not support packet injection**.

### **❓ Windows Support?**
❌ Windows does **not** fully support monitor mode or packet injection.  
💡 Consider using **Kali Linux on a live USB or virtual machine**.

---

## ✨ Contributors & Contact
- **Author:** [@Cyber_Squad6351](https://cybersquad6351.netlify.app)  
- **Instagram:** [Cyber__Squad6351](https://www.instagram.com/Cyber__Squad6351)  
- **Email:** mishraaditya.skm14@gmail.com  
- **YouTube:** [Cyber_Squad6351](https://www.youtube.com/channel/UCyourchannel)  

> **Found a bug?** Open an issue on [GitHub](https://github.com/yourrepo/NetSweepX).

---

## 📝 License
This project is **open-source** under the **MIT License**.
