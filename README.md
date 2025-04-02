# Q-MITM - Man-in-the-Middle Attack Tool

🚀 **A tool for intercepting and analyzing DNS queries within a network using MITM (Man-in-the-Middle).**

![Q-MITM Logo](https://i.postimg.cc/26GwH0gy/Screenshot-from-2025-04-02-23-02-31.png)  

## ✨ **Features:**
✅ Launch **ARP Spoofing** attacks to intercept network traffic.  
✅ Monitor **DNS queries** from all connected devices.  
✅ Extract **PTR reverse queries** to identify device names.  
✅ **Professional design** using ASCII Art for tool branding.  
✅ Enhanced **color-coded output** for better readability.  

---

## 📌 **Installation & Usage**

### 🔹 **1️⃣ Install Dependencies:**
Ensure you have `Python3` installed, then run the following command to install the required libraries:
```bash
pip install -r requirements.txt
```

### 🔹 **2️⃣ Run the Tool:**
If root privileges are required, use:
```bash
sudo python3 Q-MITM.py
```

### 🔹 **3️⃣ Configure Network Monitoring:**
Upon running the tool, you will be prompted to enter:
- **Local network range (e.g., `192.168.1.0/24`)**
- **Gateway address of the network**
- **Network interface (e.g., `eth0` or `wlan0`)**

### 📌 **Expected Output:**
```
[+] Network traffic monitoring started...
--------------------------------------------------------
Time                IP Address          DNS Query
--------------------------------------------------------
2025-04-02 12:30:45  192.168.1.2     example.com
2025-04-02 12:31:12  192.168.1.3    google.com
```

---

## 🛠 **Requirements**
✅ **Python 3.6+**  
✅ `Scapy` for network packet analysis  
✅ `Colorama` for improved terminal output  
✅ `PyFiglet` for ASCII Art generation  

**📌 Note:** Ensure you run the tool with `root` privileges to successfully intercept network packets.

---

## ⚠️ **Legal Disclaimer**
🚨 **This tool is intended for educational and ethical penetration testing purposes only.**  
❌ **Any illegal use of this tool is solely your responsibility.**  
✅ Only use it on networks where you have explicit permission to test.

---

## 🌟 **Contributing to the Project**
Do you have ideas or improvements? Feel free to contribute! Fork the repository and submit a Pull Request.  

### 📬 **Contact:**
📌 **GitHub:** [github.com/yourusername] 

---

### ⭐ **If you find this tool useful, don't forget to star the repository!** ⭐