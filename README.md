
## **README.md**

# **SOC Incident Detection & Response System** 🚀  
🔍 **Automated SOC analysis tool for detecting security threats using log correlation, threat intelligence APIs, and risk classification.**  

---

## **📌 Project Overview**  
This project simulates a **Security Operations Center (SOC) workflow** by:  
✅ **Ingesting security logs** (firewall logs, IDS alerts, Windows events)  
✅ **Performing automated threat intelligence checks** (IP reputation, malware detection, open ports)  
✅ **Generating structured incident reports** for rapid analysis  

🔗 **Uses APIs:**  
- **VirusTotal** 🦠 (file hash reputation)  
- **AbuseIPDB** 🛑 (IP risk scoring)  
- **Shodan** 🌐 (open ports & vulnerabilities)  

---

## **🛠️ Features**
- **Log Parsing & Security Event Detection**  
- **Threat Intelligence Correlation (IP, File, Ports)**  
- **Risk Level Classification (Low, High, Critical)**  
- **Automated CSV Report Generation**  
- **SOC-ready CLI Tool for Fast Analysis**  

---

## **📂 Installation & Setup**  
### **🔹 1. Clone the Repository**  
```bash
git clone https://github.com/ferasarabea/SOC-Incident-Detection-Response-System-.git
cd SSOC-Incident-Detection-Response-System-
```

### **🔹 2. Install Dependencies**  
```bash
pip install requests pandas shodan
```

### **🔹 3. Get API Keys**  
Sign up for API keys at:  
- **[VirusTotal](https://www.virustotal.com/gui/home)**  
- **[AbuseIPDB](https://www.abuseipdb.com/)**  
- **[Shodan](https://www.shodan.io/)**  

Edit `soc_analysis.py` and replace:
```python
VT_API_KEY = "your_virustotal_api_key"
ABUSE_IPDB_KEY = "your_abuseipdb_api_key"
SHODAN_API_KEY = "your_shodan_api_key"
```

---

## **🔎 How It Works**
### **1️⃣ Create a Log File (`security_logs.json`)**
Example:
```json
[
    {"timestamp": "2025-02-10T12:00:00", "event_type": "failed_login", "ip": "192.168.1.10"},
    {"timestamp": "2025-02-10T12:05:00", "event_type": "brute_force_attempt", "ip": "45.83.66.150"},
    {"timestamp": "2025-02-10T12:10:00", "event_type": "malware_detected", "file_hash": "d41d8cd98f00b204e9800998ecf8427e"}
]
```

### **2️⃣ Run the Script**
```bash
python soc_analysis.py
```

### **3️⃣ View the Incident Report (`incident_report.csv`)**
```csv
timestamp,event_type,ip,ip_risk_score,file_hash,malware_detection,open_ports,risk_level
2025-02-10T12:00:00,failed_login,192.168.1.10,N/A,N/A,N/A,N/A,Low
2025-02-10T12:05:00,brute_force_attempt,45.83.66.150,75,N/A,N/A,[22, 80],High
2025-02-10T12:10:00,malware_detected,N/A,N/A,d41d8cd98f00b204e9800998ecf8427e,{"malicious": 3, "suspicious": 2},"N/A",Critical
```

---

## **🖥️ Demo & Screenshots**
📌 **(Optional) Add CLI demo GIF or screenshots here**.

---

## **🚀 Future Improvements**
🔹 **Real-time SOC alerting system**  
🔹 **Integration with ELK Stack (Elasticsearch, Logstash, Kibana)**  
🔹 **Email notifications for critical alerts**  

---

## **📜 License**
This project is **open-source** under the **MIT License**.

---

## **🤝 Contributing**
Contributions are welcome!  
1. Fork the repo  
2. Create a feature branch  
3. Submit a pull request  

---

## **📧 Contact**
👨‍💻 **Feras Rabea**  
📍 San Antonio, TX  
📩 [ferasarabea@gmail.com](mailto:ferasarabea@gmail.com)  
 
