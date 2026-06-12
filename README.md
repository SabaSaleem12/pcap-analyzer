# Network Forensics Investigation Toolkit

## 📌 Overview
This project is a Network Forensics and Cybersecurity analysis tool built using Python and Kali Linux utilities such as Tshark and Capinfos. It automates the analysis of PCAP (packet capture) files and generates structured forensic reports, CSV exports, and visualizations to assist in digital investigations.

---

## 🚀 Features

- PCAP metadata extraction using Capinfos  
- Source IP address analysis  
- Destination IP address analysis  
- DNS query extraction and analysis  
- Protocol distribution analysis (TCP, UDP, ICMP)  
- Automated forensic report generation  
- CSV export for structured analysis (SIEM/Excel use)  
- Protocol visualization using pie chart  

---

## 🛠 Tools & Technologies Used

- Python 3  
- Scapy  
- Tshark (Wireshark CLI)  
- Capinfos  
- Matplotlib  
- Collections (Counter)  
- CSV module  

---

## 📂 Project Structure

pcap-analyzer/  
│  
├── analyzer.py                 # Main analysis script  
├── pcaps/                      # PCAP files (not included for privacy reasons)  
├── reports/                    # Generated outputs  
│   ├── investigation_report.txt  
│   ├── source_ips.csv  
│   ├── destination_ips.csv  
│   ├── dns_queries.csv  
│   └── protocol_chart.png  

---

## ▶ How to Run

### Install dependencies
pip install scapy matplotlib

### Install required system tools
sudo apt install tshark wireshark-common -y

### Run the script
python analyzer.py

---

## 📊 Output Generated

After execution, the tool generates:

- Full forensic investigation report (`reports/investigation_report.txt`)  
- CSV files for structured analysis:
  - Source IPs
  - Destination IPs
  - DNS queries  
- Protocol distribution chart (`reports/protocol_chart.png`)  

---

## 🔍 Use Cases

- Digital Forensics & Incident Response (DFIR)  
- SOC (Security Operations Center) analysis  
- Network traffic investigation  
- Cybersecurity learning projects  
- Internship portfolio project  

---

## ⚠️ Privacy Note

PCAP files are excluded from this repository to avoid exposing real network traffic or sensitive information.

---

## 👨‍💻 Author

Cybersecurity & Network Forensics Enthusiast  
Focused on Kali Linux tools, Python automation, and DFIR workflows  

---

## 📌 Status

✔ Working Prototype  
✔ Internship Ready  
✔ Portfolio Project
