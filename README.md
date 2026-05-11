# 🚀 Advanced Network Sniffer

A Python-based advanced packet sniffer built using Scapy for monitoring and analyzing live network traffic.

## 📸 Tool Screenshot

![Ultimate Sniffer](screenshort.png)

## ⚡ Features

- Live Packet Capture
- TCP / UDP / ICMP Analysis
- Source & Destination IP Tracking
- Protocol Statistics
- Packet Payload Inspection
- PCAP File Saving
- Network Bandwidth Monitoring
- Top Talkers Detection

## 🛠 Technologies

- Python
- Scapy

## 📦 Installation

```bash
git clone https://github.com/nitishbhai7360/Advanced-Network-Sniffer.git
cd Advanced-Network-Sniffer
pip install -r requirements.txt
```

## ▶ Usage

### Linux

```bash
sudo python3 network_sniffer.py
```

### Windows

```bash
python network_sniffer.py
```

## 📌 Example Commands

Capture on interface:

```bash
sudo python3 network_sniffer.py -i eth0
```

Capture only 20 packets:

```bash
sudo python3 network_sniffer.py -c 20
```

Capture HTTP traffic:

```bash
sudo python3 network_sniffer.py -f "tcp port 80"
```

Verbose Mode:

```bash
sudo python3 network_sniffer.py -v
```

Save packets:

```bash
sudo python3 network_sniffer.py -s capture.pcap
```

## ⚠ Disclaimer

This tool is created for educational and ethical cybersecurity purposes only.
