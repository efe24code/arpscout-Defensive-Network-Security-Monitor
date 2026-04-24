# arpscout-Defensive-Network-Security-Monitor
# arpscout – Defensive Network Security Monitor

![Version](https://img.shields.io/badge/version-2.1-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.10%2B-yellow)

Defensive-only network security tool that detects ARP spoofing, MITM, Evil Twin APs, jamming attacks, and unknown devices in real-time. Cross-platform (Windows, Linux, macOS) with both CLI and GUI.

> ⚠️ **This tool is purely DEFENSIVE. It does NOT perform any offensive actions.**

---

## 🚀 Features

- **Wi-Fi Scanner** – Lists nearby networks with BSSID, channel, RSSI, auth/encryption; flags open/WEP networks
- **ARP Watch** – Passive ARP table polling for IP→MAC changes, gateway spoofing, IP conflicts
- **ARP Sniffer** – Live packet capture (Scapy + Npcap) for instant spoof detection, gratuitous ARP, ARP flood
- **Evil Twin Detection** – Alerts when same SSID appears on multiple BSSIDs
- **Jammer/Deauth Heuristics** – Mass AP disappearance/anomaly detection
- **Baseline Learning** – Learn known devices; alerts on new/unknown MACs
- **Database** – SQLite persistence (events, devices, networks)
- **Notifications** – Desktop alerts (Windows toast, Linux notify-send, macOS)
- **GUI** – Full Tkinter interface with real-time logs, status panel, Wi-Fi treeview, signal graphs
- **Export** – CSV/JSON/TXT log export

---

## 📦 Installation

```bash
# Clone repository
git clone https://github.com/yourusername/arpscout.git
cd arpscout

# Install dependencies
pip install -r requirements.txt

# Windows: Install Npcap for arp-sniff (https://nmap.org/npcap/)

# Show help
python arpscout.py --help

# Scan Wi-Fi networks
python arpscout.py wifi-scan

# Start ARP watch with notifications and DB
python arpscout.py --notify --db ~/.arpscout/arpscout.db arp-watch --interval 2.0

# Live ARP packet sniffing (requires Npcap on Windows)
python arpscout.py arp-sniff --timeout 60

# Learn current devices as baseline
python arpscout.py learn-baseline

# Export events
python arpscout.py export --file events.csv --format csv

# View stats
python arpscout.py stats
python gui.py
GUI includes menu bar, real-time event log, Wi-Fi network list, status panel, and quick control buttons. Settings dialog allows customization of intervals, database path, notifications, and more.

🔍 Detection Logic
Category	Level	Description
ARP_CHANGE	WARN	IP's MAC address changed unexpectedly
GATEWAY_SPOOF	CRITICAL	Gateway MAC changed (possible ARP spoof)
IP_CONFLICT	WARN	Same MAC found on multiple IPs
NEW_DEVICE	INFO	Unknown device detected
OPEN_WIFI	WARN	Open/unencrypted Wi-Fi network
WEP_WIFI	WARN	WEP-secured network (insecure)
EVIL_TWIN	WARN	Multiple APs with same SSID
SIGNAL_ANOMALY	WARN	Unusual signal strength difference (possible rogue AP)
DEAUTH_POSSIBLE	WARN	Mass AP disappearance (possible deauth/jammer)
GRATUITOUS_ARP	INFO	Gratuitous ARP packet detected
ARP_FLOOD	WARN	High rate of ARP packets (DoS/scan)
🗄️ Data Storage
All data stored in ~/.arpscout/:

arpscout.db – SQLite database (events, devices, networks)
known_devices.json – Baseline devices (MAC, IP, labels)
logs/ – Session logs (timestamped .log files)
gui_settings.json – GUI preferences
⚙️ Requirements
Python 3.10+
Required: scapy, psutil, matplotlib (optional for graphs)
Optional: win10toast (Windows notifications), netifaces (Linux/macOS)
See requirements.txt for details.

📋 Platform Notes
Windows: Uses netsh wlan for Wi-Fi scan. Run as Administrator for full ARP visibility. For arp-sniff, install Npcap.
Linux: Uses nmcli (NetworkManager) or iwlist. arp-sniff uses libpcap (usually pre-installed).
macOS: Uses airport CLI. arp-sniff uses built-in libpcap.
🛡️ Defense-Only Statement
This tool is designed for defensive monitoring and detection only. It does not:

Send ARP replies
Inject packets
Perform any active network manipulation
Store or transmit your data externally
All detection is done locally; no external communication.

📁 Project Structure
arpscout/
├── arpscout.py    # Core engine, CLI entry point
├── gui.py          # Tkinter GUI
├── KULLANIM.md     # Detailed Turkish user guide
└── requirements.txt # Python dependencies
🤝 Contributing
Contributions are welcome! Please open an issue or PR.

Fork the repository
Create a feature branch
Submit a pull request
📄 License
MIT License – see LICENSE for details.

⚠️ Disclaimer
This tool is for educational and authorized testing only. Use only on networks you own or have permission to monitor. Unauthorized network monitoring may violate laws/regulations.
