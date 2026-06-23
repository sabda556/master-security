# Master Security (Automated IPS & SOC Tool)

**Master Security** is a lightweight, automated Intrusion Prevention System (IPS) and Security Operations Center (SOC) script built with Python. It is designed to monitor network traffic in real-time, mitigate potential threats via firewall rules, conduct automated forensic analysis, and maintain local threat intelligence persistence.

---

## 🚀 How It Works

The tool operates on a four-stage automated lifecycle when a network package is captured:
1. **Sniffing & Detection:** Uses `scapy` to intercept TCP packets on specified high-risk ports.
2. **Threshold Verification:** Tracks connection frequency. If an unwhitelisted IP hits the threshold, it triggers mitigation.
3. **Automated Mitigation:** Dynamically injects a `DROP` rule into `iptables` to isolate the attacker instantly.
4. **Forensic Scanning & Logging:** Launches an asynchronous `rustscan` to map the attacker's open ports and logs the raw telemetry into a localized SQLite3 database and JSON reports.

---

## 🛠️ Key Features

* **Real-Time Packet Inspection:** High-performance packet capturing using Scapy.
* **Smart Threat Profiling:** Automatically distinguishes between rapid-fire automated scans (`BOT`) and slower connection attempts (`HUMAN`).
* **Active Firewall Defense:** Instant threat isolation via native Linux `iptables` rule injection.
* **Automated Reconnaissance:** Leverages `rustscan` (Ultra-fast port scanner) to inspect the attacker's perimeter immediately after blocking.
* **Tor Circuit Rotation & Healing:** Routes outbound validation requests through SOCKS5 (`Tor`) with a 20-second dynamic IP rotation and automated proxy recovery.
* **TUI Dashboard:** An interactive Live Feed Terminal UI featuring state management, connection status, and real-time mitigation logs.

---

## 📁 Repository Structure

```text
master-security/
├── main.py             # Core script & TUI dashboard
├── requirements.txt    # Python dependencies
├── .gitignore          # Prevents tracking local logs and DB
├── soc_database.db     # SQLite3 persistence store (auto-generated)
└── SOC_Reports/        # Directory containing JSON and txt scans (auto-generated)
⚙️ Prerequisites & Dependencies
System Requirements
Linux OS (Kali Linux, Debian, or Ubuntu recommended)

Root privileges (sudo access required for network sniffing and iptables manipulation)

Tor Service and RustScan must be installed on the host system.
Installing Core Binary Packages:
sudo apt update
sudo apt install tor rustscan iptables -y

🔧 Installation & Setup
Clone the repository:
git clone (https://github.com/sabda556/master-security.git)
cd master-security

Install Python Dependencies:
pip install -r requirements.txt
Configure Tor: Ensure your Tor daemon is running and has the ControlPort enabled (typically port 9051) if you want the circuit healing feature to work natively.
sudo systemctl start tor

🚀 Usage
Execute the master script with root privileges:
sudo python3 main.py

Configuration Tuning
You can modify the constants directly inside main.py to match your lab environment:

SUSPICIOUS_PORTS: Ports to monitor (e.g., SSH, HTTP, HTTPS, Reverse Shell ports).

THRESHOLD: Number of attempts before triggering an automatic ban.

ROTATION_INTERVAL: Delay in seconds before changing the outbound Tor IP.

WHITELIST_IPS: Trusted network interfaces or local IP ranges that should never be blocked.

⚠️ Safety & Disclaimer
IMPORTANT: This tool is strictly developed for educational, security research, and isolated lab environments.

Because it automatically modifies system firewall rules (iptables), improper configuration or running it in a chaotic production network may cause False Positives, leading to self-inflicted Denial of Service (DoS) for legitimate clients. Use with caution. The developer assumes no liability for accidental lockouts or production downtime.
