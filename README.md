# Automated Security Toolkit

A lightweight **cybersecurity toolkit** built in **Python** that analyzes logs, monitors systems, and detects suspicious activity across networks and files.
This project combines multiple defensive security tools into a single repository to simulate real-world security monitoring and threat detection workflows.

---

## Project Goal

The goal of this project is to build a **modular security monitoring toolkit** that helps detect and analyze potential threats in a system or network environment.

This includes:

* Detecting **suspicious IP activity** from logs
* Monitoring **real-time system logs** for attack patterns
* Identifying **open ports and exposed services**
* Tracking **file integrity changes**
* Analyzing **active network connections**

---

## Project Structure

```
Automated-IP-Filtering-Script/
│
├── ip_filter.py
├── log_monitor.py
├── connection_monitor.py
├── hash_checker.py
├── port_scanner.py
│
├── sample_log.txt
├── whitelist.txt
├── baseline.json
│
├── .gitignore
├── LICENSE
├── README.md
```

---

## Tech Stack

* Python (3.9+)
* Standard Libraries:

  * socket
  * hashlib
  * subprocess
  * argparse
  * threading (concurrent.futures)
* Linux networking tools (`ss`, `netstat`)

---

## Features

* **IP Log Analyzer**

  * Flags non-whitelisted IPs
  * Detects high request volume activity

* **Real-Time Log Monitor**

  * Detects:

    * Brute force attacks
    * SQL injection attempts
    * Directory traversal
    * Malware indicators

* **Connection Monitor**

  * Analyzes active network connections
  * Flags suspicious ports and foreign connections

* **File Integrity Monitor (FIM)**

  * Creates baseline hashes
  * Detects modified or deleted files

* **Port Scanner**

  * Scans for open ports
  * Identifies services
  * Assigns risk levels

---

## Installation Instructions

---

## Installation Guide

### 1. Prerequisites

Make sure you have:

* **Python 3.9+**
* Linux or macOS (recommended for networking tools)
* Basic terminal access

---

### 2. Clone the Repository

```bash
git clone https://github.com/yourusername/Automated-IP-Filtering-Script.git
cd Automated-IP-Filtering-Script
```

---

### 3. Run the Scripts

No external dependencies required (uses built-in Python libraries).

---

## Usage

### Run IP Filter

```bash
python3 ip_filter.py
```

### Run Log Monitor

```bash
python3 log_monitor.py sample_auth.log
```

### Run Connection Monitor

```bash
python3 connection_monitor.py
```

### Run File Integrity Monitor

```bash
# Create baseline
python3 hash_checker.py --baseline /path/to/files

# Verify integrity
python3 hash_checker.py --verify
```

### Run Port Scanner

```bash
python3 port_scanner.py example.com
```

---

## License

This project is licensed under the MIT License.

