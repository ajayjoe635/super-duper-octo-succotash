# Network Security Scanner

A Python-based network reconnaissance and vulnerability detection tool that automates security assessments using Nmap. This scanner identifies open ports, running services, potential vulnerabilities, and generates detailed security reports with real-time alerting.

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## 🔍 Overview

This tool was built to simulate SIEM-style threat detection by automating network scanning, vulnerability identification, and security reporting. It's designed for penetration testers, security analysts, and network administrators who need quick security assessments of target environments.

**Key Features:**
- 🎯 Automated network reconnaissance using Nmap
- 🔐 Service version detection and vulnerability mapping
- 🚨 Real-time alerting for high-risk findings
- 📊 JSON-formatted security reports
- 📝 Detailed logging for audit trails
- ⚡ Multi-threaded scanning for faster results

---

## 🛠️ Technical Stack

- **Language:** Python 3.8+
- **Core Library:** python-nmap
- **Network Scanner:** Nmap (must be installed separately)
- **Data Format:** JSON for structured reporting
- **Logging:** Python logging module for audit trails

---

## 📋 Prerequisites

Before running this scanner, ensure you have:

1. **Python 3.8 or higher** installed
2. **Nmap** installed on your system:
   - **Linux/macOS:** `sudo apt-get install nmap` or `brew install nmap`
   - **Windows:** Download from [nmap.org](https://nmap.org/download.html)
3. **Appropriate permissions** to scan target networks (only scan networks you own or have explicit permission to test)

---

## 🚀 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/ajayjoe635/super-duper-octo-succotash.git
cd super-duper-octo-succotash
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Verify Nmap Installation
```bash
nmap --version
```

---

## 💻 Usage

### Basic Scan
```bash
python src/main.py
```

### Command-Line Options
```bash
# Scan specific target
python src/main.py --target 192.168.1.1

# Scan subnet range
python src/main.py --target 192.168.1.0/24

# Custom port range
python src/main.py --target 192.168.1.1 --ports 1-1000

# Verbose output
python src/main.py --target 192.168.1.1 --verbose
```

---

## 📊 Output Examples

### Console Output
```
[*] Starting network scan on 192.168.1.1
[+] Host is up - Latency: 5ms
[!] ALERT: Open port 22 (SSH) detected
[!] ALERT: Open port 80 (HTTP) detected
[+] Service detected: OpenSSH 7.4 (potential CVE-2018-15473)
[*] Scan complete - 5 open ports found
[*] Report saved to: security_report.json
```

### JSON Report Structure
```json
{
  "scan_time": "2025-01-15T14:30:00",
  "target": "192.168.1.1",
  "open_ports": [
    {
      "port": 22,
      "service": "ssh",
      "version": "OpenSSH 7.4",
      "risk_level": "medium",
      "vulnerabilities": ["CVE-2018-15473"]
    }
  ],
  "summary": {
    "total_ports_scanned": 1000,
    "open_ports": 5,
    "high_risk_findings": 1
  }
}
```

---

## 🔒 Security & Legal Notice

**⚠️ IMPORTANT:** This tool is for **authorized security testing only**. 

- Only scan networks you own or have explicit written permission to test
- Unauthorized network scanning may violate local, state, and federal laws
- The author assumes no liability for misuse of this tool
- Always comply with your organization's security policies and applicable laws

---

## 🎯 Use Cases

- **Security Audits:** Quick assessment of network exposure
- **Penetration Testing:** Reconnaissance phase of security assessments
- **Network Inventory:** Documenting active services and versions
- **Compliance:** Identifying unauthorized services or outdated software
- **Learning:** Hands-on practice with network security concepts

---

## 🧪 Running Tests

```bash
# Run all unit tests
python -m unittest discover -s tests

# Run with verbose output
python -m unittest discover -s tests -v
```

---

## 📁 Project Structure

```
super-duper-octo-succotash/
├── src/
│   ├── __init__.py
│   ├── main.py              # Main scanner logic
│   ├── scanner.py           # Nmap wrapper and port scanning
│   ├── analyzer.py          # Vulnerability analysis
│   └── reporter.py          # Report generation
├── tests/
│   └── test_main.py         # Unit tests
├── requirements.txt         # Python dependencies
├── scanner.log              # Execution logs (generated at runtime)
├── security_report.json     # Scan results (generated at runtime)
└── README.md
```

---

## 🔧 Configuration

Edit `src/config.py` to customize:
- Default scan timeout
- Port ranges
- Alerting thresholds
- Report output format

---

## 🚧 Roadmap

- [ ] Add CVE database integration for automated vulnerability lookup
- [ ] Implement multi-target scanning with threading
- [ ] Add email alerting for critical findings
- [ ] Create web dashboard for report visualization
- [ ] Support for custom Nmap scripts (NSE)
- [ ] Docker containerization

---

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Ajay Joe**  
Cybersecurity Graduate | ISC2 Certified in Cybersecurity
- 🔗 LinkedIn: [linkedin.com/in/ajay-joe](https://linkedin.com/in/ajay-joe)
- 📧 Email: ajoe26718@gmail.com
- 📍 Location: Dallas-Fort Worth, Texas

---

## 🙏 Acknowledgments

- Built as part of cybersecurity education at University of North Texas
- Inspired by industry-standard vulnerability scanning tools
- Thanks to the Nmap project for providing the core scanning engine

---

## 📚 Related Projects

- [My OSINT Investigation Framework](https://github.com/ajayjoe635/osint-toolkit) *(if you create it)*
- [Security Automation Scripts](https://github.com/ajayjoe635/sec-automation) *(if you create it)*

---

**⭐ If you found this useful, please star the repo!**