# sylair-recon
Automated Intelligence Reconnaissance (AIR) tool for vulnerability scanning, CVE enumeration, and security research.
# SylAIR Recon

**Automated Intelligence Reconnaissance (AIR) Tool**  
Created by Mahedi Islam Nadim

SylAIR Recon is a professional, multi-threaded vulnerability reconnaissance tool for security researchers and pentesters.  
It combines nmap service detection, NVD CVE enumeration, exploit/blog/PoC search, and Gemini AI summaries — all in one.

## Features
- High-speed nmap service/version scan
- Live CVE enumeration from NVD (API Key supported)
- ExploitDB, GitHub PoC, and Medium/blog search
- Gemini AI-powered vulnerability summaries
- Multi-threaded for fast scanning
- Professional markdown & JSON reporting
- Colorful terminal output

## Installation

```bash
git clone https://github.com/mahediislamnadim/sylair-recon.git
cd sylair-recon
pip install -r requirements.txt
# Make sure nmap is installed: sudo apt install nmap
```

## Usage

```bash
python3 sylair_recon.py
```
- Enter your target (IP or domain) when prompted.
- Set your NVD and Gemini API keys in the script.

## License

MIT

## Author

Mahedi Islam Nadim
