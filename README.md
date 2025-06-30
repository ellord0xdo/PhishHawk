# PhishHawk – Advanced Email & URL Threat Scanner
**Author:** Ebrahim Aref – Cyber Security Engineer @ Sunrun

PhishHawk is a professional-grade Python tool for detecting phishing threats in email files (.eml) and URLs. Designed for security teams and organizations, it combines advanced analysis techniques and integrations with leading threat intelligence services to deliver comprehensive risk assessments.

---

## 🚀 Features
- **Email Header Analysis**
  - SPF, DKIM, and DMARC authentication checks
  - Header alignment and spoofing detection
- **Sender Reputation Checks**
  - WHOIS domain registration lookup
  - VirusTotal and AbuseIPDB integration for domain/IP reputation
- **URL Analysis**
  - Google Safe Browsing and IPQualityScore (IPQS) scanning
  - Lexical analysis for suspicious patterns, typosquatting, and risky TLDs
- **Email Content Inspection**
  - Phishing keyword detection (text/HTML)
  - Suspicious HTML forms and obfuscation techniques
- **Attachment Inspection**
  - Detection of risky file types and common malicious extensions
- **Risk Scoring & Verdict**
  - Aggregated phishing probability score
  - Clear verdict: Safe, Suspicious, or Phishing
- **User Interfaces**
  - Command-line interface (CLI)
  - Modern GUI (`phishhawk_gui.py`)

---

## 🛠️ How It Works
1. **Input:** Accepts an email file (.eml) or a direct URL.
2. **Extraction & Parsing:** Gathers headers, body, attachments, and URLs.
3. **Analysis Modules:** Runs header, sender, URL, content, and attachment checks.
4. **Threat Intelligence:** Queries VirusTotal, AbuseIPDB, Google Safe Browsing, and IPQS.
5. **Scoring:** Aggregates results using a weighted algorithm.
6. **Output:** Presents a detailed report and a final phishing verdict.

---

## 📦 Prerequisites
- Python 3.7 or higher
- Recommended Python packages (see `requirements.txt`):
  - `requests`
  - `beautifulsoup4`
  - `dnspython`
  - `python-whois`
  - `tabulate`
  - `html5lib`
  - `PyQt5` (for GUI)

---

## ⚙️ Setup Instructions
1. **Clone the Repository**
   ```bash
   git clone https://github.com/ellord0xdo/PhishHawk.git
   cd PhishHawk
   ```
   *Windows users:* You can use Git Bash, PowerShell, or Command Prompt. If you don't have Git installed, download it from [git-scm.com](https://git-scm.com/).

2. **Create and Activate a Virtual Environment (Recommended)**
   - **Linux/macOS:**
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```
   - **Windows (Command Prompt):**
     ```bash
     python -m venv venv
     venv\Scripts\activate
     ```
   - **Windows (PowerShell):**
     ```bash
     python -m venv venv
     .\venv\Scripts\Activate.ps1
     ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

---

## 🔑 API Key Configuration
PhishHawk requires API keys for full functionality. **Do not hardcode API keys in the code.** Set them as environment variables:

- `VIRUSTOTAL_API_KEY` – [Get a key](https://www.virustotal.com/gui/join-us)
- `ABUSEIPDB_API_KEY` – [Get a key](https://www.abuseipdb.com/register)
- `GOOGLE_SAFE_Browse_API_KEY` – [Get a key](https://developers.google.com/safe-browsing/v4/get-started)
- `IPQS_API_KEY` – [Get a key](https://www.ipqualityscore.com/signup)

**Example (Linux/macOS):**
```bash
export VIRUSTOTAL_API_KEY="your_actual_virustotal_key"
export ABUSEIPDB_API_KEY="your_actual_abuseipdb_key"
export GOOGLE_SAFE_Browse_API_KEY="your_actual_google_key"
export IPQS_API_KEY="your_actual_ipqs_key"
```
**Example (Windows, PowerShell):**
```powershell
$Env:VIRUSTOTAL_API_KEY="your_actual_virustotal_key"
$Env:ABUSEIPDB_API_KEY="your_actual_abuseipdb_key"
$Env:GOOGLE_SAFE_Browse_API_KEY="your_actual_google_key"
$Env:IPQS_API_KEY="your_actual_ipqs_key"
```

---

## 🖥️ Usage
### Command-Line Interface (CLI)
```bash
# Analyze an email file
python phishhawk_scanner.py --email path/to/email.eml

# Analyze a single URL
python phishhawk_scanner.py --url "https://suspicious-example.com/login"

# Analyze a URL and output to a file
python phishhawk_scanner.py --url "https://example.com" --output report.txt

# Display help message
python phishhawk_scanner.py --help
```

### Graphical User Interface (GUI)
Launch the GUI for a user-friendly experience:
```bash
python phishhawk_gui.py
```

---

## 📄 License
This project is intended for professional and educational use. Please review your organization's policy before deploying in production environments.




