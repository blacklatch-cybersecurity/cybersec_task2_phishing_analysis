# 🛡️ CyberSec Task 2 — Phishing Email Analyzer  

A lightweight **Phishing Email Detection Tool** built for cybersecurity interns and analysts to analyze `.eml` email files for potential phishing indicators.  

---

## 📌 Overview  

This project detects phishing attempts by analyzing email headers, authentication failures, URLs, and content-based red flags.  

✅ Works fully **offline**  
✅ **Auto-detects .eml files** — no need to rename  
✅ Uses only **built-in Python libraries** (no installation needed)  

---

## ⚙️ Installation  

### 1️⃣ Clone the repository  
```bash
git clone https://github.com/blacklatch-cybersecurity/cybersec_task2_phishing_analysis.git
cd cybersec_task2_phishing_analysis

Make sure Python 3 is installed
python3 --version

If not installed:
sudo apt update && sudo apt install python3 -y

📬 How to Analyze Emails
🧪 Option 1 — Use included safe demo
python3 analyze_email.py phishing_sample.eml

⚡ Option 2 — Auto-detect mode
Just place your .eml file in the folder and run:
python3 analyze_email.py

The tool automatically finds and analyzes the first .eml file.

Option 3 — Analyze Gmail email

In Gmail, open the suspicious message → click ⋮ (three dots) → Show original

Click Download Original

Move it into this project folder:

mv ~/Downloads/original_message.eml suspicious.eml


Run the analyzer:
python3 analyze_email.py suspicious.eml

🔍 Example Output
📂 Automatically detected: suspicious.eml

====== EMAIL SUMMARY ======
From: "PayHelp Support" <security@paypa1.example.com>
To: victim@example.com
Subject: URGENT: Verify Your Account Now
Date: Fri, 10 Oct 2025 09:23:40 +0000
Detected URLs: 1
  - http://example.com/verify

====== FINDINGS ======
- Suspicious domain similarity: paypa1.example.com ≈ paypal
- SPF result: FAIL
- DKIM result: failed or missing
- DMARC result: failed or missing
- Urgency phrase detected: verify your account
- Generic greeting: Uses generic greeting like 'Hello Customer'

Score: 9  
VERDICT: **LIKELY PHISHING**
=========================

🧾 Understanding Verdicts
Verdict	Meaning	Recommended Action
LIKELY PHISHING	Multiple red flags detected	Report or delete immediately
SUSPICIOUS — INVESTIGATE	Some red flags; verify sender and links	Inspect manually
LOW RISK	No strong phishing indicators found	Still confirm before clicking any links

🧠 Developer Tips

Run analyzer on all .eml files in the folder:

for f in *.eml; do
  python3 analyze_email.py "$f"

Then just run:
analyze_phish

🔐 Safety Notes

⚠️ Do NOT open suspicious emails or attachments directly.
This tool only reads .eml files as text — no scripts are executed.
Use for analysis and education only.

🌐 Author

Created by: BlackLatch Cybersecurity
Platform: Parrot OS (Linux)
Language: Python 3

🪪 License

Licensed under the MIT License — free for educational and research use.

🚀 Quick Start Summary
git clone https://github.com/blacklatch-cybersecurity/cybersec_task2_phishing_analysis.git
cd cybersec_task2_phishing_analysis
python3 analyze_email.py


✅ The analyzer automatically finds your .eml file and reports whether it’s phishing or safe.
