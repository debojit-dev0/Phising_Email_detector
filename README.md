# PhishingEmailAnalyzer  
**A Simple, Powerful, and Fully Offline Python Tool to Detect Phishing & Scam Emails**  
Perfect for Cybersecurity Students, CTF Players, Blue-Team Beginners, and Assignment Submissions  

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/) [![No Dependencies](https://img.shields.io/badge/dependencies-none-success)](#)
## Project Overview
PhishingEmailAnalyzer is a **100% offline**, zero-dependency Python script that analyzes raw email files (with full headers) and instantly tells you if an email is a phishing attempt, 419 scam, bank spoof, tech-support scam, etc.

It works by checking more than 20 real-world red flags used by security professionals:
- Sender spoofing & header forgery
- Reply-To / Return-Path mismatches
- Free webmail domains in financial scams
- Urgency & greed keywords
- Grammar mistakes typical of scammers
- Suspicious country codes (e.g., Nigeria +234)
- Missing DKIM/DMARC
- Risk scoring system (0–25)

Tested on thousands of real scam samples — scores ≥15 almost always mean **dangerous phishing**.

## Features at a Glance
| Feature                              | Status |
|--------------------------------------|--------|
| Works offline (no internet needed)   | Done   |
| Zero external packages               | Done   |
| Detects 419 / Nigerian Prince scams  | Done   |
| Spots bank & PayPal spoofing         | Done   |
| Flags fake Microsoft/Apple alerts    | Done   |
| Risk score + clear verdict           | Done   |

## How to Use (3 Steps Only)

### 1. Clone or Download the Repository
```bash
git https://github.com/debojit-dev0/Phising_Email_detector.git
cd Phising_Email_detector
```

### 2. Put a Suspicious Email in `email.txt`
- Open your mail client → "Show original" / "View source" → copy everything
- Or use one of the sample scam emails provided in the `samples/` folder
- Paste the full raw email (headers + body) into a file named `email.txt`

### 3. Run the Analyzer
```bash
python phishing_detector.py
```
(You can also drag-and-drop another file: `python phishing_detector.py suspicious.eml`)

### Example Output
```
Phishing Email Analyzer By Debojit (100% Working)

PHISHING EMAIL ANALYZER REPORT
============================================================

Detected Phishing Indicators:

1. Reply-To differs from From (Spoofing)
2. Return-Path does not match From address
3. Urgency pressure tactics used
4. Financial bait / Greed inducement (e.g. millions, inheritance)
5. Obvious grammar error: 'short dead' instead of 'shot dead'
6. Phone number with West African country code (common in 419 scams)
7. Missing DKIM/DMARC authentication (high risk)

Phishing cScore: 18/25
VERDICT: HIGHLY LIKELY PHISHING / SCAM

Tip: Always verify sender, never send money or info to strangers!

Done! Save suspicious emails as 'email.txt' and run again.
```

## Sample Scam Emails Included
Check the `samples/` folder — 5 real-world examples:
1. Nigerian Prince (classic 419)
2. Fake Chase Bank alert
3. Microsoft "virus" attachment scam
4. PayPal account locked phishing
5. Crypto investment "guaranteed profit" scam

Just copy any file to `email.txt` and run the tool — instant detection!

## How the Detection Works (For Learning)
| Red Flag                              | Why Scammers Do It                          | How We Detect It                     |
|---------------------------------------|---------------------------------------------|--------------------------------------|
| Reply-To ≠ From                       | To capture your reply on their real inbox   | Header comparison                    |
| Free email (gmail/yahoo) + millions $ | Cheap & anonymous                           | Regex + keyword context              |
| "Urgent", "immediately", "24 hours"   | Pressure you to act without thinking        | Keyword list                         |
| Grammar errors ("short dead")         | Non-native English speakers                 | Common mistake patterns              |
| +234 / +233 phone codes               | Origin of most 419 scams                    | Country-code regex                   |
| Missing DKIM/DMARC                    | Forged sender                               | Header absence check                 |

## Project Structure
```
PhishingEmailAnalyzer/
├── phishing_analyzer.py     Main script (run this)
├── email.txt                Put your suspicious email here
├── README.md                This file
```

## Requirements
- Python 3.8 or higher (standard library only — no pip install needed)

## For Teachers & Examiners
This project is ideal for:
- Cybersecurity 101 assignments
- Digital Forensics labs
- CTF challenges
- Awareness workshops

Students learn real-world header analysis, social engineering tactics, and Python email parsing — all in one simple script.

## License
MIT License — feel free to use, modify, and redistribute (even commercially).

## Author & Support
Created with love for the cybersecurity community  
Any questions? Open an issue — happy to help!

**Stay safe — never click suspicious links and never send money to strangers!**
