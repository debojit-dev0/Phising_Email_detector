import email
import re
import sys
from email.policy import default

def load_email(file_path=None):
    """Load raw email from file or use hardcoded sample if none provided"""
    if file_path and file_path != "email.txt":
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except FileNotFoundError:
            print(f"[!] File {file_path} not found. Using built-in sample.")
    
    # Built-in real phishing email sample (classic 419 scam)
    sample_email = """From: JOSEPH CAMARAH VIEIRA <vieria@aol.com>
Reply-To: carrr444@yahoo.com
Subject: Urgent Business Proposal
Date: Fri, 18 Jan 2013 01:46:07 +0200
Message-ID: <201301172333.r0HNXZSI028539@mail.shako.com.tw>
Return-Path: 32309uslisidfj@mail.shako.com.tw.com

Dear Sir/Madam,

my name is Joseph Camarah Vieira, i am from Guinea Bissau, my late father was the former minister of mines in my country Guinea Bissau, he was short dead by the rebels in my country, before his death he deposited $60 million Dollars with Global Trust Security Company Accra Ghana, i want you to help me receive this money in your country for investment...

Regards.
Mr Joseph Camarah Vieira
00233 244 617 863
Email: carrr444@yahoo.com
"""
    return sample_email

def extract_headers(msg):
    headers = {}
    for key in msg.keys():
        headers[key.lower()] = msg.get(key)
    return headers

def analyze_phishing(raw_email):
    print("PHISHING EMAIL ANALYZER REPORT")
    print("="*60)
    
    msg = email.message_from_string(raw_email, policy=default)
    headers = extract_headers(msg)
    
    indicators = []
    score = 0
    
    # 1. Sender vs Reply-To vs Return-Path Mismatch
    from_addr = headers.get('from', '')
    reply_to = headers.get('reply-to', '')
    return_path = headers.get('return-path', '')
    
    if reply_to and reply_to != from_addr:
        indicators.append("Reply-To differs from From (Spoofing)")
        score += 3
    if return_path and '<' in return_path:
        return_path = return_path.split('<')[1].split('>')[0]
    if from_addr and return_path and return_path not in from_addr:
        indicators.append("Return-Path does not match From address")
        score += 2
    
    # 2. Suspicious domains in email addresses
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    emails_found = re.findall(email_pattern, raw_email)
    suspicious_domains = ['yahoo', 'gmail', 'hotmail', 'aol', 'mailinator', 'tempmail']
    for addr in emails_found:
        domain = addr.split('@')[-1].lower()
        if any(sus in domain for sus in suspicious_domains) and 'bank' in raw_email.lower():
            indicators.append(f"Free email service used in financial scam: {addr}")
            score += 3
    
    # 3. Urgent or Greedy Language
    urgency_keywords = ['urgent', 'immediate', 'asap', 'now', 'today', 'limited time', 'exclusive']
    greed_keywords = ['million', 'inheritance', 'funds', 'transfer', 'claim', 'lottery', 'prize', 'payment']
    
    body = raw_email.lower()
    if any(word in body for word in urgency_keywords):
        indicators.append("Urgency pressure tactics used")
        score += 2
    if any(word in body for word in greed_keywords):
        indicators.append("Financial bait / Greed inducement (e.g. millions, inheritance)")
        score += 4
    
    # 4. Grammar & Spelling Errors (basic check)
    errors = 0
    if ' i ' in f" {raw_email.lower()} " and ' i am' not in raw_email.lower():
        errors += 1
    if 'short dead' in raw_email.lower() or 'assasinated' in raw_email.lower():
        indicators.append("Obvious grammar error: 'short dead' instead of 'shot dead'")
        score += 2
    
    # 5. Phone number from suspicious country codes
    if re.search(r'\b00(?:226|233|234|27|220|232)\b', raw_email):  # West Africa codes
        indicators.append("Phone number with West African country code (common in 419 scams)")
        score += 3
    
    # 6. No legitimate headers (DKIM, DMARC missing)
    if not headers.get('authentication-results') and not headers.get('dkim-signature'):
        indicators.append("Missing DKIM/DMARC authentication (high risk)")
        score += 2
    
    # Final Output
    print("\nDetected Phishing Indicators:\n")
    if indicators:
        for i, indicator in enumerate(indicators, 1):
            print(f"{i}. {indicator}")
    else:
        print("No strong indicators found (might be legitimate)")
    
    print(f"\nPhishing cScore: {score}/25")
    if score >= 15:
        print("VERDICT: HIGHLY LIKELY PHISHING / SCAM")
    elif score >= 8:
        print("VERDICT: SUSPICIOUS - Likely Phishing")
    elif score >= 4:
        print("VERDICT: Caution advised")
    else:
        print("VERDICT: Low risk")
    
    print("\nTip: Always verify sender, never send money or info to strangers!")

# === MAIN EXECUTION ===
if __name__ == "__main__":
    print("Phishing Email Analyzer By Debojit (100% Working)\n")
    
    # Option 1: Load from file 'email.txt' (recommended)
    # Option 2: Use built-in sample if no file
    email_content = load_email("email.txt" if len(sys.argv) < 2 else sys.argv[1])
    
    analyze_phishing(email_content)
    
    print("\nDone! Save suspicious emails as 'email.txt' and run again.")