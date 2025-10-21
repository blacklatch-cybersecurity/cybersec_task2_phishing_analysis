#!/usr/bin/env python3
import sys, os, re, urllib.parse, email
from email import policy
from email.parser import BytesParser
from difflib import SequenceMatcher

brand_list = ["paypal","paypal.com","google","google.com","gmail","gmail.com","amazon","amazon.com","microsoft","microsoft.com","apple","apple.com"]
urgency_phrases = [r"verify your account", r"your account will be locked", r"action required", r"immediately", r"within 24 hours", r"update your information", r"unauthorized activity", r"confirm your identity"]
suspicious_tlds = [".ru", ".tk", ".cn", ".xyz", ".top", ".pw", ".click", ".info"]

def similar(a,b): return SequenceMatcher(None,a,b).ratio()
def extract_links_from_html(text): return re.findall(r'href=["\'](.*?)["\']', text, re.IGNORECASE)
def find_urls(text): return re.findall(r'https?://[^\s\'"<>()]+', text)

def parse_eml(path):
    with open(path,"rb") as f:
        return BytesParser(policy=policy.default).parse(f)

def auto_detect_eml():
    # Find first .eml in current directory
    files = [f for f in os.listdir(".") if f.lower().endswith(".eml")]
    return files[0] if files else None

def analyze(msg, raw_text):
    findings = []
    info = {
        "from": msg.get("From",""),
        "to": msg.get("To",""),
        "subject": msg.get("Subject",""),
        "date": msg.get("Date",""),
        "auth": msg.get("Authentication-Results",""),
        "received": msg.get_all("Received",[]) or []
    }

    # From & spoofing
    from_line = info["from"]
    findings.append(("From header", from_line.strip() or "(none)"))
    m = re.search(r'<?([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})>?', from_line)
    if m:
        domain = m.group(1).split("@",1)[1]
        for brand in brand_list:
            if similar(domain.lower(), brand.split(".")[0]) > 0.8 and brand.split(".")[0] not in domain.lower():
                findings.append(("Suspicious domain similarity", f"{domain} ≈ {brand}"))

    # Auth results
    auth = info["auth"]
    if not auth: findings.append(("Authentication-Results header","not present (may be suspicious)"))
    else:
        if "spf=fail" in auth.lower(): findings.append(("SPF result","FAIL"))
        if "dkim=fail" in auth.lower() or "dkim=none" in auth.lower(): findings.append(("DKIM result","failed or missing"))
        if "dmarc=fail" in auth.lower() or "dmarc=none" in auth.lower(): findings.append(("DMARC result","failed or missing"))

    # Links
    html_parts, text_parts = [], []
    for part in msg.walk():
        ctype = part.get_content_type()
        try: payload = part.get_content()
        except: payload = ""
        if ctype=="text/html": html_parts.append(str(payload))
        elif ctype=="text/plain": text_parts.append(str(payload))
    raw_all = "\n".join(html_parts + text_parts + [raw_text])
    urls = list(dict.fromkeys(find_urls(raw_all) + [*extract_links_from_html("\n".join(html_parts))]))
    if not urls: findings.append(("Links","No explicit http/https links found"))
    for u in urls:
        parsed = urllib.parse.urlparse(u)
        host = parsed.netloc.lower()
        for tld in suspicious_tlds:
            if host.endswith(tld): findings.append(("Suspicious TLD", u))
        if re.match(r'https?://\d+\.\d+\.\d+\.\d+', u): findings.append(("URL uses IP", u))

    # Urgency & tone
    for phrase in urgency_phrases:
        if re.search(phrase, raw_all, re.I):
            findings.append(("Urgency phrase detected", phrase))
    if re.search(r'hello (customer|user|member|client)', raw_all, re.I):
        findings.append(("Generic greeting","Uses generic greeting like 'Hello Customer'"))

    # Scoring
    score = 0
    for k,v in findings:
        if "SPF" in k or "DKIM" in k or "DMARC" in k: score += 4
        elif "Suspicious" in k or "Urgency" in k or "Generic" in k: score += 2
    verdict = "LOW RISK (but verify manually)"
    if score >= 6: verdict = "LIKELY PHISHING"
    elif score >= 3: verdict = "SUSPICIOUS — INVESTIGATE"
    return info, urls, findings, score, verdict

if __name__ == "__main__":
    # Automatic detection of .eml
    if len(sys.argv) < 2:
        target = auto_detect_eml()
        if not target:
            print("⚠️ No .eml file found in this directory. Please place one here.")
            sys.exit(1)
        print(f"📂 Automatically detected: {target}")
        path = target
    else:
        path = sys.argv[1]

    with open(path,"rb") as f: msg = BytesParser(policy=policy.default).parse(f)
    with open(path,"r",encoding="utf-8",errors="ignore") as f: raw_text=f.read()
    info, urls, findings, score, verdict = analyze(msg, raw_text)

    print("\n====== EMAIL SUMMARY ======")
    print(f"From: {info.get('from')}")
    print(f"To: {info.get('to')}")
    print(f"Subject: {info.get('subject')}")
    print(f"Date: {info.get('date')}")
    print(f"Detected URLs: {len(urls)}")
    for u in urls[:5]: print("  -", u)
    print("\n====== FINDINGS ======")
    for k,v in findings: print(f"- {k}: {v}")
    print("\nScore:", score)
    print("VERDICT:", verdict)
    print("=========================\n")
