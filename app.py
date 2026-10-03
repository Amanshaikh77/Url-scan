from flask import Flask, render_template, request
import tldextract
import socket
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re
import os

app = Flask(__name__)

# Terminal me: export NVIDIA_API_KEY="nvapi-..." ya yahan direct paste karein
NVIDIA_API_KEY = os.environ.get("NVIDIA_API_KEY", "")

def analyze_with_nvidia_ai(title, text_sample, domain):
    if not NVIDIA_API_KEY:
        return None

    try:
        url = "https://integrate.api.nvidia.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {NVIDIA_API_KEY}",
            "Content-Type": "application/json"
        }
        
        prompt = f"""You are a cybersecurity expert. Analyze this website:
Domain: {domain}
Title: {title}
Content snippet: {text_sample[:1000]}

Note: In India, sites with 'game', 'club', 'win', 'color prediction', 'matka', 'teen patti', 'aviator' are often unlicensed real-money gambling platforms.

Classify into EXACTLY ONE:
- Gambling / Betting
- Phishing / Scam
- Government / Official
- Legitimate / Safe

Format output:
CATEGORY: [Your Choice]
SUMMARY: [Short explanation in Hinglish/English]"""

        payload = {
            "model": "meta/llama-3.1-8b-instruct",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
            "max_tokens": 120
        }

        res = requests.post(url, headers=headers, json=payload, timeout=6)
        if res.status_code == 200:
            return res.json()["choices"][0]["message"]["content"].strip()
    except Exception:
        pass
    return None

def fallback_nlp_gambling(title, text_sample, domain):
    # Enhanced keywords for Indian gaming/gambling/color prediction
    core_gambling = [
        'bet', 'betting', 'casino', 'slot', 'slots', 'roulette', 'poker', 'jackpot',
        'aviator', 'color prediction', 'teen patti', 'rummy', 'win cash', 'deposit bonus',
        'cricket betting', 'satta', 'matka', '1xbet', 'betway', 'stake', 'lottery',
        'recharge bonus', 'withdraw', 'vip bonus', 'winstreak'
    ]
    
    # Suspicious domain combinations (e.g. veergame55, tirangagame, okwin, bigdaddy)
    domain_gambling_patterns = [r'game\d+', r'win\d*', r'bet\d*', r'club\d*', r'play\d*']

    full_content = (title + " " + text_sample).lower()
    domain_clean = domain.lower().replace('.', ' ')

    found_text = [w for w in core_gambling if w in full_content]
    domain_match = any(re.search(pat, domain.lower()) for pat in domain_gambling_patterns)

    if len(found_text) >= 1 or domain_match:
        matched = found_text if found_text else ["game/betting domain pattern"]
        return f"CATEGORY: Gambling / Betting\nSUMMARY: Real-money gaming / betting signature detected ({', '.join(matched[:3])})"
    
    return "CATEGORY: Legitimate / Safe\nSUMMARY: No suspicious gambling signatures detected."

def check_urlhaus_threat(domain):
    try:
        url = "https://urlhaus-api.abuse.ch/v1/host/"
        res = requests.post(url, data={"host": domain}, timeout=3).json()
        if res.get("query_status") == "ok":
            return f"Malicious ({len(res.get('urls', []))} threat reports)"
        return "Clean / Safe"
    except Exception:
        return "Clean / Safe"

def analyze_url(raw_url):
    raw_url = raw_url.strip()
    if not raw_url.startswith(('http://', 'https://')):
        url = 'https://' + raw_url
    else:
        url = raw_url

    parsed = urlparse(url)
    ext = tldextract.extract(url)
    domain_full = f"{ext.domain}.{ext.suffix}"

    data = {
        "url": raw_url,
        "domain": domain_full,
        "is_gov": False,
        "is_gambling": False,
        "ssl_secure": parsed.scheme == 'https',
        "final_url": url,
        "ip_address": "N/A",
        "country": "Unknown",
        "isp": "Unknown",
        "page_title": "No Title Found",
        "threat_intel": "Clean / Safe",
        "ai_category": "Analyzing...",
        "ai_summary": "",
        "verdict": "Likely Safe",
        "reasons": []
    }

    # 1. Government Check
    gov_suffixes = ['gov.in', 'nic.in', 'gov', 'mil.in', 'ac.in', 'edu.in', 'res.in']
    if any(domain_full.endswith(gov) for gov in gov_suffixes):
        data["is_gov"] = True
        data["reasons"].append("Official Government / Public Domain")

    # 2. Page Content Scrape
    page_text = ""
    try:
        resp = requests.get(url, timeout=4, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}, allow_redirects=True)
        data["final_url"] = resp.url
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        title_tag = soup.find('title')
        if title_tag and title_tag.string:
            data["page_title"] = title_tag.string.strip()[:65]
        
        for s in soup(['script', 'style', 'nav', 'footer']):
            s.decompose()
        page_text = ' '.join(soup.stripped_strings)[:1200]
    except Exception:
        data["reasons"].append("Site load fail / protected by Cloudflare")

    # 3. AI / NLP Classification
    ai_raw = analyze_with_nvidia_ai(data["page_title"], page_text, domain_full)
    ai_source = "NVIDIA AI"
    if not ai_raw:
        ai_raw = fallback_nlp_gambling(data["page_title"], page_text, domain_full)
        ai_source = "Local Engine"

    if "CATEGORY:" in ai_raw:
        cat_line = [l for l in ai_raw.split('\n') if "CATEGORY:" in l][0]
        data["ai_category"] = cat_line.replace("CATEGORY:", "").strip()
    else:
        data["ai_category"] = "Standard"

    if "SUMMARY:" in ai_raw:
        sum_line = [l for l in ai_raw.split('\n') if "SUMMARY:" in l][0]
        data["ai_summary"] = sum_line.replace("SUMMARY:", "").strip()
    else:
        data["ai_summary"] = ai_raw

    data["ai_category"] += f" ({ai_source})"

    # Gambling Flagging
    if "gambling" in data["ai_category"].lower() or "betting" in data["ai_category"].lower():
        data["is_gambling"] = True
        data["reasons"].append("Identified as real-money gaming / betting platform")

    # 4. IP & Geolocation
    try:
        host = urlparse(data["final_url"]).netloc.split(':')[0]
        ip = socket.gethostbyname(host)
        data["ip_address"] = ip
        
        geo_res = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
        if geo_res.get("status") == "success":
            data["country"] = geo_res.get("country", "Unknown")
            data["isp"] = geo_res.get("isp", "Unknown")
    except Exception:
        data["reasons"].append("Domain IP resolve fail")

    # 5. Live Threat Feeds
    threat_res = check_urlhaus_threat(domain_full)
    data["threat_intel"] = threat_res
    if "Malicious" in threat_res:
        data["reasons"].append("Blacklisted on cyber threat feeds")

    # 6. Deceptive / Spoofing Keywords
    keywords = ['login', 'verify', 'update', 'kyc', 'bonus', 'claim', 'aadhar', 'pan', 'reward']
    for kw in keywords:
        if kw in domain_full.lower() and not data["is_gov"] and not data["is_gambling"]:
            data["reasons"].append(f"Deceptive phishing keyword found: '{kw}'")

    if ('gov' in domain_full.lower() or 'nic' in domain_full.lower()) and not data["is_gov"]:
        data["reasons"].append("CRITICAL: Government impersonation detected (Fake Portal)")

    # Final Verdict
    if "CRITICAL: Government impersonation detected" in " ".join(data["reasons"]) or "Malicious" in threat_res:
        data["verdict"] = "High Risk / Fraud Detected"
    elif data["is_gambling"]:
        data["verdict"] = "Gambling / Real-Money Betting Site"
    elif data["is_gov"]:
        data["verdict"] = "Verified Government Site"
    elif len(data["reasons"]) >= 1 or not data["ssl_secure"]:
        data["verdict"] = "Suspicious / Review Required"
    else:
        data["verdict"] = "Standard / Likely Safe"

    return data

@app.route('/', methods=['GET', 'POST'])
def home():
    data = None
    if request.method == 'POST':
        raw_url = request.form.get('url', '').strip()
        if raw_url:
            data = analyze_url(raw_url)
    return render_template('index.html', data=data)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
