import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    'login', 'free', 'bonus', 'click', 'update', 'verify', 'gift', 'win', 'cheap'
]

SHORTENING_SERVICES = [
    'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'buff.ly'
]

def is_ip_in_url(netloc):
    return bool(re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', netloc))

def analyze_url(url):
    parsed = urlparse(url)
    netloc = parsed.netloc.lower()
    path = parsed.path.lower()
    score = 0

    findings = []

    if is_ip_in_url(netloc):
        score += 2
        findings.append("🔴 Uses IP address instead of domain")

    if any(keyword in path for keyword in SUSPICIOUS_KEYWORDS):
        score += 2
        findings.append("🟠 Contains suspicious keywords")

    if len(netloc.split('.')) > 3:
        score += 1
        findings.append("🟡 Has too many subdomains")

    if any(service in netloc for service in SHORTENING_SERVICES):
        score += 1
        findings.append("🟡 Uses URL shortening service")

    if len(url) > 75:
        score += 1
        findings.append("🟡 Unusually long URL")

    risk = "Low"
    if score >= 5:
        risk = "High"
    elif score >= 3:
        risk = "Medium"

    print(f"🛡️ Risk Level: {risk}")
    for f in findings:
        print(f"- {f}")

if __name__ == "__main__":
    url = input("🔗 Enter a URL to analyze: ").strip()
    analyze_url(url)
