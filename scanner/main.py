import json
import httpx
import socket
import ssl
from datetime import datetime
from bs4 import BeautifulSoup

def calculate_score(result):
    score = 0

    if result["status"] == 200:
        score += 5

    headers = result.get("headers") or {}
    if "strict-transport-security" in headers:
        score += 20

    # Placeholder — real version detection not implemented yet
    has_old_library = False
    if has_old_library:
        score -= 10

    # Placeholder — real version detection not implemented yet
    has_old_server = False
    if has_old_server:
        score -= 20

    if result["ssl"] is None:
        score -= 30

    return score

def get_status_label(score):
    if score >= 40:
        return "🟢 En Güvenli"
    elif score >= 20:
        return "🟡 Güvenli"
    elif score >= 0:
        return "🟡 Sınırda"
    elif score >= -59:
        return "🔴 Riskli"
    else:
        return "🚨 Kritik Risk"

data = {"name": "test", "count": 5}
with open("scanner/output.json", "w", encoding="utf-8") as file:
    file.write(json.dumps(data))

with open("scanner/subdomains.txt", "r", encoding="utf-8") as file:
    subdomains = file.read().splitlines()
    print(subdomains)

base_domain = "example.com"
full_domains = [f"{s}.{base_domain}" for s in subdomains]
results = []

for each_domain in full_domains:
    result = {
        "domain": each_domain,
        "ip": None,
        "status": None,
        "server": None,
        "headers": None,
        "redirected": False,
        "redirect_chain": [],
        "ssl": None,
    }

    try:
        ip_address = socket.gethostbyname(each_domain)
        result["ip"] = ip_address
    except socket.gaierror:
        pass

    try:
        response = httpx.get(f"https://{each_domain}")
        result["status"] = response.status_code
        result["server"] = response.headers.get("server")
        result["redirected"] = len(response.history) > 0
        result["redirect_chain"] = [str(r.url) for r in response.history]
        result["headers"] = dict(response.headers)
        soup = BeautifulSoup(response.text, "html.parser")
        title_tag = soup.title
        result["title"] = title_tag.string if title_tag else None

        known_libraries = ["jquery", "react", "vue", "bootstrap", "angular"]
        detected = []
        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                for lib in known_libraries:
                    if lib in src.lower():
                        detected.append(lib)
        result["js_libraries"] = list(set(detected))

    except httpx.RequestError:
        pass

    try:
        context = ssl.create_default_context()
        with socket.create_connection((each_domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=each_domain) as ssock:
                cert = ssock.getpeercert()
                expiry_date = datetime.strptime(cert.get("notAfter"), "%b %d %H:%M:%S %Y %Z")
                result["ssl"] = {
                    "issuer": cert.get("issuer"),
                    "expires": cert.get("notAfter"),
                    "valid": datetime.now() < expiry_date,
                }
    except Exception:
        result["ssl"] = None

    result["scanDate"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    result["score"] = calculate_score(result)
    results.append(result)
    result["status_label"] = get_status_label(result["score"])


print(results)