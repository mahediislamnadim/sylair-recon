import subprocess
import requests
import re
import time
import threading
import queue
import json
import os
from datetime import datetime

# ==== CONFIG SECTION ====
GEMINI_API_KEY = "AIzaSyB_XHvxuU7rOJsNSCjasSy5jR-ZmvuXwew"  # <-- Gemini API key here
NVD_API_KEY = "6c27aad2-e7e9-4878-89c8-8b3c5260ed59"  # <-- Your NVD API key here

# ==== PRO OUTPUT COLOR ====
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# ==== SCANNER FUNCTIONS ====
def nmap_service_version_scan(target, output_xml="nmap_scan.xml"):
    print(f"{bcolors.OKBLUE}[+] Running nmap service/version scan on {target}...{bcolors.ENDC}")
    args = ["nmap", "-sV", "-T4", "-p-", "--min-rate", "1000", "--open", target, "-oX", output_xml]
    subprocess.run(args, capture_output=True)
    services = []
    with open(output_xml) as f:
        content = f.read()
    for line in content.splitlines():
        match = re.search(r'<service name="([^"]+)"(?: product="([^"]+)")?(?: version="([^"]+)")?', line)
        if match:
            name = match.group(1)
            product = match.group(2) or match.group(1)
            version = match.group(3) or ""
            services.append({"name": name, "product": product, "version": version})
    return services

def nvd_cve_search(product, version):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": f"{product} {version}",
        "resultsPerPage": 10,
    }
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    try:
        r = requests.get(url, params=params, headers=headers, timeout=30)
        if r.status_code != 200:
            print(f"{bcolors.WARNING}[NVD API Error] {r.status_code}: {r.text}{bcolors.ENDC}")
            return []
        try:
            data = r.json()
        except Exception as e:
            print(f"{bcolors.WARNING}[NVD API JSON Error] {e}\nRaw: {r.text}{bcolors.ENDC}")
            return []
        cvelist = []
        for cve in data.get("vulnerabilities", []):
            cveid = cve["cve"]["id"]
            desc = cve["cve"]["descriptions"][0]["value"][:200]
            cvelist.append({"cve": cveid, "desc": desc})
        return cvelist
    except Exception as e:
        print(f"{bcolors.WARNING}[NVD API Exception] {e}{bcolors.ENDC}")
        return []

def search_exploitdb(product, version):
    try:
        url = f"https://www.exploit-db.com/search?description={product}%20{version}"
        resp = requests.get(url, timeout=15)
        results = []
        for match in re.finditer(r'<a href="(/exploits/\d+)"[^>]*>([^<]+)</a>', resp.text):
            exp_url = "https://www.exploit-db.com" + match.group(1)
            title = match.group(2)
            if product.lower() in title.lower():
                results.append({"title": title, "url": exp_url})
        return results
    except Exception as e:
        return [{"title": "ExploitDB Error", "url": str(e)}]

def github_poc_search(product, version):
    query = f"{product} {version} exploit poc"
    url = f"https://github.com/search?q={requests.utils.quote(query)}"
    return [{"title": f"GitHub search: {query}", "url": url}]

def medium_blog_search(product, version):
    query = f"{product} {version} exploit"
    url = f"https://medium.com/search?q={requests.utils.quote(query)}"
    return [{"title": f"Medium blog search: {query}", "url": url}]

def query_gemini_for_poc(product, version):
    url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent"
    prompt = (
        f"""
Professional security research for {product} {version}:
- List all critical/public CVEs with short summaries.
- For each CVE, list public exploit PoC links (GitHub, ExploitDB, Packet Storm, blog, Medium, etc).
- Add detection, mitigation or real-world attack info if available.
Output as a clear, concise pentest report with links.
"""
    )
    headers = {"Content-Type": "application/json"}
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.15}
    }
    try:
        response = requests.post(f"{url}?key={GEMINI_API_KEY}", json=payload, headers=headers, timeout=60)
        data = response.json()
        if "candidates" in data and data["candidates"]:
            return data["candidates"][0]["content"]["parts"][0]["text"]
    except Exception as e:
        return f"[Gemini Error] {str(e)}"
    return "No Gemini output."

# ==== THREAD WORKER FOR PARALLEL SCAN ====
def service_worker(q, results, lock):
    while not q.empty():
        s = q.get()
        pname = f"{s['product']} {s['version']}".strip()
        with lock:
            print(f"{bcolors.HEADER}\n--- Scanning: {pname} ---{bcolors.ENDC}")
        # NVD
        cves = nvd_cve_search(s['product'], s['version'])
        # ExploitDB
        exploits = search_exploitdb(s['product'], s['version'])
        # GitHub
        gh = github_poc_search(s['product'], s['version'])
        # Medium/Blog
        med = medium_blog_search(s['product'], s['version'])
        # Gemini
        gemini = query_gemini_for_poc(s['product'], s['version'])
        result = {
            "service": pname,
            "nvd_cves": cves,
            "exploitdb": exploits,
            "github": gh,
            "medium": med,
            "gemini": gemini
        }
        with lock:
            print(f"{bcolors.OKCYAN}[NVD CVEs]{bcolors.ENDC}")
            for c in cves: print(f"  {bcolors.BOLD}{c['cve']}{bcolors.ENDC}: {c['desc']}")
            print(f"{bcolors.OKCYAN}[ExploitDB]{bcolors.ENDC}")
            for e in exploits: print(f"  {e['title']}: {e['url']}")
            print(f"{bcolors.OKCYAN}[GitHub]{bcolors.ENDC}")
            for g in gh: print(f"  {g['title']}: {g['url']}")
            print(f"{bcolors.OKCYAN}[Medium]{bcolors.ENDC}")
            for m in med: print(f"  {m['title']}: {m['url']}")
            print(f"{bcolors.OKCYAN}[Gemini AI summary]{bcolors.ENDC}\n{gemini}\n")
        results.append(result)
        q.task_done()

# ==== MAIN ====
def main():
    print(f"""{bcolors.HEADER}
=========================================
        SylAIR Recon
 Automated Intelligence Recon Tool
   Created by Mahedi Islam Nadim
========================================={bcolors.ENDC}""")
    target = input(f"{bcolors.BOLD}Target IP or domain: {bcolors.ENDC}")
    services = nmap_service_version_scan(target)
    print(f"{bcolors.OKBLUE}\n[+] {len(services)} detected services:{bcolors.ENDC}")
    for s in services:
        print(f"  - {bcolors.BOLD}{s['product']} {s['version']}{bcolors.ENDC}")
    print(f"{bcolors.OKBLUE}\n[+] Scanning all services for vulnerabilities (multi-threaded)...{bcolors.ENDC}")

    q = queue.Queue()
    results = []
    lock = threading.Lock()
    for s in services:
        q.put(s)
    threads = []
    for _ in range(min(len(services), 8)):  # up to 8 concurrent threads
        t = threading.Thread(target=service_worker, args=(q, results, lock))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    # === OUTPUT SAVE ===
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    save_dir = f"sylair_recon_{target}_{timestamp}"
    os.makedirs(save_dir, exist_ok=True)
    with open(os.path.join(save_dir, "report.json"), "w") as f:
        json.dump(results, f, indent=2)
    with open(os.path.join(save_dir, "report.md"), "w") as f:
        f.write(f"# SylAIR Recon\nCreated by Mahedi Islam Nadim\n\n")
        for res in results:
            f.write(f"## {res['service']}\n")
            f.write("### NVD CVEs\n")
            for c in res["nvd_cves"]:
                f.write(f"- **{c['cve']}**: {c['desc']}\n")
            f.write("### ExploitDB\n")
            for e in res["exploitdb"]:
                f.write(f"- [{e['title']}]({e['url']})\n")
            f.write("### GitHub\n")
            for g in res["github"]:
                f.write(f"- [{g['title']}]({g['url']})\n")
            f.write("### Medium/Blog\n")
            for m in res["medium"]:
                f.write(f"- [{m['title']}]({m['url']})\n")
            f.write("### Gemini AI summary\n")
            f.write(f"{res['gemini']}\n\n")
    print(f"{bcolors.OKGREEN}[+] Scan complete. Results saved in {save_dir}{bcolors.ENDC}")

if __name__ == "__main__":
    main()
