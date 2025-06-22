import os
import sys
import re
import socket
import ssl
import threading
import queue
import random
import string
import requests
from urllib.parse import urlparse, urljoin
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# --- Utility functions ---

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def press_any_key():
    print(Fore.RED + "\nPress any key to return to the tool..." + Style.RESET_ALL, end='', flush=True)
    try:
        import msvcrt
        msvcrt.getch()
    except ImportError:
        import tty, termios
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    clear_screen()
    banner()

def print_red(text):
    print(Fore.RED + text + Style.RESET_ALL)

def print_header(title):
    clear_screen()
    print(Fore.RED + "="*60)
    print(f"  {title}")
    print("="*60 + Style.RESET_ALL)

def banner():
    clear_screen()
    print(Fore.RED + r"""
888    d8P  8888888 888b    888      88888888888 .d88888b.   .d88888b.  888      
888   d8P     888   8888b   888          888    d88P" "Y88b d88P" "Y88b 888      
888  d8P      888   88888b  888          888    888     888 888     888 888      
888d88K       888   888Y88b 888          888    888     888 888     888 888      
8888888b      888   888 Y88b888          888    888     888 888     888 888      
888  Y88b     888   888  Y88888          888    888     888 888     888 888      
888   Y88b    888   888   Y8888          888    Y88b. .d88P Y88b. .d88P 888      
888    Y88b 8888888 888    Y888          888     "Y88888P"   "Y88888P"  88888888
  """ + Style.RESET_ALL)

def link_downloader():
    print_header("Link Downloader")
    url = input(Fore.RED + "[~] Enter the file URL to download: " + Style.RESET_ALL).strip()

    filename = url.split('/')[-1]
    if not filename:
        print_red("[!] URL does not contain a filename to save.")
        press_any_key()
        return

    try:
        r = requests.get(url, stream=True, timeout=15)
        r.raise_for_status()
        with open(filename, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
        print_red(f"[+] File downloaded successfully as '{filename}'")
    except Exception as e:
        print_red(f"[!] Download failed: {e}")

    press_any_key()



# === 1. Website Vulnerability Scanner (Basic) ===
def website_vuln_scanner():
    print_header("Website Vulnerability Scanner")
    url = input(Fore.RED + "[~] Enter target URL (http/https): " + Style.RESET_ALL).strip()
    if not url.startswith("http"):
        url = "http://" + url
    if url.endswith('/'):
        url = url[:-1]

    print_red("[*] Starting vulnerability scan on: " + url)

    vulns_found = []

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; RedTigerTools/1.0; +https://github.com/loxy0dev)"})

    # 1) Check for exposed sensitive files/directories
    common_sensitive_paths = [
        ".env", "config.php", "config.yaml", "backup.zip", "db.sql",
        "admin.php~", "wp-config.php", "config.inc.php", "phpinfo.php",
        "robots.txt", ".git/config", "readme.html", "LICENSE.txt"
    ]

    for path in common_sensitive_paths:
        test_url = url + "/" + path
        try:
            r = session.get(test_url, timeout=6)
            if r.status_code == 200:
                snippet = r.text[:200].lower()
                if any(keyword in snippet for keyword in ["define", "db_password", "mysql", "password", "<?php", "user"]):
                    vulns_found.append(f"Exposed sensitive file: {test_url}")
                elif path in ["robots.txt", "readme.html", "LICENSE.txt"]:
                    vulns_found.append(f"Public file accessible: {test_url}")
            elif r.status_code in [403, 401]:
                vulns_found.append(f"Access restricted to sensitive file (possible misconfig): {test_url} (HTTP {r.status_code})")
        except:
            pass

    # 2) Check HTTP security headers
    try:
        r = session.get(url, timeout=8)
        headers = r.headers
        security_headers = {
            "X-Frame-Options": "Clickjacking protection",
            "Content-Security-Policy": "Content Security Policy",
            "X-Content-Type-Options": "MIME sniffing protection",
            "Strict-Transport-Security": "HSTS",
            "Referrer-Policy": "Referrer Policy",
            "Permissions-Policy": "Permissions Policy"
        }

        for h, desc in security_headers.items():
            if h not in headers:
                vulns_found.append(f"Missing security header: {h} ({desc})")
            else:
                if h == "X-Frame-Options" and headers[h].lower() not in ["deny", "sameorigin"]:
                    vulns_found.append(f"Weak X-Frame-Options header: {headers[h]}")
                if h == "Strict-Transport-Security" and "max-age=0" in headers[h]:
                    vulns_found.append(f"HSTS header present but max-age=0 (ineffective)")

        server_banner = headers.get("Server", "")
        if server_banner:
            print_red(f"[i] Server banner: {server_banner}")

        powered_by = headers.get("X-Powered-By", "")
        if powered_by:
            vulns_found.append(f"X-Powered-By header reveals info: {powered_by}")

    except Exception as e:
        print_red(f"[!] Error fetching headers: {e}")

    # 3) Check for directory listing enabled (basic)
    common_dirs = ["admin", "uploads", "backup", "backup-old", "files", "images", "data"]
    for d in common_dirs:
        try:
            dir_url = url + "/" + d + "/"
            r = session.get(dir_url, timeout=5)
            if r.status_code == 200 and ("Index of" in r.text or "Parent Directory" in r.text):
                vulns_found.append(f"Directory listing enabled: {dir_url}")
        except:
            pass

    # 4) Basic SQL Injection test on GET parameters
    parsed = urlparse(url)
    query = parsed.query
    if query:
        base_url = url.split('?')[0]
        params = query.split('&')
        for param in params:
            key = param.split('=')[0]
            test_url = f"{base_url}?{key}=' OR '1'='1"
            try:
                r = session.get(test_url, timeout=5)
                if any(error in r.text.lower() for error in [
                    "sql syntax", "mysql", "syntax error", "unclosed quotation mark",
                    "sql error", "database error"]):
                    vulns_found.append(f"Possible SQL Injection in parameter '{key}' at {test_url}")
            except:
                pass

    # 5) Basic reflected XSS test on GET parameters
    if query:
        for param in params:
            key = param.split('=')[0]
            xss_payload = "<script>alert('xss')</script>"
            test_url = f"{base_url}?{key}={xss_payload}"
            try:
                r = session.get(test_url, timeout=5)
                if xss_payload in r.text:
                    vulns_found.append(f"Possible Reflected XSS vulnerability in parameter '{key}' at {test_url}")
            except:
                pass

    # 6) Directory Traversal test on common file targets
    traversal_payloads = [
        "../etc/passwd", "..\\etc\\passwd",
        "../../../../../etc/passwd",
        "..\\..\\..\\..\\..\\etc\\passwd",
        "/etc/passwd",
        "..%2fetc%2fpasswd",  # URL encoded
    ]

    for payload in traversal_payloads:
        try:
            test_url = url + "/" + payload
            r = session.get(test_url, timeout=5)
            if r.status_code == 200 and "root:x:" in r.text:
                vulns_found.append(f"Directory Traversal vulnerability detected: {test_url}")
        except:
            pass

    # 7) Detect CMS by common markers
    cms_found = []
    try:
        r = session.get(url, timeout=6)
        text = r.text.lower()
        if "wp-content" in text or "wordpress" in text:
            cms_found.append("WordPress")
        if "joomla" in text:
            cms_found.append("Joomla")
        if "drupal" in text:
            cms_found.append("Drupal")
        if cms_found:
            vulns_found.append("Detected CMS: " + ", ".join(cms_found))
    except:
        pass

    # 8) Check HTTPS support and SSL redirect
    try:
        https_url = url.replace("http://", "https://")
        r = session.get(https_url, timeout=5, allow_redirects=True)
        if r.url.startswith("https://"):
            print_red("[i] HTTPS supported and active")
        else:
            vulns_found.append("HTTPS not supported or redirect missing")
    except:
        vulns_found.append("HTTPS not supported or error during HTTPS check")

    # 9) Check HTTP error pages for sensitive info
    error_test_url = url + "/thispagedoesnotexist_123456"
    try:
        r = session.get(error_test_url, timeout=5)
        if r.status_code in [500, 403, 401]:
            vulns_found.append(f"Suspicious HTTP status {r.status_code} on invalid URL - possible info leakage")
        elif r.status_code == 404:
            if "not found" not in r.text.lower():
                vulns_found.append("404 page does not contain 'not found' text - possible custom error page leaking info")
    except:
        pass

    # Results:
    if vulns_found:
        print_red("\n[!] Vulnerabilities/Issues found:")
        for v in vulns_found:
            print_red("  - " + v)
    else:
        print_red("\n[+] No common vulnerabilities detected.")

    press_any_key()

# === 2. IP Port Scanner ===
def ip_port_scanner():
    print_header("IP Port Scanner")
    target = input(Fore.RED + "[~] Enter IP address or domain: " + Style.RESET_ALL).strip()
    ports_str = input(Fore.RED + "[~] Enter port range (e.g. 1-1024): " + Style.RESET_ALL).strip()
    try:
        start_port, end_port = map(int, ports_str.split('-'))
    except:
        print_red("[!] Invalid port range format.")
        press_any_key()
        return

    open_ports = []

    def scan_port(port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            try:
                s.connect((target, port))
                open_ports.append(port)
            except:
                pass

    print_red("[*] Scanning ports...")
    threads = []
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(port,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    if open_ports:
        print_red(f"[+] Open ports on {target}:")
        for p in sorted(open_ports):
            print_red(f"  - Port {p}")
    else:
        print_red(f"[!] No open ports found on {target} in the given range.")

    press_any_key()

# === 3. DNS Resolver ===
def dns_resolver():
    print_header("DNS Resolver")
    domain = input(Fore.RED + "[~] Enter domain to resolve: " + Style.RESET_ALL).strip()
    try:
        ip = socket.gethostbyname(domain)
        print_red(f"[+] {domain} resolved to {ip}")
    except:
        print_red(f"[!] Could not resolve domain {domain}")
    press_any_key()

# === 4. Password Generator ===
def password_generator():
    print_header("Password Generator")
    length = input(Fore.RED + "[~] Enter password length (default 12): " + Style.RESET_ALL).strip()
    try:
        length = int(length)
        if length < 4:
            print_red("[!] Password length too short, using 12")
            length = 12
    except:
        length = 12

    chars = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(chars) for _ in range(length))
    print_red(f"[+] Generated password: {password}")

    press_any_key()

# === 5. Password Checker (Basic) ===
def password_checker():
    print_header("Password Checker")
    pwd = input(Fore.RED + "[~] Enter password to check: " + Style.RESET_ALL)
    length_ok = len(pwd) >= 8
    has_upper = any(c.isupper() for c in pwd)
    has_lower = any(c.islower() for c in pwd)
    has_digit = any(c.isdigit() for c in pwd)
    has_special = any(c in string.punctuation for c in pwd)

    score = sum([length_ok, has_upper, has_lower, has_digit, has_special])

    print_red("[*] Password strength:")
    if score <= 2:
        print_red("  Weak")
    elif score == 3 or score == 4:
        print_red("  Moderate")
    else:
        print_red("  Strong")

    press_any_key()

# === 6. Email Harvester ===
def email_harvester():
    print_header("Email Harvester")
    url = input(Fore.RED + "[~] Enter target URL (http/https): " + Style.RESET_ALL).strip()
    if not url.startswith("http"):
        url = "http://" + url
    try:
        r = requests.get(url, timeout=8)
        emails = set(re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", r.text))
        if emails:
            print_red(f"[+] Found emails at {url}:")
            for e in emails:
                print_red("  - " + e)
        else:
            print_red("[!] No emails found.")
    except Exception as e:
        print_red(f"[!] Error fetching URL: {e}")
    press_any_key()

# === 7. Phishing Detector (Basic) ===
def phishing_detector():
    print_header("Phishing Detector")
    url = input(Fore.RED + "[~] Enter URL to check: " + Style.RESET_ALL).strip()
    suspicious = False

    # Check if URL uses IP instead of domain
    parsed = urlparse(url)
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", parsed.netloc):
        suspicious = True
        print_red("[!] URL uses IP address instead of domain, suspicious")

    # Check for known phishing keywords in URL
    keywords = ["login", "secure", "update", "account", "webscr", "banking", "confirm", "password"]
    if any(k in url.lower() for k in keywords):
        suspicious = True
        print_red("[!] URL contains suspicious keywords")

    if not suspicious:
        print_red("[+] URL does not appear suspicious")
    press_any_key()

# === 8. TLS/SSL Scanner (Basic) ===
def tls_ssl_scanner():
    print_header("TLS/SSL Scanner")
    hostname = input(Fore.RED + "[~] Enter domain name: " + Style.RESET_ALL).strip()

    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert['subject'])
                issuer = dict(x[0] for x in cert['issuer'])
                print_red(f"[+] Certificate for {hostname}:")
                print_red(f"    Subject: {subject.get('commonName', 'N/A')}")
                print_red(f"    Issuer: {issuer.get('commonName', 'N/A')}")
                print_red(f"    Valid from: {cert['notBefore']}")
                print_red(f"    Valid until: {cert['notAfter']}")
    except Exception as e:
        print_red(f"[!] SSL connection failed: {e}")

    press_any_key()

# === Main Menu ===
def main():
    banner()
    while True:
        print(Fore.RED + """
[1] Website Vulnerability Scanner
[2] IP Port Scanner
[3] DNS Resolver
[4] Password Generator
[5] Password Checker
[6] Email Harvester
[7] Phishing Detector
[8] TLS/SSL Scanner
[9] Link Downloader
[0] Exit
""" + Style.RESET_ALL)

        choice = input(Fore.RED + "[~] Select an option: " + Style.RESET_ALL).strip()

        if choice == "1":
            website_vuln_scanner()
        elif choice == "2":
            ip_port_scanner()
        elif choice == "3":
            dns_resolver()
        elif choice == "4":
            password_generator()
        elif choice == "5":
            password_checker()
        elif choice == "6":
            email_harvester()
        elif choice == "7":
            phishing_detector()
        elif choice == "8":
            tls_ssl_scanner()
        elif choice == "9":
            link_downloader()
        elif choice == "0":
            print_red("Goodbye!")
            break
        else:
            print_red("[!] Invalid choice, try again.")

if __name__ == "__main__":
    main()
