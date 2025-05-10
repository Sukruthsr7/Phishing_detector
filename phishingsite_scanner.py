import re
import socket
import ssl
import requests
from datetime import datetime
import time
import sys
from urllib.parse import urlparse

VIRUSTOTAL_API_KEY = "ADD YOUR API"
WHOIS_API_KEY = "ADD YOUR API"
URLSCAN_API_KEY = "ADD YOUR API"

HTTP_ERROR_CODES = {
    400: "Bad Request: The server could not understand the request.",
    401: "Unauthorized: Check your API key or authentication details.",
    403: "Forbidden: You don't have permission to access this resource.",
    404: "Not Found: The requested resource was not found.",
    500: "Internal Server Error: The server encountered an issue.",
    502: "Bad Gateway: The server received an invalid response.",
    503: "Service Unavailable: The server is overloaded or down.",
}

SSL_ERROR_CODES = {
    ssl.CertificateError: "Certificate Error: SSL certificate is invalid or mismatched.",
    ssl.SSLError: "SSL Error: General SSL connection issue.",
    socket.timeout: "Timeout Error: SSL connection timed out.",
}

def explain_http_error(status_code):
    return HTTP_ERROR_CODES.get(status_code, "Unknown Error: Check the server response.")

def explain_ssl_error(error):
    for error_type, message in SSL_ERROR_CODES.items():
        if isinstance(error, error_type):
            return message
    return "Unknown SSL Error: Check the SSL configuration or certificate."

def loading_animation(task_name, duration=3):
    print(f"[+] {task_name}")
    animation = "|/-\\"
    for i in range(duration * 10):
        time.sleep(0.1)
        percent = (i + 1) / (duration * 10) * 100
        sys.stdout.write(f"\r{animation[i % len(animation)]} {percent:.1f}%")
        sys.stdout.flush()
    sys.stdout.write("\r")
    print("[+] Done!")

def search_bar():
    print("======================")
    print("Enter the URL to scan and press Enter:")
    sys.stdout.write("> ")
    sys.stdout.flush()
    url = input().strip()
    if not re.match(r'^https?://', url):
        url = 'http://' + url
    return url

def is_suspicious_url(url):
    suspicious_patterns = [
        r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # IP addresses in URL
        r"https?://.*@.*",  # Presence of '@' in URL
        r"https?://.*-[a-z0-9]+.*",  # Excessive hyphenation
        r"https?://.*\?.*=.*=.*",  # Multiple query parameters
        r"https?://.*free.*",  # Free offers
        r"https?://.*login.*",  # Login bait
        r"https?://.*secure.*",  # Misleading "secure" keyword
        r"https?://.*bit\.ly.*",  # URL shorteners
        r"https?://.*tinyurl\.com.*",  # URL shorteners
    ]
    score = 0
    for pattern in suspicious_patterns:
        if re.search(pattern, url):
            score += 1
    return score > 1  # Adjust the threshold as needed

def check_dns_resolution(url):
    loading_animation("Checking DNS resolution")
    try:
        domain = urlparse(url).netloc
        ip = socket.gethostbyname(domain)
        print(f"[+] Domain resolves to IP: {ip}")
        return True
    except socket.gaierror:
        print("[!] Domain does not resolve to a valid IP.")
        return False

def validate_ssl_certificate(url):
    loading_animation("Validating SSL certificate")
    try:
        domain = urlparse(url).netloc
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                print("[+] SSL Certificate is valid.")
                return cert
    except Exception as e:
        error_description = explain_ssl_error(e)
        print(f"[!] SSL Certificate validation failed: {error_description}")
        return None

def check_domain_age(url):
    loading_animation("Checking domain age")
    domain = urlparse(url).netloc
    api_url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={WHOIS_API_KEY}&domainName={domain}&outputFormat=JSON"
    lookup_url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName={domain}"

    print(f"[+] WHOIS Lookup URL: {lookup_url}")
    
    try:
        response = requests.get(api_url)
        if response.status_code == 200:
            data = response.json()
            creation_date = data.get("WhoisRecord", {}).get("createdDate", None)
            if creation_date:
                creation_date = datetime.strptime(creation_date.split("T")[0], "%Y-%m-%d")
                age = (datetime.now() - creation_date).days
                print(f"[+] Domain age: {age} days")
                return age
            else:
                print("[!] Unable to fetch domain age.")
        else:
            error_description = explain_http_error(response.status_code)
            print(f"[!] WHOIS lookup failed: {error_description}")
    except Exception as e:
        print(f"[!] Failed to check domain age: {e}")
    return None

def check_url_reputation(url):
    loading_animation("Checking URL reputation with VirusTotal")
    api_url = f"https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    url_id = requests.utils.quote(url, safe="")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    try:
        response = requests.get(api_url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            print("[+] VirusTotal Scan Results:")
            print(stats)
            return stats
        else:
            error_description = explain_http_error(response.status_code)
            print(f"[!] VirusTotal lookup failed: {error_description}")
    except Exception as e:
        print(f"[!] Failed to check URL reputation: {e}")
    return None

def scan_with_urlscan(url):
    loading_animation("Scanning URL with URLScan.io")
    api_url = "https://urlscan.io/api/v1/scan/"
    headers = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}
    data = {"url": url, "visibility": "public"}

    try:
        response = requests.post(api_url, headers=headers, json=data)
        if response.status_code == 200:
            result = response.json()
            print("[+] URLScan.io Scan Results:")
            print(result)
            return result
        else:
            error_description = explain_http_error(response.status_code)
            print(f"[!] URLScan.io lookup failed: {error_description}")
    except Exception as e:
        print(f"[!] Failed to scan URL with URLScan.io: {e}")
    return None

def main():
    while True:
        url = search_bar()
        
        if is_suspicious_url(url):
            print("[!] Suspicious patterns detected in URL!")
        else:
            print("[+] URL does not have suspicious patterns.")
        
        if check_dns_resolution(url):
            validate_ssl_certificate(url)
            check_domain_age(url)
            check_url_reputation(url)
            scan_with_urlscan(url)

        while True:
            print("Do you want to exit? (yes/no)")
            response = input().strip().lower()
            if response == 'yes':
                print("Exiting...")
                return
            elif response == 'no':
                print("Do you want to scan another URL? (yes/no)")
                scan_response = input().strip().lower()
                if scan_response == 'yes':
                    break
                elif scan_response == 'no':
                    print("Continuing without scanning another URL...")
                else:
                    print("Invalid input. Please enter 'yes' or 'no'.")
            else:
                print("Invalid input. Please enter 'yes' or 'no'.")

if __name__ == "__main__":
    main()
