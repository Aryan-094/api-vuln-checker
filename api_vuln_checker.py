import requests
from scapy.all import IP, TCP, sr1
import argparse
from urllib.parse import urlparse
import json
import os
from datetime import datetime

# Create directories for report output
REPORT_DIR = "reports"
if not os.path.exists(REPORT_DIR):
    os.makedirs(REPORT_DIR)

# Function to check if API uses HTTPS
def check_https(api_url):
    parsed_url = urlparse(api_url)
    if parsed_url.scheme == 'https':
        print("[+] Secure (HTTPS) connection detected.")
        return {"https": True}
    else:
        print("[-] Unsecure connection! The API does not use HTTPS.")
        return {"https": False}

# Function to check for insecure content delivery (mixed content)
def check_insecure_content(api_url, response_content):
    if 'http://' in response_content:
        print("[-] Insecure content detected (Mixed HTTP/HTTPS).")
        return {"insecure_content": True}
    else:
        print("[+] No insecure content detected.")
        return {"insecure_content": False}

# Function to check headers for security and rate limiting
def check_security_headers(headers):
    security_headers = ['Content-Security-Policy', 'X-Content-Type-Options', 'Strict-Transport-Security', 'X-Frame-Options']
    missing_headers = [header for header in security_headers if header not in headers]

    if missing_headers:
        print("[-] Missing security headers: ", missing_headers)
    else:
        print("[+] All critical security headers are present.")

    # Check for rate limiting headers
    rate_limit_headers = ['X-RateLimit-Limit', 'X-RateLimit-Remaining']
    rate_limit_detected = all(header in headers for header in rate_limit_headers)

    if rate_limit_detected:
        print("[+] API uses rate limiting.")
    else:
        print("[-] No rate limiting headers found.")
    
    return {
        "missing_headers": missing_headers,
        "rate_limiting": rate_limit_detected
    }

# Function to test network-level security using Scapy
def scapy_network_test(api_url):
    print(f"[+] Running Scapy network test for {api_url}")
    ip = urlparse(api_url).netloc
    packet = IP(dst=ip) / TCP(dport=80, flags='S')
    response = sr1(packet, timeout=2, verbose=0)

    if response and response.haslayer(TCP):
        if response.getlayer(TCP).flags == 'SA':
            print("[+] API is accepting TCP connections on port 80 (HTTP).")
            return {"tcp_open": True}
        else:
            print("[-] TCP handshake failed.")
            return {"tcp_open": False}
    return {"tcp_open": None}

# Function to check if API requires authentication
def check_authentication(response):
    if response.status_code == 401:
        print("[+] API requires authentication.")
        return {"authentication_required": True}
    elif response.status_code == 403:
        print("[+] API requires authentication (Access forbidden).")
        return {"authentication_required": True}
    else:
        print("[-] API does not require authentication.")
        return {"authentication_required": False}

# Function to detect open redirects
def check_open_redirects(api_url, response):
    if response.status_code in [301, 302, 303, 307, 308]:
        location = response.headers.get('Location', '')
        if location.startswith('http://') or location.startswith('https://'):
            parsed_redirect = urlparse(location)
            original_host = urlparse(api_url).netloc
            if parsed_redirect.netloc != original_host:
                print("[-] Open redirect vulnerability detected!")
                return {"open_redirect": True}
    print("[+] No open redirects detected.")
    return {"open_redirect": False}

# Function to check API response time
def check_response_time(response_time):
    if response_time > 2:  # Arbitrary threshold for slow response
        print(f"[-] API response time is slow: {response_time:.2f} seconds")
        return {"response_time": response_time, "performance": "Slow"}
    else:
        print(f"[+] API response time is fast: {response_time:.2f} seconds")
        return {"response_time": response_time, "performance": "Fast"}

# Placeholder functions for SQL Injection, XSS, Directory Traversal, and CORS
def check_sql_injection(api_url):
    # Simulate a SQL Injection test (example only, replace with real test)
    print(f"[+] Checking for SQL Injection on {api_url}")
    return {"sql_injection_vulnerable": False}

def check_xss(api_url):
    # Simulate an XSS test (example only, replace with real test)
    print(f"[+] Checking for XSS on {api_url}")
    return {"xss_vulnerable": False}

def check_directory_traversal(api_url):
    # Simulate a Directory Traversal test (example only, replace with real test)
    print(f"[+] Checking for Directory Traversal on {api_url}")
    return {"directory_traversal_vulnerable": False}

def check_cors(api_url, headers):
    # Simulate CORS misconfiguration check (example only, replace with real test)
    if 'Access-Control-Allow-Origin' in headers and headers['Access-Control-Allow-Origin'] == '*':
        print("[-] CORS misconfiguration detected!")
        return {"cors_misconfigured": True}
    else:
        print("[+] CORS is properly configured.")
        return {"cors_misconfigured": False}

# Function to make a GET request and analyze response
def check_api(api_url):
    report = {"api_url": api_url, "status_code": None}  # Initialize report with api_url

    try:
        # Measure response time
        response = requests.get(api_url, timeout=5)
        response_time = response.elapsed.total_seconds()

        report["status_code"] = response.status_code  # Capture status code
        print(f"[+] API responded with status code: {response.status_code}")

        # Check if HTTPS is being used
        https_result = check_https(api_url)
        report.update(https_result)

        # Check for security headers
        header_result = check_security_headers(response.headers)
        report.update(header_result)

        # Check for authentication
        auth_result = check_authentication(response)
        report.update(auth_result)

        # Run network tests using Scapy
        scapy_result = scapy_network_test(api_url)
        report.update(scapy_result)

        # Check for insecure content delivery (mixed content)
        insecure_content_result = check_insecure_content(api_url, response.text)
        report.update(insecure_content_result)

        # Check for open redirects
        open_redirect_result = check_open_redirects(api_url, response)
        report.update(open_redirect_result)

        # Check API response time/performance
        response_time_result = check_response_time(response_time)
        report.update(response_time_result)

        # Check SQL Injection vulnerability
        sql_injection_result = check_sql_injection(api_url)
        report.update(sql_injection_result)

        # Check XSS vulnerability
        xss_result = check_xss(api_url)
        report.update(xss_result)

        # Check Directory Traversal vulnerability
        directory_traversal_result = check_directory_traversal(api_url)
        report.update(directory_traversal_result)

        # Check CORS misconfiguration
        cors_result = check_cors(api_url, response.headers)
        report.update(cors_result)

    except requests.exceptions.RequestException as e:
        print(f"[-] Failed to reach the API: {e}")
        report["error"] = str(e)

    return report

# Function to save report in JSON format
def save_report(report):
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    api_host = urlparse(report.get("api_url", "unknown")).netloc

    # Ensure the report structure contains all necessary details
    report_summary = {
        "url": report.get("api_url"),
        "https": report.get("https"),
        "status_code": report.get("status_code"),
        "authentication_required": report.get("authentication_required", False),
        "rate_limiting": report.get("rate_limiting", False),
        "tcp_open": report.get("tcp_open"),
        "insecure_content": report.get("insecure_content"),
        "open_redirect": report.get("open_redirect"),
        "response_time": report.get("response_time"),
        "performance": report.get("performance"),
        "sql_injection_vulnerable": report.get("sql_injection_vulnerable"),
        "xss_vulnerable": report.get("xss_vulnerable"),
        "directory_traversal_vulnerable": report.get("directory_traversal_vulnerable"),
        "cors_misconfigured": report.get("cors_misconfigured")
    }

    # Save as JSON
    json_filename = os.path.join(REPORT_DIR, f"report_{api_host}_{timestamp}.json")
    with open(json_filename, 'w') as json_file:
        json.dump(report_summary, json_file, indent=4)
    print(f"[+] JSON report saved to {json_filename}")

# CLI function using argparse
def main():
    parser = argparse.ArgumentParser(description="API Vulnerability Checker")
    parser.add_argument('url', type=str, help="The API URL to check for vulnerabilities")
    args = parser.parse_args()

    # Check if URL argument is provided
    if not args.url:
        print("[-] Please provide an API URL after the file name.")
        print("Usage: python api_vuln_checker.py <API_URL>")
        return

    api_url = args.url
    print(f"Checking API: {api_url}")
    report = check_api(api_url)

    # Save report in JSON format
    save_report(report)

if __name__ == "__main__":
    main()
