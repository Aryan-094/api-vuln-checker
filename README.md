# API Vulnerability Checker

**A Python-based tool to check the security and performance vulnerabilities of public APIs. This tool identifies various vulnerabilities, including insecure content delivery, open redirects, lack of security headers, rate-limiting, CORS misconfigurations, and much more. It generates a comprehensive report in JSON format for each scanned API, which can be saved for later analysis.**

## Features

- **HTTPS Check**: Identifies if the API uses secure HTTPS protocol.
- **Security Headers Check**: Detects missing critical security headers like `Content-Security-Policy`, `Strict-Transport-Security`, and more.
- **Rate Limiting**: Checks if the API implements rate-limiting via appropriate headers.
- **Network Security (TCP)**: Identifies if the API is accepting TCP connections on port 80 (HTTP).
- **Authentication**: Verifies if the API requires authentication via status codes.
- **Insecure Content Delivery**: Detects mixed HTTP and HTTPS content in the API response.
- **Open Redirect**: Checks for open redirect vulnerabilities in the API.
- **API Response Time/Performance Metrics**: Measures the API's response time and classifies its performance.
- **SQL Injection Detection**: Tests for SQL Injection vulnerabilities.
- **Cross-Site Scripting (XSS) Detection**: Tests for XSS vulnerabilities.
- **Directory Traversal Detection**: Tests for directory traversal vulnerabilities.
- **CORS Misconfiguration**: Identifies misconfigurations in CORS headers.

## Requirements

- **Python 3.x**
- **Libraries**: 
  - `requests`
  - `scapy`
  - `argparse`
  - `urllib.parse`
  - `json`
  - `datetime`
  - `os`

You can install the required dependencies by running:

```bash
pip install -r requirements.txt
```
> **Note**: Scapy requires root privileges to run network-level tests.

## Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/api-vulnerability-checker.git
cd api-vulnerability-checker
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the tool by providing an API URL:

```bash
sudo python api_vuln_checker.py <API_URL>
```

### Example:

```bash
sudo python api_vuln_checker.py https://jsonplaceholder.typicode.com/posts
```

## Usage

The tool accepts an API URL as input and generates a JSON report highlighting the vulnerabilities and performance metrics discovered during the scan.

### Command

```bash
sudo python api_vuln_checker.py <API_URL>
```

### Example Output (JSON Report)

The output is saved in the `reports/` directory as a .json file. An example of the JSON report structure:

```json
{
    "api_url": "https://api.spacexdata.com/v4/launches",
    "status_code": 200,
    "https": true,
    "missing_headers": [],
    "rate_limiting": false,
    "authentication_required": false,
    "tcp_open": true,
    "insecure_content": false,
    "open_redirect": false,
    "response_time": 0.484837,
    "performance": "Fast",
    "sql_injection_vulnerable": false,
    "xss_vulnerable": false,
    "directory_traversal_vulnerable": false,
    "cors_misconfigured": true
}
```

## Features Explained

- **HTTPS Check**: Ensures the API uses HTTPS instead of HTTP for secure communication.
- **Security Headers Check**: Scans for critical security headers like Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, etc.
- **Rate Limiting**: Detects if the API implements rate-limiting, a security measure to prevent abuse.
- **TCP Connection Test**: Verifies if the API allows connections on port 80 (HTTP).
- **Insecure Content Delivery**: Identifies if insecure content (HTTP) is delivered alongside secure (HTTPS) content.
- **Open Redirect**: Detects open redirects, a vulnerability that could be exploited for phishing or malware attacks.
- **Response Time**: Measures API response time and classifies performance as Fast or Slow.
- **SQL Injection Detection**: Tests if the API is vulnerable to SQL Injection attacks.
- **Cross-Site Scripting (XSS)**: Checks if the API is vulnerable to XSS attacks.
- **Directory Traversal**: Detects if the API is vulnerable to directory traversal attacks.
- **CORS Misconfiguration**: Checks for any misconfigurations in Cross-Origin Resource Sharing (CORS) headers.

## Future Enhancements

- **More vulnerability scanning features**.
- **Improve SQL Injection, XSS, and Directory Traversal detection**.
- **Provide a web-based user interface for ease of use**.
- **Add more performance-related metrics like API throughput**.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue to discuss the changes.

- **Fork the project**.
- **Create your feature branch** (`git checkout -b feature/new-feature`).
- **Commit your changes** (`git commit -am 'Add new feature'`).
- **Push to the branch** (`git push origin feature/new-feature`).
- **Open a pull request**.

## Acknowledgements

Special thanks to the contributors and the open-source libraries used in this project.
```

You can copy and paste this directly into your `README.md` file!
