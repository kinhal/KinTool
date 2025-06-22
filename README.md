# KinTool

KinTool is an all-in-one cybersecurity toolkit written in Python, featuring a web vulnerability scanner, port scanner, DNS resolver, password generator and checker, email harvester, phishing detector, TLS/SSL scanner, and a link downloader.

---

## Features

1. **Website Vulnerability Scanner**  
   Scans a website for common vulnerabilities such as exposed sensitive files, missing security headers, basic SQL Injection, reflected XSS, directory traversal, and enabled directory listing.

2. **IP Port Scanner**  
   Performs a TCP port scan on a given IP address or domain.

3. **DNS Resolver**  
   Resolves a domain name into one or more IP addresses.

4. **Password Generator**  
   Generates random passwords with customizable length.

5. **Password Checker**  
   Evaluates password strength and provides improvement suggestions.

6. **Email Harvester**  
   Basic multi-threaded crawler to collect emails from a website.

7. **Phishing Detector**  
   Analyzes URLs for common phishing indicators.

8. **TLS/SSL Scanner**  
   Displays TLS/SSL certificate details of a domain.

9. **Link Downloader**  
   Downloads a file from a URL and saves it with the filename after the domain.

---

## Requirements

- Python 3.7+
- [requests](https://pypi.org/project/requests/)
- [colorama](https://pypi.org/project/colorama/)
