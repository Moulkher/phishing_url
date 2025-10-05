A Python CLI tool to analyze URLs and detect potential phishing or risky websites using Google Safe Browsing, WHOIS domain info, and SSL/TLS checks.

Features:
- Checks if a URL is flagged by Google Safe Browsing.
- Analyzes domain creation/expiration dates to detect suspicious domains.
- Inspects SSL/TLS certificates for expiration, validity, and weak versions.
- Outputs a risk summary with detailed flags.

Prerequisites:
- A Google Safe Browsing API key is required. Replace the value in gsb_checker.py before running the tool.

Usage:
- run is_it_phishy.py
