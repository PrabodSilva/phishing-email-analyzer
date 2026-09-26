# Phishing Email Analyzer

A Python tool that analyzes `.eml` files and URLs for phishing red flags and gives each email a risk score (0-100).

## Progress
- [x] Day 1: Email header analysis (Reply-To / Return-Path mismatch, SPF/DKIM/DMARC, display-name spoofing, mail route)
- [x] Day 2: URL analyzer (IP links, @ trick, lookalike brands, shorteners, suspicious endings, domain age)
- [ ] Day 3: Body analysis + risk scoring
- [ ] Day 4: Flask dashboard

## Run (Day 1)
```
python analyzer/header_analyzer.py sample_emails/phish_paypal.eml
```

## Safety
All phishing samples in `sample_emails/` are fake and written for testing. Never click links or open attachments in real phishing emails.

## Run (Day 2)
```
   pip install -r requirements.txt
   python analyzer/url_analyzer.py "http://paypa1-alerts.xyz/login"
```