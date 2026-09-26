# 🛡️ Phishing Email Analyzer

A Python + Flask web tool that checks a **link** or a whole **email (.eml)** and tells you if it is
**✅ SAFE, ⚠️ SUSPICIOUS or ❌ PHISHING**, with a short reason why.

It only **reads** the text. It never opens links or attachments, and it runs only on your own computer.

## ▶️ How to run

```
git clone https://github.com/PrabodSilva/phishing-email-analyzer.git
cd phishing-email-analyzer
python -m venv venv
venv\Scripts\activate          # Windows
pip install -r requirements.txt
python app.py
```
Your browser opens **http://127.0.0.1:5000**. Paste a link or upload a `.eml` file.

**How to get a .eml file from Gmail:** open the email → click ⋮ (three dots) → **Download message**.

## 🔍 What it checks

| Layer | Checks |
|---|---|
| **Sender (headers)** | Reply-To mismatch, Return-Path mismatch, display-name spoofing, SPF / DKIM / DMARC results, lookalike sender domain, mail route |
| **Links** | IP-address links, `@` trick, punycode, lookalike brands (`paypa1`, `micros0ft`, `amazn`), brand in subdomain, link shorteners, risky endings (`.xyz`, `.top`), no HTTPS, domain age (WHOIS) |
| **Content** | Link text mismatch (shows one site, opens another), urgency words, requests for passwords / card details, generic greeting, risky attachments (`.exe`, `.html`, `.zip`, `.docm`…) |

Each red flag adds points. Email score: **0–30 Safe, 31–60 Suspicious, 61–100 Phishing**.
(A single link uses lower limits: 0–9 Safe, 10–29 Suspicious, 30+ Phishing.)

## 🎯 MITRE ATT&CK mapping
- **T1566 – Phishing**
  - T1566.001 Spearphishing Attachment → risky attachment check
  - T1566.002 Spearphishing Link → link and link-text-mismatch checks
- **T1036 – Masquerading** → display-name spoofing, lookalike domains

## 📁 Project structure
```
app.py                     Flask web app (Day 4)
analyzer/header_analyzer.py  Email headers (Day 1)
analyzer/url_analyzer.py     Links (Day 2)
analyzer/body_analyzer.py    Email body (Day 3)
analyzer/scorer.py           Risk score + verdict (Day 3)
templates/                 Web pages
sample_emails/             Fake test emails (safe + phishing)
```

## 💻 Command line (optional)
```
python analyzer/scorer.py sample_emails/phish_paypal.eml
python analyzer/scorer.py "http://paypa1-alerts.xyz/login"
```

## ✅ Progress
- [x] Day 1: Email header analysis
- [x] Day 2: URL analyzer
- [x] Day 3: Body analysis + risk scoring
- [x] Day 4: Flask web dashboard

## ⚠️ Safety & limits
- All phishing samples here are fake and written for testing.
- This is a learning project. It can miss clever attacks and can sometimes warn on real emails. Always think before you click.
