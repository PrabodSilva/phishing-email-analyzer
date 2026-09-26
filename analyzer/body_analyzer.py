"""
body_analyzer.py  -  Day 3 of the Phishing Email Analyzer

Reads the BODY of an email (the message you see) and checks for:
  1. Link text mismatch  (the link SAYS paypal.com but GOES to evil.xyz)
  2. Every link, using the Day 2 URL analyzer
  3. Urgency / fear words ("suspended", "within 24 hours")
  4. Requests for secret info ("password", "card number")
  5. Generic greeting ("Dear Customer")
  6. Dangerous attachments (.exe, .html, .zip ...)

Usage:
    python analyzer/body_analyzer.py sample_emails/phish_paypal.eml
"""

import os
import re
import sys

from bs4 import BeautifulSoup

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from header_analyzer import load_email, finding          # Day 1
from url_analyzer import analyze_url, extract             # Day 2

# ------------------------------------------------------------------ word lists
URGENT_WORDS = [
    "urgent", "immediately", "suspended", "within 24 hours", "within 48 hours",
    "unusual activity", "verify now", "act now", "final notice", "locked",
    "will be closed", "permanently closed", "limited time", "payment failed",
    "avoid losing", "expire", "last warning", "unauthorized", "has failed",
]

SECRET_WORDS = [
    "password", "otp", "one-time code", "card number", "cvv", "pin number",
    "bank details", "billing details", "login details", "social security",
    "confirm your account", "verify your account", "update your billing",
]

GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear client", "dear account holder",
    "dear member", "dear valued customer", "hello user", "dear sir/madam",
]

RISKY_EXTENSIONS = [
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".jar", ".msi",
    ".zip", ".rar", ".7z", ".iso", ".img", ".html", ".htm", ".docm",
    ".xlsm", ".pptm", ".lnk", ".hta",
]

URL_PATTERN = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
DOMAIN_LIKE = re.compile(r"^(https?://)?([a-z0-9-]+\.)+[a-z]{2,}(/\S*)?$", re.IGNORECASE)


# ------------------------------------------------------------------ helpers
def get_body_parts(msg):
    """Return (plain_text, html_text, attachment_names)."""
    plain, html, attachments = "", "", []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename or part.get_content_disposition() == "attachment":
            attachments.append(filename or "(no name)")
            continue
        try:
            content = part.get_content()
        except Exception:
            continue
        if part.get_content_type() == "text/plain":
            plain += str(content) + "\n"
        elif part.get_content_type() == "text/html":
            html += str(content) + "\n"
    return plain, html, attachments


def get_links(plain, html):
    """Return a list of {'href': real address, 'text': what the reader sees}."""
    links, seen = [], set()
    if html:
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if href.lower().startswith(("http://", "https://")) and href not in seen:
                seen.add(href)
                links.append({"href": href, "text": a.get_text(" ", strip=True)})
    for href in URL_PATTERN.findall(plain):
        href = href.rstrip(".,;")
        if href not in seen:
            seen.add(href)
            links.append({"href": href, "text": href})
    return links


def site_of(url):
    """'https://www.paypal.com/verify' -> 'paypal.com'"""
    host = re.sub(r"^https?://", "", url.strip(), flags=re.IGNORECASE).split("/")[0].split("@")[-1]
    ext = extract(host.lower())
    return f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain


def find_words(text, word_list):
    text = text.lower()
    return [w for w in word_list if w in text]


# ------------------------------------------------------------------ checks
def check_link_mismatch(links):
    """The link TEXT shows one website, but the link really goes to another."""
    results = []
    for link in links:
        shown = link["text"]
        if not DOMAIN_LIKE.match(shown):
            continue  # the text is normal words like "Click here", nothing to compare
        if site_of(shown) != site_of(link["href"]):
            results.append(finding(
                "Link text mismatch", "HIGH",
                f"The link shows '{shown}' but really goes to '{site_of(link['href'])}'",
            ))
    return results


def check_urgency(text):
    found = find_words(text, URGENT_WORDS)
    if len(found) >= 2:
        return finding("Urgency words", "MEDIUM",
                       f"Tries to rush you: {', '.join(found[:4])}")


def check_secret_requests(text):
    found = find_words(text, SECRET_WORDS)
    if found:
        return finding("Asks for secret info", "HIGH",
                       f"Asks for: {', '.join(found[:4])}")


def check_greeting(text):
    found = find_words(text[:300], GENERIC_GREETINGS)
    if found:
        return finding("Generic greeting", "LOW",
                       f"Uses '{found[0].title()}' instead of your name")


def check_attachments(attachments):
    results = []
    for name in attachments:
        if name.lower().endswith(tuple(RISKY_EXTENSIONS)):
            results.append(finding("Risky attachment", "HIGH",
                                   f"'{name}' is a file type often used to attack"))
    return results


# ------------------------------------------------------------------ main function
def analyze_body(path, use_whois=False):
    msg = load_email(path)
    plain, html, attachments = get_body_parts(msg)
    visible_text = plain + " " + BeautifulSoup(html, "html.parser").get_text(" ") if html else plain
    links = get_links(plain, html)

    findings = []
    findings.extend(check_link_mismatch(links))
    for result in [check_urgency(visible_text),
                   check_secret_requests(visible_text),
                   check_greeting(visible_text)]:
        if result:
            findings.append(result)
    findings.extend(check_attachments(attachments))

    # Check every link with the Day 2 analyzer
    link_reports = [analyze_url(link["href"], use_whois) for link in links[:15]]

    return {
        "file": path,
        "links": links,
        "link_reports": link_reports,
        "attachments": attachments,
        "findings": findings,
    }


def print_report(report):
    icons = {"HIGH": "[!!!]", "MEDIUM": "[!! ]", "LOW": "[ ! ]"}
    print("=" * 60)
    print(f" BODY ANALYSIS: {report['file']}")
    print("=" * 60)
    print(f" Links found : {len(report['links'])}")
    for lr in report["link_reports"]:
        print(f"   - {lr['url']}  ({len(lr['findings'])} red flags)")
    print(f" Attachments : {', '.join(report['attachments']) or '(none)'}")
    print(f"\n Red flags found: {len(report['findings'])}")
    if not report["findings"]:
        print("   None - the message text looks clean.")
    for f in report["findings"]:
        print(f"   {icons[f['severity']]} {f['check']}: {f['detail']}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python analyzer/body_analyzer.py <file.eml> [more.eml ...]")
        sys.exit(1)
    for eml_path in sys.argv[1:]:
        print_report(analyze_body(eml_path))
