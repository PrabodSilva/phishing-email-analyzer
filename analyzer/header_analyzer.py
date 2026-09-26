"""
header_analyzer.py  -  Day 1 of the Phishing Email Analyzer

Reads a .eml file and checks its HEADERS for phishing red flags:
  1. From vs Reply-To mismatch
  2. From vs Return-Path mismatch
  3. SPF / DKIM / DMARC authentication results
  4. Display-name spoofing (brand name + unrelated address)
  5. Received hops (which mail servers the email passed through)

Usage:
    python analyzer/header_analyzer.py sample_emails/phish_paypal.eml
"""

import re
import sys
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

# Brands attackers love to impersonate (on Day 3 we move this to data/brands.txt)
BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "linkedin", "dhl", "fedex",
    "bank", "visa", "mastercard", "github", "dropbox", "outlook",
]

# Free email providers - a "company" should not send from these
FREE_MAIL = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "proton.me"]


# ---------------------------------------------------------------- helpers
def load_email(path):
    """Open a .eml file and return an EmailMessage object."""
    with open(path, "rb") as f:
        return BytesParser(policy=policy.default).parse(f)


def get_domain(address):
    """'john@mail.paypal.com' -> 'mail.paypal.com'"""
    if "@" not in address:
        return ""
    return address.split("@")[-1].strip().strip(">").lower()


def base_domain(domain):
    """'mail.paypal.com' -> 'paypal.com' (simple version; Day 2 uses tldextract)"""
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def finding(check, severity, detail):
    """Every red flag is stored as a small dict."""
    return {"check": check, "severity": severity, "detail": detail}


# ---------------------------------------------------------------- checks
def check_reply_to(msg, from_addr):
    reply_name, reply_addr = parseaddr(str(msg.get("Reply-To", "")))
    if not reply_addr:
        return None
    if base_domain(get_domain(reply_addr)) != base_domain(get_domain(from_addr)):
        return finding(
            "Reply-To mismatch", "HIGH",
            f"Email is from '{from_addr}' but replies go to '{reply_addr}'",
        )
    return None


def check_return_path(msg, from_addr):
    _, rp_addr = parseaddr(str(msg.get("Return-Path", "")))
    if not rp_addr:
        return None
    if base_domain(get_domain(rp_addr)) != base_domain(get_domain(from_addr)):
        # MEDIUM, not HIGH: real companies sometimes use mailing services
        return finding(
            "Return-Path mismatch", "MEDIUM",
            f"From domain '{get_domain(from_addr)}' but bounces go to '{get_domain(rp_addr)}'",
        )
    return None


def check_authentication(msg):
    """Read SPF, DKIM, DMARC results from the Authentication-Results header."""
    results = {}
    findings = []
    auth_header = " ".join(str(h) for h in (msg.get_all("Authentication-Results") or []))

    for method in ["spf", "dkim", "dmarc"]:
        match = re.search(rf"{method}=(\w+)", auth_header, re.IGNORECASE)
        results[method] = match.group(1).lower() if match else "missing"

        if results[method] in ("fail", "softfail", "none", "permerror"):
            findings.append(finding(
                f"{method.upper()} check", "HIGH",
                f"{method.upper()} result is '{results[method]}' - sender may be forged",
            ))
        elif results[method] == "missing":
            findings.append(finding(
                f"{method.upper()} check", "LOW",
                f"No {method.upper()} result found in headers",
            ))
    return results, findings


def check_display_name(from_name, from_addr):
    """'PayPal Security' <xyz@random.ru>  -> brand in name, but not in domain."""
    name = from_name.lower()
    domain = get_domain(from_addr)
    for brand in BRANDS:
        if brand in name and brand not in domain:
            severity = "HIGH" if domain in FREE_MAIL else "MEDIUM"
            return finding(
                "Display-name spoofing", severity,
                f"Name says '{from_name}' but the address is '{from_addr}'",
            )
    return None

def check_missing_date(msg):
    # TODO: if the email has no "Date" header, return a finding
    # Hint: look at how check_reply_to() uses msg.get(...) and finding(...)
    pass


def get_received_hops(msg):
    """List the mail servers from the Received headers (newest first)."""
    hops = []
    for header in msg.get_all("Received") or []:
        text = str(header)
        match = re.search(r"from\s+(\S+)", text)
        if match:
            hops.append(match.group(1))
        else:
            # Some lines have no 'from', e.g. Gmail's internal 'by ...' step
            by_match = re.search(r"by\s+(\S+)", text)
            hops.append(f"(internal) {by_match.group(1)}" if by_match else "unknown")
    return hops


# ---------------------------------------------------------------- main function
def analyze_headers(path):
    """Run every header check and return one results dictionary."""
    msg = load_email(path)
    from_name, from_addr = parseaddr(str(msg.get("From", "")))

    findings = []
    for result in [
        check_reply_to(msg, from_addr),
        check_return_path(msg, from_addr),
        check_display_name(from_name, from_addr),
    ]:
        if result:
            findings.append(result)

    auth_results, auth_findings = check_authentication(msg)
    findings.extend(auth_findings)

    return {
        "file": path,
        "subject": str(msg.get("Subject", "(no subject)")),
        "from_name": from_name,
        "from_address": from_addr,
        "date": str(msg.get("Date", "")),
        "auth": auth_results,
        "hops": get_received_hops(msg),
        "findings": findings,
    }


def print_report(report):
    icons = {"HIGH": "[!!!]", "MEDIUM": "[!! ]", "LOW": "[ ! ]"}
    print("=" * 60)
    print(f" HEADER ANALYSIS: {report['file']}")
    print("=" * 60)
    print(f" Subject : {report['subject']}")
    print(f" From    : {report['from_name']} <{report['from_address']}>")
    print(f" Date    : {report['date']}")
    print(f" SPF={report['auth']['spf']}  DKIM={report['auth']['dkim']}  DMARC={report['auth']['dmarc']}")
    print(f"\n Mail route ({len(report['hops'])} hops):")
    for i, hop in enumerate(reversed(report["hops"]), 1):
        print(f"   {i}. {hop}")

    print(f"\n Red flags found: {len(report['findings'])}")
    if not report["findings"]:
        print("   None - headers look clean.")
    for f in report["findings"]:
        print(f"   {icons[f['severity']]} {f['check']}: {f['detail']}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python analyzer/header_analyzer.py <file.eml> [more.eml ...]")
        sys.exit(1)
    for eml_path in sys.argv[1:]:
        print_report(analyze_headers(eml_path))
