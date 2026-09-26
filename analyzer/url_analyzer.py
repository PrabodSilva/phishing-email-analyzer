"""
url_analyzer.py  -  Day 2 of the Phishing Email Analyzer

Checks ONE link (URL) for phishing red flags.
It only READS the text of the link. It never opens or visits the link.

Usage:
    python analyzer/url_analyzer.py "http://paypa1-secure.xyz/login"
    python analyzer/url_analyzer.py "https://github.com" --no-whois
"""

import re
import sys
import ipaddress
from datetime import datetime
from difflib import SequenceMatcher
from urllib.parse import urlparse

import tldextract

# Use the list of domain endings that comes built in (works offline, no warnings)
extract = tldextract.TLDExtract(suffix_list_urls=())

# ------------------------------------------------------------------ word lists
# Brand name -> its REAL website
BRANDS = {
    "paypal": "paypal.com", "google": "google.com", "microsoft": "microsoft.com",
    "apple": "apple.com", "amazon": "amazon.com", "netflix": "netflix.com",
    "facebook": "facebook.com", "instagram": "instagram.com", "whatsapp": "whatsapp.com",
    "linkedin": "linkedin.com", "github": "github.com", "dropbox": "dropbox.com",
    "outlook": "outlook.com", "dhl": "dhl.com", "fedex": "fedex.com",
    "binance": "binance.com", "office365": "office.com", "icloud": "icloud.com",
}

SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
              "buff.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc"]

SUSPICIOUS_TLDS = ["xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link",
                   "work", "zip", "mov", "rest", "cam", "icu", "buzz", "support"]

# Attackers swap letters for numbers that look similar: paypa1, micros0ft
LOOKALIKE_CHARS = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a"}


# ------------------------------------------------------------------ helpers
def finding(check, severity, detail):
    return {"check": check, "severity": severity, "detail": detail}


def undo_lookalikes(text):
    """'paypa1' -> 'paypal', 'micros0ft' -> 'microsoft'"""
    for fake, real in LOOKALIKE_CHARS.items():
        text = text.replace(fake, real)
    return text


def is_ip_address(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# ------------------------------------------------------------------ checks
def check_ip(host):
    if is_ip_address(host):
        return finding("IP address instead of name", "HIGH",
                       f"The link uses a number '{host}' instead of a website name")


def check_at_symbol(url):
    if "@" in url.split("//", 1)[-1].split("/")[0]:
        return finding("@ symbol trick", "HIGH",
                       "Browsers ignore everything before '@', so the real site is hidden")


def check_length(url):
    if len(url) > 75:
        return finding("Very long link", "LOW",
                       f"The link is {len(url)} characters long (long links can hide the real site)")


def check_https(scheme):
    if scheme != "https":
        return finding("No HTTPS", "MEDIUM", "The link uses 'http' (not encrypted)")


def check_punycode(host):
    if "xn--" in host:
        return finding("Punycode (fake letters)", "HIGH",
                       "The name uses look-alike letters from other alphabets")


def check_shortener(registered):
    if registered in SHORTENERS:
        return finding("Link shortener", "MEDIUM",
                       f"'{registered}' hides where the link really goes")


def check_subdomains(subdomain):
    parts = [p for p in subdomain.split(".") if p]
    if len(parts) >= 3:
        return finding("Too many subdomains", "MEDIUM",
                       f"The link has {len(parts)} parts before the real name: '{subdomain}'")


def check_suspicious_tld(suffix):
    if suffix.split(".")[-1] in SUSPICIOUS_TLDS:
        return finding("Suspicious ending", "MEDIUM",
                       f"'.{suffix}' is a cheap ending often used by attackers")


def check_hyphens(domain):
    if domain.count("-") >= 2:
        return finding("Many hyphens", "LOW",
                       f"'{domain}' has many hyphens, e.g. 'secure-login-update'")


def check_lookalike(domain, registered):
    """Find fake brand names like paypa1.com, micros0ft-support.top, paypall.com"""
    if registered in BRANDS.values():
        return None  # It IS the real site

    cleaned = undo_lookalikes(domain)
    for brand, real_site in BRANDS.items():
        # 1) Brand name appears after fixing fake letters: paypa1 -> paypal
        if brand in cleaned:
            if brand in domain:
                detail = f"'{registered}' uses the name '{brand}' but is NOT {real_site}"
            else:
                detail = f"'{registered}' pretends to be '{brand}' using fake letters"
            return finding("Lookalike brand", "HIGH", detail)

        # 2) Almost the same spelling: paypall, amazn, gooogle
        for word in re.split(r"[-.]", cleaned):
            similarity = SequenceMatcher(None, word, brand).ratio()
            if len(word) >= 4 and similarity >= 0.85:
                return finding("Lookalike brand", "HIGH",
                               f"'{word}' looks like '{brand}' ({int(similarity * 100)}% the same)")
    return None


def check_brand_in_wrong_place(subdomain, path, registered):
    """paypal.com.login-secure.xyz  -> brand is in the subdomain, real site is login-secure.xyz"""
    if registered in BRANDS.values():
        return None
    text = (subdomain + " " + path).lower()
    for brand, real_site in BRANDS.items():
        if brand in text:
            return finding("Brand in the wrong place", "HIGH",
                           f"'{brand}' appears in the link, but the real site is '{registered}'")
    return None


def check_domain_age(registered):
    """Ask WHOIS when the domain was created. New domains (< 30 days) are risky."""
    try:
        import whois
        data = whois.whois(registered)
        created = data.creation_date
        if isinstance(created, list):
            created = created[0]
        if not created:
            return None, "unknown"
        age_days = (datetime.now() - created.replace(tzinfo=None)).days
        if age_days < 30:
            return finding("Very new website", "HIGH",
                           f"'{registered}' was created only {age_days} days ago"), age_days
        return None, age_days
    except Exception:
        return None, "unknown (WHOIS lookup failed)"


# ------------------------------------------------------------------ main function
def analyze_url(url, use_whois=True):
    url = url.strip()
    if not re.match(r"^[a-zA-Z]+://", url):
        url = "http://" + url  # people often paste links without http://

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    ext = extract(host)
    registered = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

    findings = []

    if is_ip_address(host):
        findings.append(check_ip(host))
    else:
        for result in [
            check_punycode(host),
            check_shortener(registered),
            check_subdomains(ext.subdomain),
            check_suspicious_tld(ext.suffix),
            check_hyphens(ext.domain),
            check_lookalike(ext.domain, registered),
            check_brand_in_wrong_place(ext.subdomain, parsed.path, registered),
        ]:
            if result:
                findings.append(result)

    for result in [check_at_symbol(url), check_length(url), check_https(parsed.scheme)]:
        if result:
            findings.append(result)

    age = "skipped"
    if use_whois and not is_ip_address(host) and ext.suffix:
        age_finding, age = check_domain_age(registered)
        if age_finding:
            findings.append(age_finding)

    return {
        "url": url,
        "host": host,
        "registered_domain": registered,
        "subdomain": ext.subdomain,
        "domain_age_days": age,
        "findings": findings,
    }


def print_report(report):
    icons = {"HIGH": "[!!!]", "MEDIUM": "[!! ]", "LOW": "[ ! ]"}
    print("=" * 60)
    print(f" URL ANALYSIS: {report['url']}")
    print("=" * 60)
    print(f" Real website : {report['registered_domain']}")
    print(f" Subdomain    : {report['subdomain'] or '(none)'}")
    age = report["domain_age_days"]
    print(f" Domain age   : {age} days" if isinstance(age, int) else f" Domain age   : {age}")
    print(f"\n Red flags found: {len(report['findings'])}")
    if not report["findings"]:
        print("   None - this link looks clean.")
    for f in report["findings"]:
        print(f"   {icons[f['severity']]} {f['check']}: {f['detail']}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    args = sys.argv[1:]
    use_whois = "--no-whois" not in args
    urls = [a for a in args if a != "--no-whois"]
    if not urls:
        print('Usage: python analyzer/url_analyzer.py "<url>" [more urls] [--no-whois]')
        sys.exit(1)
    for u in urls:
        print_report(analyze_url(u, use_whois))
