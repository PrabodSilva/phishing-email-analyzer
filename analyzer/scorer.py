"""
scorer.py  -  Day 3 of the Phishing Email Analyzer  (the "brain")

Joins Day 1 (headers) + Day 2 (links) + Day 3 (body) together,
gives points for every red flag, and makes the final decision:

    SAFE        - looks genuine
    SUSPICIOUS  - be careful
    PHISHING    - fake / dangerous

Usage:
    python analyzer/scorer.py sample_emails/phish_paypal.eml
    python analyzer/scorer.py "http://paypa1-alerts.xyz/login"
"""

import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from header_analyzer import analyze_headers, get_domain, finding
from url_analyzer import analyze_url, extract, check_lookalike, check_suspicious_tld, check_punycode
from body_analyzer import analyze_body

# ------------------------------------------------------------------ points
# How many points each red flag adds (bigger = more dangerous)
POINTS = {
    # Day 1 - headers
    "Reply-To mismatch": 15,
    "Return-Path mismatch": 5,
    "Display-name spoofing": 15,
    "SPF check": 15,
    "DKIM check": 10,
    "DMARC check": 15,
    # Day 2 - links
    "IP address instead of name": 25,
    "@ symbol trick": 25,
    "Punycode (fake letters)": 25,
    "Lookalike brand": 30,
    "Brand in the wrong place": 30,
    "Very new website": 20,
    "Link shortener": 10,
    "Too many subdomains": 10,
    "Suspicious ending": 15,
    "No HTTPS": 10,
    "Many hyphens": 5,
    "Very long link": 5,
    # Day 3 - body
    "Link text mismatch": 30,
    "Asks for secret info": 15,
    "Risky attachment": 25,
    "Urgency words": 10,
    "Generic greeting": 5,
    # Sender's own domain
    "Sender lookalike": 30,
    "Sender risky ending": 15,
    "Sender fake letters": 25,
}
LOW_POINTS = 3  # e.g. "SPF result missing" is only a small warning

# Very short, simple reasons for the web page
SHORT_REASON = {
    "Reply-To mismatch": "Replies go to a different address",
    "Return-Path mismatch": "Bounced mail goes to another domain",
    "Display-name spoofing": "Sender name pretends to be a known brand",
    "SPF check": "Sender failed the SPF security check",
    "DKIM check": "Email has no valid digital signature (DKIM)",
    "DMARC check": "Sender failed the DMARC security check",
    "IP address instead of name": "Link uses a number (IP) instead of a website name",
    "@ symbol trick": "Link hides the real website using '@'",
    "Punycode (fake letters)": "Website name uses fake look-alike letters",
    "Lookalike brand": "Website pretends to be a famous brand",
    "Brand in the wrong place": "Brand name is used to disguise a different website",
    "Very new website": "Website was created very recently",
    "Link shortener": "Short link hides the real destination",
    "Too many subdomains": "Link has too many parts to confuse you",
    "Suspicious ending": "Website uses a cheap, risky ending (.xyz, .top...)",
    "No HTTPS": "Link is not secure (http)",
    "Many hyphens": "Website name has many hyphens",
    "Very long link": "Link is very long",
    "Link text mismatch": "A link shows one website but opens another",
    "Asks for secret info": "Asks for passwords or card details",
    "Risky attachment": "Has a dangerous attachment",
    "Urgency words": "Uses pressure words to rush you",
    "Generic greeting": "Doesn't use your name",
    "Sender lookalike": "Sender's address pretends to be a famous brand",
    "Sender risky ending": "Sender uses a cheap, risky domain (.xyz, .top...)",
    "Sender fake letters": "Sender's address uses fake look-alike letters",
}

VERDICT_TEXT = {
    "SAFE": "Looks genuine",
    "SUSPICIOUS": "Be careful",
    "PHISHING": "Fake / phishing",
}


def points_for(f):
    if f["severity"] == "LOW" and f["check"] in ("SPF check", "DKIM check", "DMARC check"):
        return LOW_POINTS
    return POINTS.get(f["check"], 10)


def score_findings(groups):
    """groups = {"Sender": [...], "Links": [...], "Content": [...]}
    Each kind of red flag is counted ONCE (10 bad links don't give 10x points)."""
    counted, reasons, category_points = set(), [], {}
    for category, findings in groups.items():
        category_points[category] = 0
        for f in findings:
            if f["check"] in counted:
                continue
            counted.add(f["check"])
            pts = points_for(f)
            category_points[category] += pts
            reasons.append({**f, "category": category, "points": pts,
                            "short": SHORT_REASON.get(f["check"], f["check"])})
    reasons.sort(key=lambda r: r["points"], reverse=True)
    return min(sum(category_points.values()), 100), reasons, category_points


def make_verdict(score, limits):
    safe_max, suspicious_max = limits
    if score <= safe_max:
        return "SAFE"
    if score <= suspicious_max:
        return "SUSPICIOUS"
    return "PHISHING"


def make_summary(verdict, reasons, mode):
    """One very short sentence for the web page."""
    big = [r["short"] for r in reasons if r["points"] >= 10][:2]
    if verdict == "SAFE":
        if mode == "email":
            return "Sender passed the security checks and no phishing tricks were found."
        return "No phishing tricks were found in this link."
    if not big:
        big = [r["short"] for r in reasons][:2]
    return ". ".join(big) + "."


# ------------------------------------------------------------------ public functions
def check_sender_domain(from_address):
    """Run Day 2 domain checks on the sender's domain (catches micros0ft-support.top)."""
    domain = get_domain(from_address)
    if not domain:
        return []
    ext = extract(domain)
    registered = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    new_names = {"Lookalike brand": "Sender lookalike",
                 "Suspicious ending": "Sender risky ending",
                 "Punycode (fake letters)": "Sender fake letters"}
    results = []
    for f in [check_lookalike(ext.domain, registered),
              check_suspicious_tld(ext.suffix),
              check_punycode(domain)]:
        if f:
            results.append({**f, "check": new_names[f["check"]],
                            "detail": f"Sender domain '{domain}': {f['detail']}"})
    return results


def analyze_email_file(path, use_whois=False):
    header = analyze_headers(path)
    body = analyze_body(path, use_whois)

    link_findings = []
    for lr in body["link_reports"]:
        link_findings.extend(lr["findings"])

    groups = {
        "Sender": header["findings"] + check_sender_domain(header["from_address"]),
        "Links": link_findings + [f for f in body["findings"] if f["check"] == "Link text mismatch"],
        "Content": [f for f in body["findings"] if f["check"] != "Link text mismatch"],
    }
    score, reasons, category_points = score_findings(groups)
    verdict = make_verdict(score, (30, 60))

    return {
        "mode": "email",
        "input": os.path.basename(path),
        "subject": header["subject"],
        "from": f"{header['from_name']} <{header['from_address']}>",
        "auth": header["auth"],
        "hops": header["hops"],
        "links": body["link_reports"],
        "attachments": body["attachments"],
        "score": score,
        "verdict": verdict,
        "verdict_text": VERDICT_TEXT[verdict],
        "summary": make_summary(verdict, reasons, "email"),
        "reasons": reasons,
        "category_points": category_points,
    }


def analyze_link(url, use_whois=True):
    url = url.strip()
    if "://" not in url:
        url = "https://" + url  # a pasted name like 'mail.google.com' - don't punish missing http
    report = analyze_url(url, use_whois)
    score, reasons, category_points = score_findings({"Link": report["findings"]})
    # One link has fewer checks than a whole email, so the limits are lower
    verdict = make_verdict(score, (9, 29))

    return {
        "mode": "link",
        "input": report["url"],
        "real_site": report["registered_domain"],
        "domain_age": report["domain_age_days"],
        "score": score,
        "verdict": verdict,
        "verdict_text": VERDICT_TEXT[verdict],
        "summary": make_summary(verdict, reasons, "link"),
        "reasons": reasons,
        "category_points": category_points,
    }


def analyze(user_input, use_whois=False):
    """Give it a .eml file path OR a link - it decides which one it is."""
    if user_input.lower().endswith(".eml") and os.path.isfile(user_input):
        return analyze_email_file(user_input, use_whois)
    return analyze_link(user_input, use_whois)


def print_result(result):
    badge = {"SAFE": "[ SAFE ]", "SUSPICIOUS": "[ SUSPICIOUS ]", "PHISHING": "[ PHISHING ]"}
    print("=" * 60)
    print(f" CHECKED : {result['input']}")
    if result["mode"] == "email":
        print(f" Subject : {result['subject']}")
        print(f" From    : {result['from']}")
    else:
        print(f" Real website: {result['real_site']}")
    print("-" * 60)
    print(f" RESULT  : {badge[result['verdict']]}  {result['verdict_text']}")
    print(f" SCORE   : {result['score']} / 100")
    print(f" WHY     : {result['summary']}")
    print("-" * 60)
    if result["reasons"]:
        print(" All red flags:")
        for r in result["reasons"]:
            print(f"   +{r['points']:>2}  [{r['category']}] {r['short']}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    args = sys.argv[1:]
    whois_on = "--whois" in args
    items = [a for a in args if a != "--whois"]
    if not items:
        print('Usage: python analyzer/scorer.py <file.eml or "url"> [more ...] [--whois]')
        sys.exit(1)
    for item in items:
        print_result(analyze(item, whois_on))
