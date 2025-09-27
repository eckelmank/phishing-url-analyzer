# Phishing URL Risk Analyzer (heuristics-based)
# Author: Kaylee Eckelman
# Usage:
#   python phishing_url_analyzer.py --input urls.csv --output results.csv --plot
# The --plot flag is optional; it requires matplotlib.

import argparse, re, csv, sys, ipaddress
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = {"verify","update","login","secure","account","bank",
                       "limited","confirm","urgent","password","invoice","reset","unlock"}
SUSPICIOUS_TLDS = {"zip","mov","gq","tk","ml","cf","xyz","top","work","fit","rest","date","link","country"}

def hostname_from_url(url):
    try:
        parsed = urlparse(url if re.match(r'^\w+://', url) else 'http://' + url)
        host = parsed.hostname or ""
        return host.lower()
    except Exception:
        return ""

def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False

def tld_of(host):
    parts = host.split('.')
    if len(parts) >= 2:
        return parts[-1]
    return ""

def score_url(url):
    host = hostname_from_url(url)
    host_no_www = host[4:] if host.startswith('www.') else host
    path = urlparse(url if '://' in url else 'http://' + url).path.lower()
    tld = tld_of(host_no_www)
    score = 0
    reasons = []

    # Heuristics
    if is_ip(host_no_www):
        score += 3; reasons.append("Uses IP instead of domain")
    if len(url) > 80:
        score += 2; reasons.append("Very long URL")
    hyphens = host_no_www.count('-')
    if hyphens >= 2:
        score += 1; reasons.append("Many hyphens in domain")
    dots = host_no_www.count('.')
    if dots >= 3:
        score += 1; reasons.append("Deep subdomain chain")
    if '@' in url:
        score += 2; reasons.append("'@' present in URL")
    if '%' in url or url.lower().startswith('http://'):
        score += 1; reasons.append("Obfuscation or no HTTPS")
    if tld in SUSPICIOUS_TLDS:
        score += 2; reasons.append(f"Suspicious TLD .{tld}")

    # keyword checks
    text = (host_no_www + " " + path).lower()
    hits = [k for k in SUSPICIOUS_KEYWORDS if k in text]
    if hits:
        score += 2; reasons.append("Phishy keywords: " + ", ".join(sorted(hits)))

    # digits ratio in host
    letters = sum(c.isalpha() for c in host_no_www)
    digits = sum(c.isdigit() for c in host_no_www)
    if letters + digits > 0:
        ratio = digits / (letters + digits)
        if ratio > 0.35:
            score += 1; reasons.append("Unusual digit-heavy domain")

    verdict = "Likely Phishing" if score >= 5 else ("Suspicious" if score >= 3 else "Likely Legit")
    return score, verdict, "; ".join(reasons)

def process_rows(rows):
    results = []
    for url in rows:
        s, v, why = score_url(url)
        results.append({"url": url, "score": s, "verdict": v, "reasons": why})
    return results

def main():
    parser = argparse.ArgumentParser(description="Phishing URL risk scorer (heuristics-based)")
    parser.add_argument("--input","-i", default="urls.csv", help="CSV file with a 'url' column")
    parser.add_argument("--output","-o", default="results.csv", help="Output CSV path")
    parser.add_argument("--plot", action="store_true", help="Show verdict distribution (requires matplotlib)")
    args = parser.parse_args()

    # Read URLs
    urls = []
    try:
        with open(args.input, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            if 'url' not in reader.fieldnames:
                print("Input CSV must have a 'url' column.", file=sys.stderr)
                sys.exit(2)
            for row in reader:
                urls.append(row['url'])
    except FileNotFoundError:
        print(f"Input file not found: {args.input}", file=sys.stderr)
        sys.exit(2)

    results = process_rows(urls)

    # Write results
    with open(args.output, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=["url","score","verdict","reasons"])
        writer.writeheader()
        writer.writerows(results)
    print(f"Wrote {len(results)} rows to {args.output}")

    if args.plot:
        try:
            import matplotlib.pyplot as plt
            from collections import Counter
            counts = Counter(r['verdict'] for r in results)
            labels, values = zip(*counts.items()) if counts else ([], [])
            plt.figure(figsize=(6,4))
            plt.bar(labels, values)
            plt.title("Verdict Distribution")
            plt.ylabel("Count")
            plt.tight_layout()
            plt.show()
        except Exception as e:
            print("Plotting failed (matplotlib not installed or other issue):", e, file=sys.stderr)

if __name__ == "__main__":
    main()
