"""Explainable, offline URL risk triage for learning and defensive use."""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlsplit


SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "ow.ly", "is.gd", "buff.ly", "rebrand.ly"}
SUSPICIOUS_TLDS = {"zip", "mov", "country", "click", "gq", "tk", "work", "top"}
BRAND_WORDS = {"paypal", "microsoft", "google", "apple", "amazon", "netflix", "facebook", "instagram"}
IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


@dataclass
class Finding:
    signal: str
    points: int
    detail: str


@dataclass
class Assessment:
    input_url: str
    normalized_url: str
    host: str
    score: int
    rating: str
    findings: list[Finding]
    limitations: str = "Heuristic triage only; this result cannot prove that a URL is safe or malicious."

    def to_dict(self) -> dict:
        result = asdict(self)
        result["findings"] = [asdict(item) for item in self.findings]
        return result


def inspect_url(value: str) -> Assessment:
    """Score visible URL characteristics without connecting to the URL."""
    raw = value.strip()
    normalized = raw if "://" in raw else f"https://{raw}"
    parsed = urlsplit(normalized)
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host or any(ch.isspace() for ch in raw):
        raise ValueError("Enter a valid URL or hostname.")

    findings: list[Finding] = []

    def flag(signal: str, points: int, detail: str) -> None:
        findings.append(Finding(signal, points, detail))

    if parsed.scheme.lower() != "https":
        flag("http_scheme", 15, "The address does not use HTTPS.")
    if "@" in parsed.netloc:
        flag("userinfo", 25, "The URL contains user-info before the host, which can disguise the destination.")
    if len(raw) >= 100:
        flag("long_url", 10, "The URL is unusually long (100 or more characters).")
    if len(host.split(".")) >= 5:
        flag("many_subdomains", 10, "The hostname has many subdomain levels.")
    if "xn--" in host:
        flag("punycode", 20, "The hostname contains an encoded internationalized label; inspect it carefully for lookalikes.")
    if IPV4.match(host):
        flag("ip_host", 15, "The hostname is an IPv4 address rather than a named domain.")
    if host in SHORTENERS:
        flag("url_shortener", 15, "A URL-shortening service hides the final destination.")
    if host.count("-") >= 3:
        flag("hyphenated_host", 10, "The hostname contains several hyphens.")
    if sum(ch.isdigit() for ch in host) >= 5:
        flag("digits_in_host", 10, "The hostname contains several digits.")
    if parsed.scheme.lower() == "http" and parsed.port == 80:
        flag("explicit_http_port", 5, "The address specifies the default unencrypted HTTP port.")
    labels = host.split(".")
    if len(labels) >= 2 and labels[-1] in SUSPICIOUS_TLDS:
        flag("uncommon_tld", 10, f"The top-level domain .{labels[-1]} is uncommon in this basic rule set.")
    for brand in sorted(BRAND_WORDS):
        if brand in host and not (host == brand or host.endswith(f".{brand}")):
            flag("brand_in_subdomain_or_label", 15, f"The hostname includes the brand name '{brand}' without being that brand's domain.")

    score = min(100, sum(f.points for f in findings))
    rating = "high" if score >= 45 else "medium" if score >= 20 else "low"
    return Assessment(raw, normalized, host, score, rating, findings)


def read_urls(path: Path) -> list[str]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        return [row[0].strip() for row in csv.reader(stream) if row and row[0].strip() and not row[0].lstrip().startswith("#")]


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline, explainable URL risk triage (no network requests).")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("url", nargs="?", help="URL or hostname to inspect")
    source.add_argument("--file", type=Path, help="CSV or text file with one URL per line")
    parser.add_argument("--json", action="store_true", help="Write machine-readable JSON")
    parser.add_argument("--output", type=Path, help="Save results as JSON Lines")
    args = parser.parse_args()

    try:
        urls = [args.url] if args.url else read_urls(args.file)
        results = [inspect_url(url).to_dict() for url in urls]
    except (OSError, ValueError) as exc:
        print(f"phishlens: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(results if len(results) != 1 else results[0], indent=2))
    else:
        for item in results:
            print(f"{item['rating'].upper():6}  {item['score']:3}/100  {item['host']}")
            for finding in item["findings"]:
                print(f"  +{finding['points']:2} {finding['detail']}")
            if not item["findings"]:
                print("  No configured risk signals were detected.")
            print(f"  Note: {item['limitations']}")

    if args.output:
        with args.output.open("w", encoding="utf-8") as stream:
            for item in results:
                stream.write(json.dumps(item) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
