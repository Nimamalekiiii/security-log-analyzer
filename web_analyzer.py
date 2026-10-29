"""Web attack detector for Apache/Nginx access logs.

Companion to analyzer.py (which handles login logs). This module inspects
HTTP access logs and flags web attacks such as SQL injection, XSS, path
traversal and automated scanning — the same attacks demonstrated in the
SecForge lab (https://github.com/Nimamalekiiii/secforge-lab).
"""

from datetime import datetime
from urllib.parse import unquote
import re
import sys
import json
import argparse


# Each pattern below maps a regex (matched against the decoded request)
# to the attack category it indicates.
SQLI_PATTERNS = [
    r"union\s+select", r"or\s+1\s*=\s*1", r"'\s*or\s*'", r"--\s",
    r"information_schema", r"sleep\s*\(", r"benchmark\s*\(", r"xp_cmdshell",
]
XSS_PATTERNS = [
    r"<script", r"onerror\s*=", r"onload\s*=", r"javascript:", r"<iframe",
    r"<img[^>]+src", r"alert\s*\(",
]
TRAVERSAL_PATTERNS = [
    r"\.\./", r"\.\.\\", r"/etc/passwd", r"/etc/shadow", r"boot\.ini",
]
SCANNER_AGENTS = [
    "sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster",
    "wpscan", "hydra", "curl", "python-urllib",
]

LOG_RE = re.compile(
    r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^"]*?) HTTP/[\d.]+" (\d{3}) (\S+)'
    r'(?: "([^"]*)" "([^"]*)")?'
)


def read_log_file(filename):
    try:
        with open(filename, "r") as file:
            return file.readlines()
    except FileNotFoundError:
        print(f"❌ Error: Log file '{filename}' was not found.")
        sys.exit(1)


def match_any(text, patterns):
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)


def classify_request(request, user_agent):
    """Return the set of attack categories a single request matches."""
    decoded = unquote(request)
    hits = set()

    if match_any(decoded, SQLI_PATTERNS):
        hits.add("sql_injection")
    if match_any(decoded, XSS_PATTERNS):
        hits.add("xss")
    if match_any(decoded, TRAVERSAL_PATTERNS):
        hits.add("path_traversal")
    if any(agent in user_agent.lower() for agent in SCANNER_AGENTS):
        hits.add("scanner")

    return hits


def analyze_requests(logs):
    data = {}

    for line in logs:
        match = LOG_RE.match(line.strip())
        if not match:
            continue

        ip = match.group(1)
        raw_time = match.group(2)
        request = match.group(4)
        status = int(match.group(5))
        user_agent = match.group(8) or ""

        try:
            time = datetime.strptime(raw_time.split()[0], "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            time = None

        if ip not in data:
            data[ip] = {
                "requests": 0,
                "not_found": 0,
                "attacks": {
                    "sql_injection": 0,
                    "xss": 0,
                    "path_traversal": 0,
                    "scanner": 0,
                },
                "paths": set(),
                "first_seen": time,
                "last_seen": time,
            }

        entry = data[ip]
        entry["requests"] += 1
        entry["paths"].add(request.split("?")[0])

        if status == 404:
            entry["not_found"] += 1

        if time:
            if entry["first_seen"] is None or time < entry["first_seen"]:
                entry["first_seen"] = time
            if entry["last_seen"] is None or time > entry["last_seen"]:
                entry["last_seen"] = time

        for category in classify_request(request, user_agent):
            entry["attacks"][category] += 1

    return data


def detect_path_scanning(entry):
    """Many 404s or many distinct paths from one IP = scanning/enumeration."""
    return entry["not_found"] >= 10 or len(entry["paths"]) >= 20


def calculate_risk_score(entry):
    score = 0
    attacks = entry["attacks"]

    score += min(attacks["sql_injection"] * 20, 60)
    score += min(attacks["path_traversal"] * 20, 40)
    score += min(attacks["xss"] * 10, 30)

    if attacks["scanner"]:
        score += 25
    if detect_path_scanning(entry):
        score += 20

    return min(score, 100)


def calculate_risk_level(score):
    if score >= 70:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    else:
        return "LOW"


def build_findings(data):
    findings = []
    for ip, entry in data.items():
        score = calculate_risk_score(entry)
        findings.append({
            "ip": ip,
            "requests": entry["requests"],
            "not_found": entry["not_found"],
            "distinct_paths": len(entry["paths"]),
            "sql_injection": entry["attacks"]["sql_injection"],
            "xss": entry["attacks"]["xss"],
            "path_traversal": entry["attacks"]["path_traversal"],
            "scanner": entry["attacks"]["scanner"],
            "scanning": detect_path_scanning(entry),
            "risk_score": score,
            "risk_level": calculate_risk_level(score),
        })
    findings.sort(key=lambda f: f["risk_score"], reverse=True)
    return findings


def generate_report(findings, output_file):
    report = []
    report.append("====================================")
    report.append("       WEB ATTACK REPORT")
    report.append("====================================")
    report.append("")

    high = medium = low = 0

    for f in findings:
        if f["risk_level"] == "HIGH":
            high += 1
        elif f["risk_level"] == "MEDIUM":
            medium += 1
        else:
            low += 1

        report.append(f"IP: {f['ip']}")
        report.append(f"Requests: {f['requests']}  (404s: {f['not_found']}, "
                      f"distinct paths: {f['distinct_paths']})")
        report.append(f"Risk score: {f['risk_score']}/100")
        report.append(f"Risk level: {f['risk_level']}")

        if f["sql_injection"]:
            report.append(f"[HIGH] 🚨 SQL injection attempts: {f['sql_injection']}")
        if f["path_traversal"]:
            report.append(f"[HIGH] 🚨 Path traversal attempts: {f['path_traversal']}")
        if f["xss"]:
            report.append(f"[MEDIUM] ⚠️ XSS attempts: {f['xss']}")
        if f["scanner"]:
            report.append("[MEDIUM] ⚠️ Automated scanner / tool user-agent detected")
        if f["scanning"]:
            report.append("[MEDIUM] ⚠️ Path scanning / enumeration (many 404s or paths)")

        report.append("")

    report.append("====================================")
    report.append("             SUMMARY")
    report.append("====================================")
    report.append("")
    report.append(f"IPs analyzed: {len(findings)}")
    report.append(f"High risk IPs: {high}")
    report.append(f"Medium risk IPs: {medium}")
    report.append(f"Low risk IPs: {low}")

    report_text = "\n".join(report)
    print(report_text)

    with open(output_file, "w") as file:
        file.write(report_text)

    print(f"\nReport saved to: {output_file}")


def generate_json_report(findings, output_file):
    with open(output_file, "w") as file:
        json.dump(findings, file, indent=4)
    print(f"JSON report saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Detect web attacks (SQLi, XSS, traversal, scanning) in access logs."
    )
    parser.add_argument("logfile", help="Path to the web access log file")
    parser.add_argument("--json", action="store_true",
                        help="Generate a JSON report")
    parser.add_argument("--output", help="Output file name")
    args = parser.parse_args()

    logs = read_log_file(args.logfile)
    data = analyze_requests(logs)
    findings = build_findings(data)

    if args.json:
        generate_json_report(findings, args.output or "web_report.json")
    else:
        generate_report(findings, args.output or "web_report.txt")


if __name__ == "__main__":
    main()
