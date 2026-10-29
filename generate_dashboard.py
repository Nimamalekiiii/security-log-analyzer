"""Generate dashboard data (docs/data.js) from the security logs.

Reads the login log and the web access log, runs the detectors from
analyzer.py and web_analyzer.py, and writes a JSON blob that the SIEM
dashboard (docs/index.html) renders.
"""

from datetime import datetime
from collections import defaultdict
import json
import os

import analyzer
import web_analyzer

LOGIN_LOG = "security.log"
WEB_LOG = "web_access.log"
OUT = os.path.join("docs", "data.js")


def login_section():
    ips = {}
    if not os.path.exists(LOGIN_LOG):
        return ips
    data = analyzer.analyze_logins(analyzer.read_log_file(LOGIN_LOG))
    for ip, d in data.items():
        failed_times = [e["time"] for e in d["events"] if e["type"] == "FAILED"]
        brute = analyzer.detect_brute_force(failed_times)
        susp = analyzer.detect_suspicious_login_pattern(d["events"])
        multi = analyzer.detect_multiple_users(d["users"])
        enum = analyzer.detect_account_enumeration(d["events"])
        score = analyzer.calculate_risk_score(d["failed_attempts"], brute, susp, multi, enum)
        ips[ip] = {
            "score": score,
            "level": analyzer.calculate_risk_level(score),
            "failed": d["failed_attempts"],
            "brute": brute,
            "enum": enum,
            "events": len(d["events"]),
        }
    return ips


def web_section():
    if not os.path.exists(WEB_LOG):
        return [], 0
    logs = web_analyzer.read_log_file(WEB_LOG)
    findings = web_analyzer.build_findings(web_analyzer.analyze_requests(logs))
    total = sum(f["requests"] for f in findings)
    return findings, total


def build_timeline():
    buckets = defaultdict(int)
    if os.path.exists(LOGIN_LOG):
        for line in analyzer.read_log_file(LOGIN_LOG):
            if "LOGIN_FAILED" in line:
                try:
                    t = datetime.strptime(line[:19], "%Y-%m-%d %H:%M:%S")
                    buckets[t.strftime("%H:%M")] += 1
                except ValueError:
                    pass
    if os.path.exists(WEB_LOG):
        for line in web_analyzer.read_log_file(WEB_LOG):
            m = web_analyzer.LOG_RE.match(line.strip())
            if not m:
                continue
            if web_analyzer.classify_request(m.group(4), m.group(8) or ""):
                try:
                    t = datetime.strptime(m.group(2).split()[0], "%d/%b/%Y:%H:%M:%S")
                    buckets[t.strftime("%H:%M")] += 1
                except ValueError:
                    pass
    return [{"time": k, "count": buckets[k]} for k in sorted(buckets)]


def main():
    login = login_section()
    web, web_requests = web_section()

    # --- summary ---
    unique_ips = set(login) | {f["ip"] for f in web}
    levels = [v["level"] for v in login.values()] + [f["risk_level"] for f in web]
    total_login_events = sum(v["events"] for v in login.values())

    attack_types = {
        "SQL injection": sum(f["sql_injection"] for f in web),
        "XSS": sum(f["xss"] for f in web),
        "Path traversal": sum(f["path_traversal"] for f in web),
        "Scanner": sum(1 for f in web if f["scanner"] > 0),
        "Brute force": sum(1 for v in login.values() if v["brute"]),
        "Enumerering": sum(1 for v in login.values() if v["enum"]),
    }
    attack_types = {k: v for k, v in attack_types.items() if v > 0}

    # --- top IPs ---
    top = []
    for ip, v in login.items():
        top.append({"ip": ip, "risk_score": v["score"], "risk_level": v["level"]})
    for f in web:
        top.append({"ip": f["ip"], "risk_score": f["risk_score"], "risk_level": f["risk_level"]})
    top = sorted(top, key=lambda x: x["risk_score"], reverse=True)[:7]

    # --- findings table ---
    findings = []
    for ip, v in sorted(login.items(), key=lambda kv: kv[1]["score"], reverse=True):
        flags = []
        if v["brute"]:
            flags.append("brute force")
        if v["enum"]:
            flags.append("enumerering")
        detail = f"{v['failed']} mislykkede innlogginger" + (f" ({', '.join(flags)})" if flags else "")
        findings.append({"ip": ip, "source": "Innlogging", "detail": detail,
                         "risk_score": v["score"], "risk_level": v["level"]})
    for f in sorted(web, key=lambda x: x["risk_score"], reverse=True):
        parts = []
        if f["sql_injection"]:
            parts.append(f"SQLi x{f['sql_injection']}")
        if f["xss"]:
            parts.append(f"XSS x{f['xss']}")
        if f["path_traversal"]:
            parts.append(f"traversal x{f['path_traversal']}")
        if f["scanner"]:
            parts.append("scanner")
        if f["scanning"]:
            parts.append("scanning")
        detail = ", ".join(parts) if parts else f"{f['requests']} forespørsler"
        findings.append({"ip": f["ip"], "source": "Web", "detail": detail,
                         "risk_score": f["risk_score"], "risk_level": f["risk_level"]})
    findings = sorted(findings, key=lambda x: x["risk_score"], reverse=True)

    payload = {
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "summary": {
            "total_events": total_login_events + web_requests,
            "unique_ips": len(unique_ips),
            "high_risk": levels.count("HIGH"),
            "medium_risk": levels.count("MEDIUM"),
            "low_risk": levels.count("LOW"),
        },
        "attack_types": attack_types,
        "top_ips": top,
        "timeline": build_timeline(),
        "findings": findings,
    }

    os.makedirs("docs", exist_ok=True)
    with open(OUT, "w") as f:
        f.write("window.SIEM_DATA = " + json.dumps(payload, indent=2) + ";\n")
    print(f"✅ Skrev {OUT}")
    print(f"   {payload['summary']['total_events']} hendelser, "
          f"{payload['summary']['high_risk']} høy-risiko IP-er, "
          f"{len(attack_types)} angrepstyper")


if __name__ == "__main__":
    main()
