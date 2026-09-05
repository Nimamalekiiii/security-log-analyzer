from datetime import datetime
import sys
import json
import argparse


def read_log_file(filename):
    try:
        with open(filename, "r") as file:
            return file.readlines()
    except FileNotFoundError:
        print(f"❌ Error: Log file '{filename}' was not found.")
        sys.exit(1)


def analyze_logins(logs):
    login_data = {}

    for log in logs:
        if "LOGIN_FAILED" not in log and "LOGIN_SUCCESS" not in log:
            continue

        try:
            timestamp = log[:19]
            time = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")

            ip = log.split("ip=")[1].strip()
            user = log.split("user=")[1].split(" ip=")[0]

        except (ValueError, IndexError):
            print("⚠️ Warning: Skipping invalid log entry.")
            continue

        if ip not in login_data:
            login_data[ip] = {
                "failed_attempts": 0,
                "successful_logins": 0,
                "users": set(),
                "events": []
            }

        login_data[ip]["users"].add(user)

        if "LOGIN_FAILED" in log:
            login_data[ip]["failed_attempts"] += 1
            login_data[ip]["events"].append({
                "type": "FAILED",
                "time": time,
                "user": user
            })

        elif "LOGIN_SUCCESS" in log:
            login_data[ip]["successful_logins"] += 1
            login_data[ip]["events"].append({
                "type": "SUCCESS",
                "time": time,
                "user": user
            })

    return login_data


def detect_suspicious_login_pattern(events):
    events.sort(key=lambda event: event["time"])

    failed_attempts = 0

    for event in events:
        if event["type"] == "FAILED":
            failed_attempts += 1

        elif event["type"] == "SUCCESS":
            if failed_attempts >= 2:
                return True

            failed_attempts = 0

    return False


def detect_multiple_users(users):
    return len(users) >= 3


def detect_account_enumeration(events):
    failed_users = set()

    for event in events:
        if event["type"] == "FAILED":
            failed_users.add(event["user"])

    return len(failed_users) >= 3


def detect_brute_force(timestamps):
    timestamps.sort()

    for i in range(len(timestamps)):
        start_time = timestamps[i]

        for j in range(i + 1, len(timestamps)):
            time_difference = timestamps[j] - start_time

            if time_difference.total_seconds() <= 60 and j - i >= 4:
                return True

    return False


def calculate_risk_score(attempts, brute_force=False,
                         suspicious_pattern=False,
                         multiple_users=False,
                         account_enumeration=False):

    score = 0

    score += min(attempts * 5, 25)

    if brute_force:
        score += 50

    if suspicious_pattern:
        score += 20

    if multiple_users:
        score += 10

    if account_enumeration:
        score += 25

    return min(score, 100)


def calculate_risk_level(score):
    if score >= 70:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    else:
        return "LOW"


def generate_report(login_data, output_file):
    total_ips = len(login_data)
    total_failed_logins = 0
    total_successful_logins = 0

    high_risk = 0
    medium_risk = 0
    low_risk = 0
    brute_force_alerts = 0
    suspicious_pattern_alerts = 0
    multiple_user_alerts = 0
    account_enumeration_alerts = 0

    report = []

    report.append("================================")
    report.append("       SECURITY REPORT")
    report.append("================================")
    report.append("")

    for ip, data in login_data.items():
        attempts = data["failed_attempts"]
        successful_logins = data["successful_logins"]
        users = ", ".join(data["users"])
        events = data["events"]

        total_failed_logins += attempts
        total_successful_logins += successful_logins

        failed_timestamps = [
            event["time"]
            for event in events
            if event["type"] == "FAILED"
        ]

        brute_force = detect_brute_force(failed_timestamps)
        suspicious_pattern = detect_suspicious_login_pattern(events)
        multiple_users = detect_multiple_users(data["users"])
        account_enumeration = detect_account_enumeration(events)

        risk_score = calculate_risk_score(
            attempts,
            brute_force,
            suspicious_pattern,
            multiple_users,
            account_enumeration
        )

        risk = calculate_risk_level(risk_score)

        if risk == "HIGH":
            high_risk += 1
        elif risk == "MEDIUM":
            medium_risk += 1
        else:
            low_risk += 1

        if brute_force:
            brute_force_alerts += 1

        if suspicious_pattern:
            suspicious_pattern_alerts += 1

        if multiple_users:
            multiple_user_alerts += 1

        if account_enumeration:
            account_enumeration_alerts += 1

        report.append(f"IP: {ip}")
        report.append(f"Target user(s): {users}")
        report.append(f"Failed logins: {attempts}")
        report.append(f"Successful logins: {successful_logins}")
        report.append(f"Risk score: {risk_score}/100")
        report.append(f"Risk level: {risk}")

        if brute_force:
            report.append("[HIGH] 🚨 Possible brute-force attack detected!")
            report.append(
                "Multiple failed logins detected within 60 seconds."
            )

        if suspicious_pattern:
            report.append("[MEDIUM] ⚠️ Suspicious login pattern detected!")
            report.append(
                "Multiple failed logins were followed by a successful login."
            )

        if multiple_users:
            report.append("[MEDIUM] ⚠️ Multiple user accounts targeted!")
            report.append(
                "Several different usernames were attempted from the same IP address."
            )

        if account_enumeration:
            report.append("[MEDIUM] ⚠️ Possible account enumeration detected!")
            report.append(
                "Multiple different usernames received failed login attempts from the same IP address."
            )

        report.append("")

    report.append("================================")
    report.append("           SUMMARY")
    report.append("================================")
    report.append("")
    report.append(f"IPs analyzed: {total_ips}")
    report.append(f"Failed login attempts: {total_failed_logins}")
    report.append(f"Successful logins: {total_successful_logins}")
    report.append(f"High risk IPs: {high_risk}")
    report.append(f"Medium risk IPs: {medium_risk}")
    report.append(f"Low risk IPs: {low_risk}")
    report.append(f"Brute-force alerts: {brute_force_alerts}")
    report.append(
        f"Suspicious login pattern alerts: {suspicious_pattern_alerts}"
    )
    report.append(f"Multiple user alerts: {multiple_user_alerts}")
    report.append(
        f"Account enumeration alerts: {account_enumeration_alerts}"
    )

    report_text = "\n".join(report)

    print(report_text)

    with open(output_file, "w") as file:
        file.write(report_text)

    print(f"\nReport saved to: {output_file}")


def generate_json_report(login_data, output_file):
    json_data = []

    for ip, data in login_data.items():
        attempts = data["failed_attempts"]
        successful_logins = data["successful_logins"]
        users = list(data["users"])
        events = data["events"]

        failed_timestamps = [
            event["time"]
            for event in events
            if event["type"] == "FAILED"
        ]

        brute_force = detect_brute_force(failed_timestamps)
        suspicious_pattern = detect_suspicious_login_pattern(events)
        multiple_users = detect_multiple_users(data["users"])
        account_enumeration = detect_account_enumeration(events)

        risk_score = calculate_risk_score(
            attempts,
            brute_force,
            suspicious_pattern,
            multiple_users,
            account_enumeration
        )

        risk = calculate_risk_level(risk_score)

        json_data.append({
            "ip": ip,
            "users": users,
            "failed_logins": attempts,
            "successful_logins": successful_logins,
            "risk_score": risk_score,
            "risk_level": risk,
            "brute_force_detected": brute_force,
            "suspicious_login_pattern": suspicious_pattern,
            "multiple_users_targeted": multiple_users,
            "account_enumeration_detected": account_enumeration
        })

    with open(output_file, "w") as file:
        json.dump(json_data, file, indent=4)

    print(f"JSON report saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze security login logs for suspicious activity."
    )

    parser.add_argument(
        "logfile",
        help="Path to the security log file"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Generate a JSON security report"
    )

    parser.add_argument(
        "--output",
        help="Output file name"
    )

    args = parser.parse_args()

    logs = read_log_file(args.logfile)
    login_data = analyze_logins(logs)

    if args.json:
        output_file = args.output or "security_report.json"
        generate_json_report(login_data, output_file)
    else:
        output_file = args.output or "security_report.txt"
        generate_report(login_data, output_file)


if __name__ == "__main__":
    main()