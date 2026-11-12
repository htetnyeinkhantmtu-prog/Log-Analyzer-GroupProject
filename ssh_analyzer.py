# AI-assisted: Review, understand, and document the assisted sections before submission.
"""
SSH log analysis module for the CYBR 353 Log Analyzer.

Authors: Rosalin
Purpose: Parse Linux SSH authentication logs and detect suspicious activity.
AI-assisted sections must be reviewed and explained by the project authors.
"""

import csv
import ipaddress
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path


LOG_PATTERN = re.compile(
    r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r"\s+(\S+)\s+(\w+)(?:\[\d+\])?:\s+(.*)$"
)

AUTH_PATTERN = re.compile(
    r"^(Failed|Accepted)\s+(\S+)\s+for\s+"
    r"(?:(invalid user)\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)"
)


def parse_ssh_line(line, year=2026):
    """Parse one Linux syslog SSH or account-management line.

    Args:
        line (str): One line from an auth log.
        year (int): Year to apply to syslog timestamps, which omit the year.

    Returns:
        dict or None: Parsed event, or None when the line is unsupported/malformed.
    """
    if not isinstance(line, str):
        return None

    match = LOG_PATTERN.match(line.strip())

    if not match:
        return None

    try:
        timestamp = datetime.strptime(
            f"{year} {match.group(1)}",
            "%Y %b %d %H:%M:%S"
        )
    except (ValueError, TypeError):
        return None

    hostname, program, message = (
        match.group(2),
        match.group(3),
        match.group(4)
    )

    auth_match = AUTH_PATTERN.search(message)

    if auth_match:
        try:
            ipaddress.ip_address(auth_match.group(5))

            return {
                "timestamp": timestamp,
                "hostname": hostname,
                "event_type": "authentication",
                "status": "failed" if auth_match.group(1) == "Failed" else "accepted",
                "method": auth_match.group(2),
                "invalid_user": bool(auth_match.group(3)),
                "username": auth_match.group(4),
                "source_ip": auth_match.group(5),
                "source_port": int(auth_match.group(6))
            }

        except ValueError:
            return None

    invalid_match = re.search(
        r"Invalid user\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)",
        message
    )

    if invalid_match:
        try:
            ipaddress.ip_address(invalid_match.group(2))

            return {
                "timestamp": timestamp,
                "hostname": hostname,
                "event_type": "authentication",
                "status": "failed",
                "method": "unknown",
                "invalid_user": True,
                "username": invalid_match.group(1),
                "source_ip": invalid_match.group(2),
                "source_port": int(invalid_match.group(3))
            }

        except ValueError:
            return None

    if program == "useradd":
        user_match = re.search(
            r"new user:\s*name=(\S+?)(?:,|$)",
            message
        )

        if user_match:
            return {
                "timestamp": timestamp,
                "hostname": hostname,
                "event_type": "account_created",
                "username": user_match.group(1),
                "message": message
            }

    if program == "usermod":
        group_match = re.search(
            r"add ['\"]([^'\"]+)['\"] to group ['\"]([^'\"]+)['\"]",
            message
        )

        if group_match:
            return {
                "timestamp": timestamp,
                "hostname": hostname,
                "event_type": "account_modified",
                "username": group_match.group(1),
                "group": group_match.group(2),
                "message": message
            }

        return {
            "timestamp": timestamp,
            "hostname": hostname,
            "event_type": "account_modified",
            "username": None,
            "group": None,
            "message": message
        }

    return None


def load_ssh_log(file_path, year=2026):
    """Read and parse a UTF-8 SSH log file.

    Args:
        file_path (str or Path): Path to the log.
        year (int): Year used to parse syslog timestamps.

    Returns:
        list: Successfully parsed records; an empty list if reading fails.
    """
    records = []

    try:
        with Path(file_path).open("r", encoding="utf-8") as log_file:
            for line in log_file:
                record = parse_ssh_line(line, year)

                if record is not None:
                    records.append(record)

    except (OSError, UnicodeError) as error:
        print(f"Error reading SSH log: {error}")

    return records


def count_failed_logins(records):
    """Count failed SSH authentication events by source IP and username.

    Args:
        records (list): Parsed SSH records.

    Returns:
        dict: Failed-event counts under by_ip and by_user.
    """
    by_ip = Counter()
    by_user = Counter()

    for record in records:
        if (
            record.get("event_type") == "authentication"
            and record.get("status") == "failed"
        ):
            if record.get("source_ip"):
                by_ip[record["source_ip"]] += 1

            if record.get("username"):
                by_user[record["username"]] += 1

    return {
        "by_ip": dict(by_ip),
        "by_user": dict(by_user)
    }


def detect_ssh_brute_force(records, threshold=5, window=300):
    """Detect many failed SSH logins from one IP within a time window.

    Args:
        records (list): Parsed SSH records.
        threshold (int): Minimum number of failures.
        window (int): Window length in seconds.

    Returns:
        list: Brute-force alerts, one per source IP.
    """
    if (
        not isinstance(threshold, int)
        or threshold < 1
        or not isinstance(window, (int, float))
        or window <= 0
    ):
        raise ValueError(
            "threshold must be a positive integer and window must be positive"
        )

    failures = defaultdict(list)

    for record in records:
        if (
            record.get("event_type") == "authentication"
            and record.get("status") == "failed"
        ):
            if (
                record.get("source_ip")
                and isinstance(record.get("timestamp"), datetime)
            ):
                failures[record["source_ip"]].append(record["timestamp"])

    alerts = []

    for ip, times in failures.items():
        times.sort()
        left = 0

        for right, current in enumerate(times):
            while current - times[left] > timedelta(seconds=window):
                left += 1

            count = right - left + 1

            if count >= threshold:
                alerts.append({
                    "type": "ssh_brute_force",
                    "source_ip": ip,
                    "failed_attempts": count,
                    "window_seconds": window,
                    "first_failure": times[left],
                    "last_failure": current,
                    "severity": "High"
                })
                break

    return alerts


def detect_suspicious_users(records):
    """Flag root login attempts and authentication attempts using invalid users.

    Args:
        records (list): Parsed SSH records.

    Returns:
        list: Suspicious username alerts.
    """
    alerts = []

    for record in records:
        if record.get("event_type") != "authentication":
            continue

        username = (record.get("username") or "").lower()

        if username == "root":
            alerts.append({
                "type": "root_login_attempt",
                "source_ip": record.get("source_ip"),
                "username": username,
                "status": record.get("status"),
                "severity": "Medium"
            })

        if record.get("invalid_user"):
            alerts.append({
                "type": "invalid_username_attempt",
                "source_ip": record.get("source_ip"),
                "username": record.get("username"),
                "severity": "Medium"
            })

    return alerts


def detect_password_spraying(records, threshold=5, window=900):
    """Detect one source IP failing against several usernames in a time window.

    Args:
        records (list): Parsed SSH records.
        threshold (int): Minimum distinct usernames to flag.
        window (int): Window length in seconds.

    Returns:
        list: Password-spraying alerts, one per source IP.
    """
    if (
        not isinstance(threshold, int)
        or threshold < 2
        or not isinstance(window, (int, float))
        or window <= 0
    ):
        raise ValueError(
            "threshold must be at least 2 and window must be positive"
        )

    grouped = defaultdict(list)

    for record in records:
        if (
            record.get("event_type") == "authentication"
            and record.get("status") == "failed"
        ):
            ip = record.get("source_ip")
            user = record.get("username")
            stamp = record.get("timestamp")

            if ip and user and isinstance(stamp, datetime):
                grouped[ip].append((stamp, user))

    alerts = []

    for ip, events in grouped.items():
        events.sort(key=lambda item: item[0])
        left = 0

        for right, (stamp, _) in enumerate(events):
            while stamp - events[left][0] > timedelta(seconds=window):
                left += 1

            users = {
                user for _, user in events[left:right + 1]
            }

            if len(users) >= threshold:
                alerts.append({
                    "type": "password_spraying",
                    "source_ip": ip,
                    "distinct_usernames": sorted(users),
                    "username_count": len(users),
                    "window_seconds": window,
                    "severity": "High"
                })
                break

    return alerts


def detect_success_after_failures(records, threshold=3, window=600):
    """Detect a successful SSH login after failures for the same IP and username.

    Args:
        records (list): Parsed SSH records.
        threshold (int): Minimum earlier failures required.
        window (int): Look-back window in seconds before success.

    Returns:
        list: Alerts for successful logins preceded by repeated failures.
    """
    if (
        not isinstance(threshold, int)
        or threshold < 1
        or not isinstance(window, (int, float))
        or window <= 0
    ):
        raise ValueError("threshold and window must be positive")

    events = [
        record for record in records
        if (
            record.get("event_type") == "authentication"
            and record.get("source_ip")
            and record.get("username")
            and isinstance(record.get("timestamp"), datetime)
            and record.get("status") in {"failed", "accepted"}
        )
    ]

    events.sort(key=lambda record: record["timestamp"])
    alerts = []

    for index, record in enumerate(events):
        if record["status"] != "accepted":
            continue

        start = record["timestamp"] - timedelta(seconds=window)

        previous_failures = [
            previous for previous in events[:index]
            if (
                previous["status"] == "failed"
                and previous["source_ip"] == record["source_ip"]
                and previous["username"].lower()
                == record["username"].lower()
                and start <= previous["timestamp"] < record["timestamp"]
            )
        ]

        if len(previous_failures) >= threshold:
            alerts.append({
                "type": "success_after_failures",
                "source_ip": record["source_ip"],
                "username": record["username"],
                "failed_attempts": len(previous_failures),
                "window_seconds": window,
                "success_time": record["timestamp"],
                "severity": "High"
            })

    return alerts


def detect_account_changes(records):
    """Flag new accounts and additions to privileged groups.

    Args:
        records (list): Parsed SSH/account-management records.

    Returns:
        list: Account-change security alerts.
    """
    alerts = []

    privileged_groups = {
        "sudo",
        "wheel",
        "admin",
        "administrators"
    }

    for record in records:
        if record.get("event_type") == "account_created":
            alerts.append({
                "type": "account_created",
                "username": record.get("username"),
                "hostname": record.get("hostname"),
                "severity": "High"
            })

        elif (
            record.get("event_type") == "account_modified"
            and (record.get("group") or "").lower() in privileged_groups
        ):
            alerts.append({
                "type": "privileged_group_change",
                "username": record.get("username"),
                "group": record.get("group"),
                "hostname": record.get("hostname"),
                "severity": "Critical"
            })

    return alerts


def validate_ip(ip_text):
    """Validate and classify an IPv4 or IPv6 address.

    Args:
        ip_text (str): IP address text.

    Returns:
        dict: Validity, IP version, and address classification.
    """
    try:
        address = ipaddress.ip_address(str(ip_text).strip())

        private_networks = (
            [
                ipaddress.ip_network("10.0.0.0/8"),
                ipaddress.ip_network("172.16.0.0/12"),
                ipaddress.ip_network("192.168.0.0/16")
            ]
            if address.version == 4
            else [ipaddress.ip_network("fc00::/7")]
        )

        documentation_networks = (
            [
                ipaddress.ip_network("192.0.2.0/24"),
                ipaddress.ip_network("198.51.100.0/24"),
                ipaddress.ip_network("203.0.113.0/24")
            ]
            if address.version == 4
            else [ipaddress.ip_network("2001:db8::/32")]
        )

        if address.is_loopback:
            category = "Loopback"
        elif any(address in net for net in documentation_networks):
            category = "Documentation"
        elif any(address in net for net in private_networks):
            category = "Private"
        elif address.is_global:
            category = "Public"
        elif address.is_reserved:
            category = "Reserved"
        else:
            category = "Other non-global"

        return {
            "ip": str(address),
            "valid": True,
            "version": address.version,
            "classification": category
        }

    except ValueError:
        return {
            "ip": str(ip_text),
            "valid": False,
            "version": None,
            "classification": "Invalid"
        }


def export_report(alerts, summary, output_folder="reports"):
    """Export SSH alerts and summary as JSON and CSV files.

    Args:
        alerts (list): Alert dictionaries.
        summary (dict): Summary information.
        output_folder (str or Path): Output directory.

    Returns:
        dict or None: Output file paths, or None if writing fails.
    """
    try:
        folder = Path(output_folder)
        folder.mkdir(parents=True, exist_ok=True)

        alerts_path = folder / "alerts.json"
        summary_path = folder / "summary.json"
        csv_path = folder / "alerts.csv"

        with alerts_path.open("w", encoding="utf-8") as file:
            json.dump(alerts, file, indent=4, default=str)

        with summary_path.open("w", encoding="utf-8") as file:
            json.dump(summary, file, indent=4, default=str)

        with csv_path.open("w", newline="", encoding="utf-8") as file:
            fields = sorted({
                key for alert in alerts for key in alert
            })

            if not fields:
                fields = ["message"]

            writer = csv.DictWriter(
                file,
                fieldnames=fields,
                extrasaction="ignore"
            )

            writer.writeheader()

            if alerts:
                writer.writerows(alerts)
            else:
                writer.writerow({
                    "message": "No alerts detected"
                })

        return {
            "alerts_json": str(alerts_path),
            "summary_json": str(summary_path),
            "alerts_csv": str(csv_path)
        }

    except (OSError, TypeError, ValueError) as error:
        print(f"Error exporting SSH reports: {error}")
        return None