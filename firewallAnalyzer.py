import hashlib
import ipaddress
import json
import os
from datetime import datetime, timedelta

import requests

CHUNK_SIZE = 4096  # Size of each chunk to read from the file


def compute_file_hash(file_path):
    """
    Computes the SHA-256 hash of a file.

    Args:
        file_path (str): The path to the file.

    Returns:
        str: The SHA-256 hash in hexadecimal format, or None if the
            file cannot be read.
    """

    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            # Read and update hash value in blocks of CHUNK_SIZE
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                sha256_hash.update(chunk)
    except FileNotFoundError:
        print("Log file not found. Please check the file path.")
        return None
    except PermissionError:
        print("Permission denied. Please check your access rights to the log file.")
        return None
    return sha256_hash.hexdigest()


EXPECTED_FIELDS = 18  # Windows Firewall entries have 18 fields


def parse_firewall_line(line):
    """
    Parses one firewall log line and extracts the relevant information.

    Args:
        line (str): A single line from the firewall log.

    Returns:
        dict: A dictionary containing extracted information, or None if
            the line cannot be parsed.
    """

    # Skip blank lines and header lines that start with "#"
    if not line.strip() or line.strip().startswith("#"):
        return None

    # split() with no argument also removes "\r\n" and leading spaces
    parts = line.split()
    if len(parts) != EXPECTED_FIELDS:
        return None

    timestamp = parts[0] + " " + parts[1]
    action = parts[2]
    protocol = parts[3]
    src_ip = parts[4]
    dst_ip = parts[5]

    try:
        src_port = int(parts[6]) if parts[6] != '-' else None
        dst_port = int(parts[7]) if parts[7] != '-' else None
    except ValueError:
        return None

    return {
            "source": "Windows Firewall",
            "timestamp": timestamp,
            "action": action,
            "protocol": protocol,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "path": parts[16],  # SEND or RECEIVE (direction of traffic)
        }


def load_firewall_log(file_path):
    """
    Loads and parses a Windows Firewall log file.

    Args:
        file_path (str): The path to the firewall log file.

    Returns:
        list: A list of dictionaries containing parsed log entries, or None
            if the file cannot be read.
    """
    log_entries = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                parsed_entry = parse_firewall_line(line)
                if parsed_entry:
                    log_entries.append(parsed_entry)
        return log_entries

    except FileNotFoundError:
        print("Log file not found. Please check the file path.")
        return None
    except PermissionError:
        print("Permission denied. Please check your access rights "
              "to the log file.")
        return None


def verify_log_integrity(file_path, expected_hash):
    """
    Verifies the integrity of a log file by comparing its SHA-256 hash with an expected hash.

    Args:
        file_path (str): The path to the log file.
        expected_hash (str): The expected SHA-256 hash in hexadecimal format.

    Returns:
        bool: True if the hashes match; False if they differ, the file
            cannot be read, or expected_hash is invalid.
    """
    if not isinstance(expected_hash, str) or not expected_hash.strip():
        print("Invalid input: expected_hash must be a string.")
        return False
    computed_hash = compute_file_hash(file_path)
    if computed_hash is None:
        return False
    return computed_hash == expected_hash.strip().lower()


DROP_THRESHOLD = 20  # blocked packets from one IP that count as suspicious
TIME_WINDOW_SECONDS = 60  # ...if they happen within this many seconds
PORT_SCAN_THRESHOLD = 10  # distinct ports from one IP that count as a scan
TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"

#AI assisted
def is_noise_destination(dest_ip):
    """
    Determines if the given destination address is multicast, broadcast,
    or a known noise destination.

    Args:
        dest_ip (str): The destination IP address from a log entry.

    Returns:
        bool: True if the destination is multicast or broadcast, False
            otherwise (including values that are not valid IPs).
    """
    if dest_ip == "255.255.255.255" or dest_ip.endswith(".255"):
        return True
    try:
        return ipaddress.ip_address(dest_ip).is_multicast
    except ValueError:
        return False


def detect_blocked_spikes(log_entries, drop_threshold=DROP_THRESHOLD):
    """
    Detects source IPs with many blocked inbound packets in a short time.

    Args:
        log_entries (list): Parsed log entries (dicts from parse_firewall_line).
        drop_threshold (int): The number of blocked packets within the time window that triggers an alert.

    Returns:
        list: One alert dict per suspicious source IP (empty if none),
            or None if log_entries is not a list.
    """
    if not isinstance(log_entries, list):
        return None

    drops_by_ip = {}
    for log_entry in log_entries:
        if log_entry.get("source") != "Windows Firewall":
            continue  # Skip entries that are not from Windows Firewall
        if log_entry["action"] != "DROP" or log_entry["path"] != "RECEIVE":
            continue  # Only consider blocked inbound packets
        if is_noise_destination(log_entry["dst_ip"]):
            continue  # Skip noise destinations
        try:
            droptime = datetime.strptime(
                log_entry["timestamp"], TIMESTAMP_FORMAT
            )
        except ValueError:
            continue  # Skip entries with invalid timestamps
        drops_by_ip.setdefault(log_entry["src_ip"], []).append(droptime)

    # AI-assisted: sliding-window technique
    window = timedelta(seconds=TIME_WINDOW_SECONDS)
    alerts = []
    for src_ip, times in drops_by_ip.items():
        times.sort()
        start = 0
        best_count = 0
        first_seen = last_seen = None
        for end in range(len(times)):
            # Move the window start forward until it is at most 60s wide
            while times[end] - times[start] > window:
                start += 1
            count = end - start + 1
            if count > best_count:
                best_count = count
                first_seen, last_seen = times[start], times[end]

        if best_count >= drop_threshold:
            severity = "high" if best_count >= drop_threshold * 3 else "medium"
            alerts.append({
                "source": "firewall",
                "type": "blocked_traffic_spike",
                "severity": severity,
                "src_ip": src_ip,
                "count": best_count,
                "first_seen": first_seen.strftime(TIMESTAMP_FORMAT),
                "last_seen": last_seen.strftime(TIMESTAMP_FORMAT),
                "details": f"{best_count} blocked inbound packets within "
                           f"{TIME_WINDOW_SECONDS} seconds",
            })
    return alerts


def detect_port_scan(log_entries, port_scan_threshold=PORT_SCAN_THRESHOLD):
    """
    Detects source IPs that have attempted connections to
    many different destination ports within a short time window.

    Args:
        log_entries (list): Parsed log entries (dicts from parse_firewall_line).
        port_scan_threshold (int): The number of unique destination ports
            within the time window that triggers an alert.

    Returns:
        list: One alert dict per suspicious source IP (empty if none),
            or None if log_entries is not a list.
    """
    if not isinstance(log_entries, list):
        return None

    events_by_ip = {}
    for log_entry in log_entries:
        if log_entry.get("source") != "Windows Firewall":
            continue  # Skip entries that are not from Windows Firewall
        if log_entry["action"] != "DROP" or log_entry["path"] != "RECEIVE":
            continue  # Only consider blocked inbound packets
        if is_noise_destination(log_entry["dst_ip"]):
            continue  # Skip noise destinations
        if log_entry["dst_port"] is None:
            continue  # Skip entries without a port (e.g. ICMP)
        try:
            event_time = datetime.strptime(
                log_entry["timestamp"], TIMESTAMP_FORMAT
            )
        except ValueError:
            continue
        events_by_ip.setdefault(log_entry["src_ip"], []).append(
            (event_time, log_entry["dst_port"])
        )

    # AI-assisted: nested-loop window search
    window = timedelta(seconds=TIME_WINDOW_SECONDS)
    alerts = []
    for src_ip, events in events_by_ip.items():
        events.sort()  # oldest first
        best_ports = set()
        first_seen = last_seen = None
        for i, (start_time, _) in enumerate(events):
            ports_in_window = set()  # a set ignores repeated ports
            end_time = start_time
            for event_time, port in events[i:]:
                if event_time - start_time > window:
                    break  # past the window, stop looking
                ports_in_window.add(port)
                end_time = event_time
            if len(ports_in_window) > len(best_ports):
                best_ports = ports_in_window
                first_seen, last_seen = start_time, end_time

        unique_ports_count = len(best_ports)
        if unique_ports_count >= port_scan_threshold:
            high_level = port_scan_threshold * 3
            severity = "high" if unique_ports_count >= high_level else "medium"
            alerts.append({
                "source": "firewall",
                "type": "port_scan",
                "severity": severity,
                "src_ip": src_ip,
                "count": unique_ports_count,
                "first_seen": first_seen.strftime(TIMESTAMP_FORMAT),
                "last_seen": last_seen.strftime(TIMESTAMP_FORMAT),
                "details": f"{unique_ports_count} unique destination ports "
                           f"blocked within {TIME_WINDOW_SECONDS} seconds: "
                           f"{sorted(best_ports)}",
            })
    return alerts

# AI-assisted: AbuseIPDB integration

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
REQUEST_TIMEOUT = 5  # seconds


def check_ip_reputation(ip_address):
    """
    Looks up an IP address on AbuseIPDB and returns its abuse score.

    Args:
        ip_address (str): The IP address to check.

    Returns:
        int: Abuse confidence score from 0 (clean) to 100 (very abusive),
            or None if no API key is set or the lookup fails.
    """

    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        print("No API key set (ABUSEIPDB_API_KEY). Skipping reputation check.")
        return None

    try:
        response = requests.get(
            ABUSEIPDB_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip_address, "maxAgeInDays": 90},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        return response.json()["data"]["abuseConfidenceScore"]
    except (requests.exceptions.RequestException, ValueError, KeyError):
        print(f"Reputation lookup failed for {ip_address}.")
        return None

#AI-assisted: export report to JSON
def export_firewall_report(alerts, output_path="firewall_report.json"):
    """
    Saves the firewall alerts to a JSON file.

    Args:
        alerts (list): Alert dicts from the detector functions.
        output_path (str): Where to save the report.

    Returns:
        bool: True if the report was saved, False otherwise.
    """
    if not isinstance(alerts, list):
        print("Invalid input: alerts must be a list.")
        return False

    report = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_alerts": len(alerts),
        "alerts": alerts,
    }

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4)
    except (OSError, TypeError):
        print(f"Could not save the report to {output_path}.")
        return False
    return True
