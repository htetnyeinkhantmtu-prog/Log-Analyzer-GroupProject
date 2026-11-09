"""
Demo script for the firewall log analyser.

Runs the firewall functions on a normal log and on a log that contains simulated attacks. 
parse_firewall_line() and is_noise_destination() run indirectly, through load_firewall_log() and the detectors.

"""
from firewallAnalyzer import (
    check_ip_reputation,
    compute_file_hash,
    detect_blocked_spikes,
    detect_port_scan,
    export_firewall_report,
    load_firewall_log,
    verify_log_integrity,
)

NORMAL_LOG = "sample_logs/pfirewall.log"
ATTACK_LOG = "sample_logs/firewall_attack.log"
REPORT_FILE = "firewall_report.json"


def analyse_log(log_path):
    """
    Runs the integrity check, loading and both detectors on one log file.

    Args:
        log_path (str): The path to the firewall log file.

    Returns:
        list: The alerts found (empty if none, or if the file cannot be read).
    """
    print(f"\n=== {log_path} ===")

    original_hash = compute_file_hash(log_path)
    if original_hash is None:
        return []
    print(f"SHA-256 before analysis: {original_hash}")

    entries = load_firewall_log(log_path)
    if entries is None:
        return []
    print(f"Parsed entries: {len(entries)}")

    alerts = detect_blocked_spikes(entries) + detect_port_scan(entries)
    print(f"Alerts found: {len(alerts)}")
    for alert in alerts:
        print(f"  [{alert['severity']}] {alert['type']} "
              f"from {alert['src_ip']}: {alert['details']}")

    unchanged = verify_log_integrity(log_path, original_hash)
    print(f"Log unchanged after analysis: {unchanged}")
    return alerts


def main():
    """Runs the full firewall demo."""
    # Person A: add the SSH log demo here

    all_alerts = []
    for log_path in (NORMAL_LOG, ATTACK_LOG):
        all_alerts += analyse_log(log_path)

    print("\n=== Tamper check (wrong hash) ===")
    print("Hash accepted:", verify_log_integrity(ATTACK_LOG, "0" * 64))

    print("\n=== Error handling (missing file) ===")
    print("Result:", load_firewall_log("sample_logs/does_not_exist.log"))

    print("\n=== IP reputation (needs ABUSEIPDB_API_KEY) ===")
    for ip in sorted({alert["src_ip"] for alert in all_alerts}):
        print(ip, "->", check_ip_reputation(ip))

    print("\n=== Export ===")
    if export_firewall_report(all_alerts, REPORT_FILE):
        print(f"Report saved to {REPORT_FILE}")


if __name__ == "__main__":
    main()
