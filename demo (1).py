"""
CYBR 353 Log Analyzer
Demo script the combined SSH and Firewall demo.

"""

from pathlib import Path
import ssh_analyzer

from firewallAnalyzer import (
    check_ip_reputation,
    compute_file_hash,
    detect_blocked_spikes,
    detect_port_scan,
    export_firewall_report,
    load_firewall_log,
    verify_log_integrity,
)


# ==================================================
# SSH LOG ANALYZER
# ==================================================

def run_ssh_demo():

    # Locate the sample SSH log
    ROOT = Path(__file__).resolve().parent
    LOG_PATH = ROOT / "sample_log" / "sample_auth1.log"

    print("Looking for file:", LOG_PATH)
    print("File exists:", LOG_PATH.exists())

    # Load SSH records
    records = ssh_analyzer.load_ssh_log(LOG_PATH)

    print("\n========== SSH LOG ANALYZER ==========")
    print("Total parsed records:", len(records))

    if not records:
        print("No records were loaded. Check the log file and format.")
        return

    # Count failed logins
    summary = ssh_analyzer.count_failed_logins(records)

    print("\n========== FAILED LOGIN SUMMARY ==========")

    print("\nFailed logins by IP:")
    for ip, count in sorted(
        summary["by_ip"].items(),
        key=lambda item: item[1],
        reverse=True
    ):
        print(f"{ip}: {count}")

    print("\nFailed logins by username:")
    for username, count in sorted(
        summary["by_user"].items(),
        key=lambda item: item[1],
        reverse=True
    ):
        print(f"{username}: {count}")

    # Detect brute-force activity
    brute_alerts = ssh_analyzer.detect_ssh_brute_force(records)

    print("\n========== BRUTE-FORCE DETECTION ==========")
    for alert in brute_alerts:
        print(alert)

    if not brute_alerts:
        print("No brute-force activity detected.")

    # Detect suspicious usernames
    user_alerts = ssh_analyzer.detect_suspicious_users(records)

    print("\n========== SUSPICIOUS USER DETECTION ==========")
    print("Total suspicious username events:", len(user_alerts))

    for alert in user_alerts[:10]:
        print(alert)

    if len(user_alerts) > 10:
        print(f"... and {len(user_alerts) - 10} more alerts.")

    if not user_alerts:
        print("No suspicious usernames detected.")

    # Detect password spraying
    spray_alerts = ssh_analyzer.detect_password_spraying(records)

    print("\n========== PASSWORD SPRAYING DETECTION ==========")
    for alert in spray_alerts:
        print(alert)

    if not spray_alerts:
        print("No password spraying detected.")

    # Detect successful login after failures
    success_alerts = ssh_analyzer.detect_success_after_failures(records)

    print("\n========== SUCCESS AFTER FAILURES ==========")
    for alert in success_alerts:
        print(alert)

    if not success_alerts:
        print("No matching successful logins detected.")

    # Detect account changes
    account_alerts = ssh_analyzer.detect_account_changes(records)

    print("\n========== ACCOUNT CHANGE DETECTION ==========")
    for alert in account_alerts:
        print(alert)

    if not account_alerts:
        print("No account changes detected.")

    # Validate an IP address
    print("\n========== IP VALIDATION ==========")
    print(ssh_analyzer.validate_ip("203.0.113.77"))

    # Export all alerts
    all_alerts = (
        brute_alerts
        + user_alerts
        + spray_alerts
        + success_alerts
        + account_alerts
    )

    report_files = ssh_analyzer.export_report(all_alerts, summary)

    print("\n========== REPORTS GENERATED ==========")

    if report_files:
        for report_name, file_path in report_files.items():
            print(f"{report_name}: {file_path}")
    else:
        print("Report generation failed. Check the output folder permissions.")

    print("\n========== ANALYSIS COMPLETE ==========")

    # Check which lines were skipped
    with open(LOG_PATH, "r", encoding="utf-8") as file:
        lines = file.readlines()

    print("\n========== LOG FILE CHECK ==========")
    print("Total lines:", len(lines))
    print("Parsed records:", len(records))
    print("Skipped lines:", len(lines) - len(records))

    for line_number, line in enumerate(lines, start=1):
        if ssh_analyzer.parse_ssh_line(line) is None:
            print(f"Skipped line {line_number}: {line.strip()}")


# ==================================================
# FIREWALL LOG ANALYZER
# ==================================================

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


def run_firewall_demo():
    """Runs the full firewall demo."""

    all_alerts = []
    for log_path in (NORMAL_LOG, ATTACK_LOG):
        all_alerts += analyse_log(log_path)

    print("\n=== Tamper check (wrong hash) ===")
    print("Hash accepted:", verify_log_integrity(ATTACK_LOG, "0" * 64))

    print("\n=== Error handling (missing file) ===")
    print("Loading a file that does not exist on purpose...")
    print("Result:", load_firewall_log("sample_logs/does_not_exist.log"))

    print("\n=== IP reputation (needs ABUSEIPDB_API_KEY) ===")
    for ip in sorted({alert["src_ip"] for alert in all_alerts}):
        print(ip, "->", check_ip_reputation(ip))

    print("\n=== Export ===")
    if export_firewall_report(all_alerts, REPORT_FILE):
        print(f"Report saved to {REPORT_FILE}")


# ==================================================
# MAIN DEMO
# ==================================================

def main():
    run_ssh_demo()
    run_firewall_demo()


if __name__ == "__main__":
    main()
