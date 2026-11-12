CYBR353 Group Project - Log Analyser / Simple IDS
Firewall log module (firewallAnalyzer.py)
=================================================

This project consists of two modules:
- SSH log module (ssh_analyzer.py): analyzes SSH authentication events and detect suspicios login activities and account changes.
- Firewall log module (firewallAnalyzer.py) - analyzes Window Firewall logs and detects suspicious network activities.


REQUIREMENTS
------------
- Python 3.9 or later
- Internet access is optional (only used for AbuseIPDB lookups)

SETUP
-----
1. (Optional) create a virtual environment:
       python -m venv venv
       venv\Scripts\activate        (Windows)
       source venv/bin/activate     (Linux / macOS)
2. Install the dependency:
       pip install -r requirements.txt

FILES
-----
SSH Module:
ssh_analyzer.py                 SSH module: log parsing, failed login counting, brute-force                                         detection, password spraying detection, successful login after                                      failures, account change detection, IP validation, and JSON/CSV                                     report generation.
sample_log/sample_auth1.log     Linux SSH authentication log containing normal and simulated                                        suspicious activities.

Firewall Module:
firewallAnalyzer.py             Firewall module: file hashing, integrity check,
                                log parsing, spike and port-scan detection,
                                IP reputation lookup, JSON report export
demo.py                         Runs every function on the sample logs
test_firewall.py                Short checks for edge cases (prints PASS/FAIL)
requirements.txt                Third-party dependency (requests)
sample_logs/pfirewall.log       Windows Firewall log (normal traffic)
sample_logs/firewall_attack.log Synthetic log with simulated attacks


HOW TO RUN
----------
From this folder:
    python demo.py              Full demonstration
    python test_firewall.py     Edge-case checks

The demo runs both anaylzers and generates these reports:
- reports/: SSH analysis results (alerts.json, summary.json, and alerts.csv)
- Firewall_report.json: (the alerts it found).

OPTIONAL: IP REPUTATION (AbuseIPDB)
-----------------------------------
check_ip_reputation() needs a free AbuseIPDB API key in an environment
variable. Without a key the lookup is skipped and everything else still runs.
    Windows PowerShell:   $env:ABUSEIPDB_API_KEY="your-key"
    Windows cmd:          set ABUSEIPDB_API_KEY=your-key
    Linux / macOS:        export ABUSEIPDB_API_KEY="your-key"
Never put the key inside the code.

EXPECTED DEMO RESULT
--------------------
SSH Analyzer
- sample_auth1.log: SSH log entries are parsed, and suspicious activities are detected.
- The analyzer identifies brute-force attempts, suspicious usernames, password spraying, successful   logins after many repeated failures, and account changes.
- SSH reports are saved in the reports folder as JSON and CSV files.

Firewall Analyzer
- pfirewall.log: all entries parsed, 0 alerts, hash unchanged after analysis
- firewall_attack.log: 2 alerts (blocked-traffic spike from 203.0.113.50,
  port scan from 203.0.113.77); malformed lines are skipped
- A wrong hash is rejected, a missing file returns None, and the report is
  saved to firewall_report.json

NOTES
-----
- The SSH attack log contains simulated authentication events and account-management activities.
- The SSH parser uses 2026 as the default year because Linux syslog timestamps don't include a year.
- SSH detection thresholds can be adjusted through the function parameters in the ssh_analyzer.py
- The SSH and Firewall attack log are synthetic. They use 203.0.113.x, an address range
  reserved for documentation.
- Firewall detection settings are constants at the top of LogAnalyzer.py:
  20 blocked packets in 60 seconds, and 10 different ports in 60 seconds.
