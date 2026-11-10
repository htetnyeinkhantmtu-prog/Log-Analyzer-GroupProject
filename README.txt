CYBR353 Group Project - Log Analyser / Simple IDS
Firewall log module (firewallAnalyzer.py)
=================================================

This README covers the Windows Firewall part of the project.
[Person A: add the SSH log module instructions here.]

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
firewallAnalyzer.py                  Firewall module: file hashing, integrity check,
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

The demo writes firewall_report.json (the alerts it found).

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
- pfirewall.log: all entries parsed, 0 alerts, hash unchanged after analysis
- firewall_attack.log: 2 alerts (blocked-traffic spike from 203.0.113.50,
  port scan from 203.0.113.77); malformed lines are skipped
- A wrong hash is rejected, a missing file returns None, and the report is
  saved to firewall_report.json

NOTES
-----
- The attack log is synthetic. It uses 203.0.113.x, an address range
  reserved for documentation.
- Detection settings are constants at the top of LogAnalyzer.py:
  20 blocked packets in 60 seconds, and 10 different ports in 60 seconds.
