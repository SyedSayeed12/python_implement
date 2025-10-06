# !/usr/bin/env python3
"""
Server Log Security Analyzer

Features:
- Parse Apache/Nginx common logs and simple system auth logs.
- Detect suspicious patterns:
  * Repeated failed login attempts (brute-force)
  * Access to restricted URLs (e.g., /admin, /wp-admin, /phpmyadmin)
  * Unusual IP activity (high request rate, many distinct URLs)
- Generate JSON/CSV report listing incidents with timestamps, IPs, and suspected attack types.
- Optional threat intelligence enrichment using AbuseIPDB (requires API key).

Usage examples:
    python server_log_security_analyzer.py --files access.log auth.log --output report.json
    python server_log_security_analyzer.py --files access.log --threat-intel-key YOUR_KEY --output report.csv
    python server_log_security_analyzer.py --run-tests   # run built-in unit-style tests

Note: This is a single-file starter tool. You may extend parsers and detections to fit your environment.

This file was updated to fix a SyntaxError where `HIGH_RATE_THRESHOLD` and
`FAILED_LOGIN_THRESHOLD` were assigned after a `global` declaration that came
later in `main()`. The fix moves the `global` declaration to the top of
`main()` so the names are not used prior to the global statement.
"""

import re
import argparse
import json
import csv
import sys
import tempfile
import os
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Optional, Dict, Any

try:
    import requests
except Exception:
    requests = None

# ----------------------------- Configuration -----------------------------
FAILED_LOGIN_WINDOW = timedelta(minutes=5)
FAILED_LOGIN_THRESHOLD = 5
HIGH_RATE_WINDOW = timedelta(minutes=1)
HIGH_RATE_THRESHOLD = 100  # requests per minute
RESTRICTED_PATHS = [
    r"/admin",
    r"/wp-admin",
    r"/phpmyadmin",
    r"/\.env",
    r"/config",
]

# Regex for Apache/Nginx combined log format (common variants) - captures ip, time, request
APACHE_COMMON_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<request>[A-Z]+\s+[^\s]+[^\"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
)
# Example time format: 10/Oct/2000:13:55:36 -0700
APACHE_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"


# Simple syslog parser for auth logs
SYSLOG_RE = re.compile(r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<rest>.+)$")
SYSLOG_MONTHS = {m: i for i, m in enumerate(['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'], start=1)}

# Patterns for failed login messages (common in OpenSSH and sudo)
FAILED_LOGIN_PATTERNS = [
    re.compile(r'Failed password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'),
    re.compile(r'authentication failure; .* rhost=(?P<ip>\d+\.\d+\.\d+\.\d+)'),
    re.compile(r'Failed login for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)'),
]

# ----------------------------- Utilities -----------------------------

def parse_apache_line(line: str):
    m = APACHE_COMMON_RE.search(line)
    if not m:
        return None
    d = m.groupdict()
    ip = d['ip']
    req = d['request']
    status = int(d['status'])
    time_str = d['time']
    try:
        timestamp = datetime.strptime(time_str, APACHE_TIME_FMT)
    except Exception:
        # Try without timezone
        try:
            timestamp = datetime.strptime(time_str.split()[0], "%d/%b/%Y:%H:%M:%S")
        except Exception:
            timestamp = None
    # request like: GET /index.html HTTP/1.1
    parts = req.split()
    method = parts[0] if parts else None
    path = parts[1] if len(parts) > 1 else None
    return {'ip': ip, 'timestamp': timestamp, 'method': method, 'path': path, 'status': status, 'raw': line}


def parse_syslog_line(line: str, year: Optional[int] = None):
    m = SYSLOG_RE.match(line)
    if not m:
        return None
    gd = m.groupdict()
    mon = SYSLOG_MONTHS.get(gd['month'], 0)
    day = int(gd['day'])
    t = gd['time']
    if year is None:
        year = datetime.now().year
    dt_str = f"{year}-{mon:02d}-{day:02d} {t}"
    try:
        timestamp = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
    except Exception:
        timestamp = None
    rest = gd['rest']
    # try to extract IP from known patterns
    for pat in FAILED_LOGIN_PATTERNS:
        mm = pat.search(rest)
        if mm:
            ip = mm.groupdict().get('ip')
            return {'ip': ip, 'timestamp': timestamp, 'message': rest, 'raw': line}
    # fallback: return message without ip
    return {'ip': None, 'timestamp': timestamp, 'message': rest, 'raw': line}

# ----------------------------- Analyzer -----------------------------

class LogAnalyzer:
    def __init__(self, threat_intel_key: Optional[str] = None):
        self.entries = []  # list of dicts: ip, timestamp, path, status, raw
        self.failed_login_events = defaultdict(list)  # ip -> list[timestamp]
        self.request_counters = defaultdict(list)  # ip -> list[timestamp]
        self.ip_paths = defaultdict(set)
        self.incidents = []
        self.threat_intel_key = threat_intel_key

    def add_entry(self, entry: Dict[str,Any]):
        # normalize timestamp to naive UTC when possible — keep as-is otherwise
        self.entries.append(entry)
        ip = entry.get('ip')
        ts = entry.get('timestamp')
        if ip and ts:
            self.request_counters[ip].append(ts)
            path = entry.get('path') or entry.get('message')
            if path:
                self.ip_paths[ip].add(path)

        # detect immediate failed-login pattern from syslog-style entries
        msg = entry.get('message') or entry.get('raw','')
        for pat in FAILED_LOGIN_PATTERNS:
            m = pat.search(msg)
            if m:
                ip_detect = m.groupdict().get('ip')
                if ip_detect:
                    ts = entry.get('timestamp') or datetime.now()
                    self.failed_login_events[ip_detect].append(ts)

    def detect_bruteforce(self):
        for ip, times in list(self.failed_login_events.items()):
            times_sorted = sorted(times)
            # sliding window
            start = 0
            for i in range(len(times_sorted)):
                while times_sorted[i] - times_sorted[start] > FAILED_LOGIN_WINDOW:
                    start += 1
                window_size = i - start + 1
                if window_size >= FAILED_LOGIN_THRESHOLD:
                    incident = {
                        'type': 'brute_force_failed_logins',
                        'ip': ip,
                        'count': window_size,
                        'first_seen': times_sorted[start].isoformat(),
                        'last_seen': times_sorted[i].isoformat(),
                    }
                    self.incidents.append(incident)
                    break

    def detect_restricted_access(self):
        for e in self.entries:
            path = e.get('path')
            if not path:
                continue
            for pat in RESTRICTED_PATHS:
                if re.search(pat, path, re.IGNORECASE):
                    incident = {
                        'type': 'restricted_path_access',
                        'ip': e.get('ip'),
                        'path': path,
                        'timestamp': e.get('timestamp').isoformat() if e.get('timestamp') else None,
                        'raw': e.get('raw')
                    }
                    self.incidents.append(incident)
    def detect_high_request_rate(self):
        for ip, times in self.request_counters.items():
            times_sorted = sorted(times)
            start = 0
            for i in range(len(times_sorted)):
                while times_sorted[i] - times_sorted[start] > HIGH_RATE_WINDOW:
                    start += 1
                window_size = i - start + 1
                if window_size >= HIGH_RATE_THRESHOLD:
                    incident = {
                        'type': 'high_request_rate',
                        'ip': ip,
                        'count_per_minute': window_size,
                        'first_seen': times_sorted[start].isoformat(),
                        'last_seen': times_sorted[i].isoformat(),
                    }
                    self.incidents.append(incident)
                    break

    def detect_many_paths(self, threshold: int = 50):
        for ip, paths in self.ip_paths.items():
            if len(paths) >= threshold:
                incident = {
                    'type': 'many_distinct_paths',
                    'ip': ip,
                    'distinct_paths': len(paths),
                    'sample_paths': list(paths)[:10]
                }
                self.incidents.append(incident)

    def analyze(self):
        # run all detectors
        self.detect_bruteforce()
        self.detect_restricted_access()
        self.detect_high_request_rate()
        self.detect_many_paths()

        # enrich with threat intel if available
        if self.threat_intel_key and requests:
            seen_ips = {inc['ip'] for inc in self.incidents if inc.get('ip')}
            for ip in seen_ips:
                info = self.enrich_ip_with_abuseipdb(ip)
                if info:
                    for inc in self.incidents:
                        if inc.get('ip') == ip:
                            inc['threat_intel'] = info

    # ----------------------------- Threat intelligence -----------------------------
    def enrich_ip_with_abuseipdb(self, ip: str) -> Optional[Dict[str,Any]]:
        """
        Uses AbuseIPDB lookup (https://www.abuseipdb.com/). Requires an API key.
        If you prefer another service, adapt this method.
        """
        if not self.threat_intel_key:
            return None
        if not requests:
            return {'error': 'requests library not available in runtime'}
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {
            'Accept': 'application/json',
            'Key': self.threat_intel_key
        }
        params = {'ipAddress': ip}
        try:
            r = requests.get(url, headers=headers, params=params, timeout=10)
            if r.status_code == 200:
                data = r.json().get('data')
                return {
                    'abuseConfidenceScore': data.get('abuseConfidenceScore'),
                    'countryCode': data.get('countryCode'),
                    'lastReportedAt': data.get('lastReportedAt'),
                    'domain': data.get('domain'),
                }
            else:
                return {'error': f'HTTP {r.status_code}'}
        except Exception as ex:
            return {'error': str(ex)}

    # ----------------------------- Reporting -----------------------------
    def save_report_json(self, path: str):
        with open(path, 'w', encoding='utf-8') as f:
            json.dump({'generated_at': datetime.utcnow().isoformat(), 'incidents': self.incidents}, f, indent=2)

    def save_report_csv(self, path: str):
        if not self.incidents:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                f.write(' ')
            return
        keys = set()
        for inc in self.incidents:
            keys.update(inc.keys())
        keys = sorted(keys)
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            for inc in self.incidents:
                writer.writerow({k: json.dumps(v) if isinstance(v, (dict, list)) else v for k, v in inc.items()})

# ----------------------------- Log file reading -----------------------------

def process_file(filename: str, analyzer: LogAnalyzer):
    # try to guess format by filename or content
    is_access_like = any(x in filename.lower() for x in ['access', 'http', 'nginx', 'apache'])
    is_auth_like = any(x in filename.lower() for x in ['auth', 'secure', 'messages'])
    with open(filename, 'r', errors='ignore') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            entry = None
            if is_access_like:
                entry = parse_apache_line(line)
            if not entry and is_auth_like:
                entry = parse_syslog_line(line)
            if not entry:
                # try both fallbacks
                entry = parse_apache_line(line) or parse_syslog_line(line)
            if entry:
                analyzer.add_entry(entry)

# ----------------------------- CLI -----------------------------

def run_tests():
    """Run a small suite of checks on the analyzer functionality.

    The tests are intentionally simple and don't require external files or
    network access. They modify thresholds temporarily to validate
    detection logic.
    """
    print("Running built-in tests...")
    failures = []

    # --- Brute force detection test ---
    a = LogAnalyzer()
    ip = '10.0.0.1'
    now = datetime.now()
    a.failed_login_events[ip] = [now, now + timedelta(seconds=10), now + timedelta(seconds=20)]
    global FAILED_LOGIN_THRESHOLD
    old_failed = FAILED_LOGIN_THRESHOLD
    FAILED_LOGIN_THRESHOLD = 3
    a.detect_bruteforce()
    if not any(inc['type'] == 'brute_force_failed_logins' and inc['ip'] == ip for inc in a.incidents):
        failures.append('brute_force_detection')
    # restore
    FAILED_LOGIN_THRESHOLD = old_failed

    # --- Restricted path detection test ---
    b = LogAnalyzer()
    b.entries.append({'ip': '1.2.3.4', 'path': '/admin/login', 'timestamp': now, 'raw': 'GET /admin/login HTTP/1.1'})
    b.detect_restricted_access()
    if not any(inc['type'] == 'restricted_path_access' and inc['ip'] == '1.2.3.4' for inc in b.incidents):
        failures.append('restricted_path_detection')

    # --- High request rate detection test ---
    c = LogAnalyzer()
    ip2 = '2.2.2.2'
    c.request_counters[ip2] = [now + timedelta(seconds=i) for i in range(6)]
    global HIGH_RATE_THRESHOLD
    old_rate = HIGH_RATE_THRESHOLD
    HIGH_RATE_THRESHOLD = 5
    c.detect_high_request_rate()
    if not any(inc['type'] == 'high_request_rate' and inc['ip'] == ip2 for inc in c.incidents):
        failures.append('high_request_rate_detection')
    HIGH_RATE_THRESHOLD = old_rate

    # --- Many distinct paths detection test ---
    d = LogAnalyzer()
    ip3 = '3.3.3.3'
    d.ip_paths[ip3] = set([f'/path{i}' for i in range(5)])
    d.detect_many_paths(threshold=4)
    if not any(inc['type'] == 'many_distinct_paths' and inc['ip'] == ip3 for inc in d.incidents):
        failures.append('many_distinct_paths_detection')

    if failures:
        print("FAILURES:", failures)
        print("One or more tests failed.")
        sys.exit(1)
    else:
        print("All built-in tests passed.")
        sys.exit(0)


def main(argv=None):
    # Important: declare globals before using them in defaults or assignment
    global HIGH_RATE_THRESHOLD, FAILED_LOGIN_THRESHOLD

    p = argparse.ArgumentParser(description='Server log security analyzer')
    p.add_argument('--files', '-f', nargs='+', help='Log files to analyze')
    p.add_argument('--output', '-o', help='Output report path (.json or .csv)')
    p.add_argument('--threat-intel-key', '-t', help='AbuseIPDB API key (optional)')
    p.add_argument('--high-rate-threshold', type=int, default=HIGH_RATE_THRESHOLD, help='Requests/minute threshold')
    p.add_argument('--failed-login-threshold', type=int, default=FAILED_LOGIN_THRESHOLD, help='Failed logins threshold')
    p.add_argument('--debug', action='store_true')
    p.add_argument('--run-tests', action='store_true', help='Run built-in tests and exit')

    args = p.parse_args(argv)

    if args.run_tests:
        run_tests()

    # ensure required args present when not running tests
    if not args.files or not args.output:
        p.error('--files and --output are required unless --run-tests is used')

    # apply thresholds from CLI
    HIGH_RATE_THRESHOLD = args.high_rate_threshold
    FAILED_LOGIN_THRESHOLD = args.failed_login_threshold

    analyzer = LogAnalyzer(threat_intel_key=args.threat_intel_key)

    for fname in args.files:
        try:
            process_file(fname, analyzer)
        except FileNotFoundError:
            print(f"File not found: {fname}", file=sys.stderr)

    analyzer.analyze()

    out = args.output
    if out.endswith('.json'):
        analyzer.save_report_json(out)
        print(f"Report saved to {out}")
    elif out.endswith('.csv'):
        analyzer.save_report_csv(out)
        print(f"Report saved to {out}")
    else:
        # default to json
        analyzer.save_report_json(out)
        print(f"Report saved to {out} (json)")


# run_tests()
if __name__ == '__main__':
    main()

