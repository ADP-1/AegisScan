from venv import logger
import requests
from bs4 import BeautifulSoup
import subprocess
from datetime import datetime
import time
import json
import re

from utils.progress import ProgressHandler

class SQLiScanner:
    def __init__(self, target_url, progress_handler, depth=3):
        self.target_url = target_url
        self.depth = depth
        self.start_time = None
        self.end_time = None
        self.progress_handler = progress_handler
        self.process = None
        
    def run_scan(self):
        self.start_time = datetime.now()
        cmd = [
            "sqlmap", 
            "-u", self.target_url,
            "--batch",
            "--level", str(self.depth),
            "--output-dir=./reports",
            "--flush-session"
        ]
        
        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        # Stream output in real-time
        while True:
            output = self.process.stdout.readline()
            if not output and self.process.poll() is not None:
                break
            if output:
                self._parse_sqlmap_output(output.strip())
        
        self.end_time = datetime.now()
        self.progress_handler.update_progress(100)  # Force completion
        return self._parse_results()

    def _parse_sqlmap_output(self, line):
        # Match patterns like: 
        # [INFO] tested 45% of payloads
        # [INFO] completed 60% of requests
        match = re.search(r'(tested|completed).*?(\d+)%', line)
        if match:
            try:
                self.progress_handler.update_progress(int(match.group(2)))
            except ValueError:
                pass

    def _parse_results(self):
        try:
            with open('./reports/output.json') as f:
                sqlmap_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error(f"Error parsing SQLMap results: {str(e)}")
            return {"error": "Failed to parse scan results"}

    def _format_report(self, data):
        return {
            "target": self.target_url,
            "vulnerabilities": {
                "SQLi": [{
                    "parameter": param['name'],
                    "type": param['type'],
                    "payloads": param['payloads'],
                    "extracted_data": param['extracted_data']
                } for param in data['parameters']]
            },
            "statistics": {
                "requests": data['total_requests'],
                "response_time": f"{data['avg_response_time']}ms"
            }
        }

    def _parse_findings(self, data):
        return {
            "url": self.target_url,
            "method": data['request']['method'],
            "parameters": [
                {
                    "name": param['name'],
                    "type": param['type'],
                    "payloads": [
                        {
                            "type": payload['type'],
                            "value": payload['value'],
                            "response": payload['response'][:100] + "..."
                        } for payload in param['payloads']
                    ],
                    "extracted_data": {
                        "db_type": data['dbms'],
                        "version": data['dbms_version'],
                        "tables": data['tables'][:3]  # Limit for demo
                    }
                } for param in data['parameters']
            ]
        }

    def generate_report(self, results):
        if 'error' in results:
            return f"[!] Scan failed: {results['error']}"

        report = f"""
[+] SCAN SUMMARY
──────────────────────────────────────────────────────────────
  📅 Scan Date       : {results['scan_summary']['date']}
  🕒 Scan Duration   : {results['scan_summary']['duration']}
  🎯 Target         : {results['scan_summary']['target']}
  🔍 Scan Type      : {results['scan_summary']['scan_type']}
  🛠 Tests Performed : {results['scan_summary']['tests_performed']} Completed
  ✅ Vulnerabilities : {results['scan_summary']['vulnerabilities']} Confirmed SQL Injection
  📌 Injection Points: {results['scan_summary']['injection_points']} Unique Parameters Affected

[+] SQL INJECTION FINDINGS
──────────────────────────────────────────────────────────────"""
        
        for param in results['findings']['parameters']:
            report += f"""
  🌐 URL            : {results['findings']['url']}
  🔄 Method        : {results['findings']['method']}
  📌 Affected Param : {param['name']}
  🔥 Exploitation  : {param['type'].title()} SQL Injection
  ⚠ Severity      : CRITICAL
  
  Payload Used:
    {param['payloads'][0]['value']}

  Server Response:
    {param['payloads'][0]['response']}

  Extracted Data:
    📌 Database Type   : {param['extracted_data']['db_type']}
    📌 Database Version: {param['extracted_data']['version']}
    📌 Found Tables    : {', '.join(param['extracted_data']['tables'])}
──────────────────────────────────────────────────────────────"""

        report += f"""
[+] SCAN STATISTICS
──────────────────────────────────────────────────────────────
  🔹 Total HTTP Requests Sent  : {results['statistics']['requests']}
  🔹 Unique URLs Scanned       : {results['statistics']['urls']}
  🔹 Average Response Time     : {results['statistics']['response_time']}

[+] REFERENCES & NEXT STEPS
──────────────────────────────────────────────────────────────
  📌 OWASP SQL Injection Prevention Guide:
     → https://owasp.org/www-community/attacks/SQL_Injection
  📌 Immediate Actions:
    1. Parameterize all SQL queries
    2. Implement strict input validation
    3. Update database access credentials

📢 Report Generated by: AegisScan - CLI Security Scanner
🚀 Developed by: Aditya Pandey & Masood Aslam 
──────────────────────────────────────────────────────────────"""
        return report

    def _format_xss_results(self, results):
        # Implement XSS results formatting logic
        pass

    def _html_template(self, results):
        # Implement HTML template generation logic
        pass

    def run_ci_scan(self):
        cmd = [
            "sqlmap",
            "-u", self.target_url, 
            "--batch",
            "--level", str(self.depth),
            "--output-dir=./reports",
            "--flush-session",
            "--format=json"
        ]
        subprocess.run(cmd, check=True) 