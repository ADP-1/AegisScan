import subprocess
import json
import re
import os
import time
import logging
from datetime import datetime
from utils.progress import ProgressHandler
import sys
from colorama import init, Fore, Back, Style

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Create logs directory if it doesn't exist
log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
os.makedirs(log_dir, exist_ok=True)

logging.basicConfig(
    filename=os.path.join(log_dir, "sql_injection.log"),
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

class SQLiScanner:
    def __init__(self, target_url, progress_handler=None, depth=3, risk=1):
        self.target_url = target_url
        self.depth = depth
        self.risk = risk
        self.progress_handler = progress_handler
        self.start_time = None
        self.end_time = None
        self.output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'reports')
        # Add payload counter
        self.payloads_tested = 0
        
        # Ensure output directory exists
        os.makedirs(self.output_dir, exist_ok=True)

    def run_scan(self):
        """Runs SQLMap scan on the target URL"""
        try:
            self.start_time = datetime.now()
            print(f"\n{Fore.CYAN}[*] Starting SQL Injection scan on {Fore.YELLOW}{self.target_url}")

            # Direct SQLMap command execution
            cmd = [
                "sqlmap",
                "-u", self.target_url,
                "--batch",
                "--random-agent",
                "--level", str(self.depth),
                "--risk", str(self.risk),
                "--output-dir", self.output_dir,
                "--flush-session",
                "--threads=10",  # Increased threads for faster scanning
                "--timeout=30",
                "--retries=3",
                "--keep-alive",
                "--technique=BEUSTQ",
                "--tamper=space2comment,between",
                "-v", "3"
            ]

            print(f"{Fore.BLUE}[*] Executing: {Fore.WHITE}{' '.join(cmd)}\n")

            # Start SQLMap process
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1
            )

            current_progress = 0
            print(f"{Fore.GREEN}[+] SQL Injection Scan Progress:")
            print(f"{Fore.YELLOW}{'=' * 60}")

            # Add signal handler for Ctrl+C
            import signal
            original_sigint = signal.getsignal(signal.SIGINT)
            
            def sigint_handler(sig, frame):
                print(f"\n{Fore.YELLOW}[!] Scan interrupted. Generating final report...")
                self.end_time = datetime.now()
                result = self._parse_results()
                report = self.generate_report(result)
                print(report)
                signal.signal(signal.SIGINT, original_sigint)
                sys.exit(1)
                
            signal.signal(signal.SIGINT, sigint_handler)

            while True:
                output_line = process.stdout.readline()
                if output_line == '' and process.poll() is not None:
                    break
                
                if output_line:
                    self._colorize_output(output_line.strip())
                    current_progress = self._update_progress(output_line, current_progress)
                    # Update payload counter if a payload is detected
                    if "[PAYLOAD]" in output_line:
                        self.payloads_tested += 1
                        print(f"{Fore.CYAN}[*] Payloads tested: {self.payloads_tested}", end="\r")

            # Process return code
            if process.returncode != 0:
                print(f"\n{Fore.RED}[!] SQLMap process failed with code {process.returncode}")
                return {"error": "Scan failed"}

            print(f"\n{Fore.GREEN}[✓] Scan Completed!")
            return self._parse_results()

        except Exception as e:
            print(f"\n{Fore.RED}[!] Error during scan: {str(e)}")
            return {"error": str(e)}

    def _colorize_output(self, line):
        """Colorize SQLMap output based on content"""
        if "testing " in line.lower():
            print(f"{Fore.CYAN}[*] {line}")
        elif "payload: " in line.lower():
            print(f"{Fore.YELLOW}[>] {line}")
        elif "parameter " in line.lower() and "appears to be" in line.lower():
            print(f"{Fore.GREEN}[!] {Back.GREEN}{Fore.WHITE} VULNERABLE {Style.RESET_ALL} {line}")
        elif "the back-end dbms is" in line.lower():
            print(f"{Fore.MAGENTA}[+] {line}")
        elif "database: " in line.lower():
            print(f"{Fore.BLUE}[*] {line}")
        elif "table found: " in line.lower():
            print(f"{Fore.GREEN}[+] {line}")
        elif "warning" in line.lower():
            print(f"{Fore.YELLOW}[!] {line}")
        elif "error" in line.lower():
            print(f"{Fore.RED}[!] {line}")
        else:
            print(f"{Fore.WHITE}{line}")

    def _update_progress(self, line, current_progress):
        """Update progress bar with color"""
        if "testing " in line.lower():
            current_progress += 2
        elif "parameter '" in line.lower():
            current_progress += 5
        elif "the back-end dbms is" in line.lower():
            current_progress += 10

        current_progress = min(current_progress, 99)
        
        if self.progress_handler:
            self.progress_handler.update_progress(current_progress)
            bar_length = 40
            filled = int(current_progress * bar_length / 100)
            bar = f"{Fore.GREEN}{'█' * filled}{Fore.WHITE}{'░' * (bar_length - filled)}"
            print(f"\r{Fore.BLUE}Progress: [{bar}] {current_progress}%", end='', flush=True)

        return current_progress

    def _parse_results(self):
        """Parse SQLMap results with colored output"""
        try:
            # Get target directory from URL
            target_host = self.target_url.split('//')[1].split('/')[0]
            target_dir = os.path.join(self.output_dir, target_host)
            
            vulnerabilities = []
            
            # Check if target directory exists
            if not os.path.exists(target_dir):
                logging.warning(f"No results directory found at {target_dir}")
                return self._create_empty_result()

            # Parse log file
            log_file = os.path.join(target_dir, "log")
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    content = f.read()
                    
                    # Parse vulnerabilities
                    if "might be injectable" in content:
                        vulnerabilities.append({
                            "parameter": self._extract_parameter(content),
                            "type": self._extract_vulnerability_type(content),
                            "severity": "HIGH",
                            "details": self._extract_details(content)
                        })
                    
                    # Parse boolean-based blind injection
                    if "appears to be 'AND boolean-based blind" in content:
                        vulnerabilities.append({
                            "parameter": self._extract_parameter(content),
                            "type": "Boolean-based blind SQL injection",
                            "severity": "HIGH",
                            "details": "Parameter is vulnerable to boolean-based blind SQL injection"
                        })

                    # Parse error-based injection
                    if "appears to be 'MySQL >= 5.0 error-based" in content:
                        vulnerabilities.append({
                            "parameter": self._extract_parameter(content),
                            "type": "Error-based SQL injection",
                            "severity": "CRITICAL",
                            "details": "Parameter is vulnerable to error-based SQL injection"
                        })

            return {
                "vulnerabilities": {
                    "SQLi": vulnerabilities
                },
                "statistics": {
                    "duration": str(self.end_time - self.start_time) if self.end_time else "N/A",
                    "requests": len(vulnerabilities),
                    "payloads_tested": self.payloads_tested  # Add payloads count to statistics
                }
            }

        except Exception as e:
            logging.error(f"Error parsing results: {str(e)}")
            return self._create_empty_result()

    def _extract_parameter(self, content):
        """Extract vulnerable parameter from SQLMap output"""
        match = re.search(r"parameter '([^']+)'", content)
        return match.group(1) if match else "Unknown"

    def _extract_vulnerability_type(self, content):
        """Extract vulnerability type from SQLMap output"""
        if "boolean-based blind" in content:
            return "Boolean-based blind SQL injection"
        elif "error-based" in content:
            return "Error-based SQL injection"
        elif "time-based blind" in content:
            return "Time-based blind SQL injection"
        elif "UNION query" in content:
            return "UNION-based SQL injection"
        return "SQL injection"

    def _extract_details(self, content):
        """Extract detailed information from SQLMap output"""
        details = []
        
        if "the back-end DBMS is" in content:
            dbms_match = re.search(r"the back-end DBMS is '([^']+)'", content)
            if dbms_match:
                details.append(f"Database: {dbms_match.group(1)}")
        
        if "appears to be" in content:
            vuln_match = re.search(r"appears to be '([^']+)'", content)
            if vuln_match:
                details.append(f"Vulnerability: {vuln_match.group(1)}")

        return " | ".join(details) if details else "SQL injection vulnerability detected"

    def _determine_severity(self, results):
        """Determine overall severity of findings"""
        if not results.get("vulnerabilities"):
            return "NONE"
        
        severity_levels = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
        max_severity = 0
        
        for vuln in results.get("vulnerabilities", []):
            severity = severity_levels.get(vuln.get("severity", "NONE"), 0)
            max_severity = max(max_severity, severity)
        
        for level, value in severity_levels.items():
            if value == max_severity:
                return level
        
        return "NONE"

    def generate_report(self, results):
        """Generate a detailed scan report"""
        if "error" in results:
            return f"\n❌ Scan failed: {results['error']}"

        vulnerabilities = results.get("vulnerabilities", {}).get("SQLi", [])
        
        report = f"""
🎯 SQL INJECTION SCAN REPORT
═══════════════════════════════════════════════════════════════
📅 Scan Date: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}
⏱️  Duration: {self.end_time - self.start_time if self.end_time else 'N/A'}
🌐 Target: {self.target_url}
🎲 Risk Level: {self.risk}
🧪 Payloads Tested: {self.payloads_tested}
✨ Found Vulnerabilities: {len(vulnerabilities)}

"""

        if vulnerabilities:
            report += " DETAILED FINDINGS\n"
            report += "═══════════════════════════════════════════════════════════════\n"
            
            for i, vuln in enumerate(vulnerabilities, 1):
                report += f"""
🔴 Vulnerability #{i}:
    Parameter: {vuln['parameter']}
    Type: {vuln['type']}
    Severity: {vuln['severity']}
    Details: {vuln['details']}
    """
        else:
            report += "ℹ️  No SQL injection vulnerabilities were found\n"

        report += "\n═══════════════════════════════════════════════════════════════"
        return report

    def _create_empty_result(self):
        """Create an empty result structure"""
        return {
            "vulnerabilities": {
                "SQLi": []
            },
            "statistics": {
                "duration": "0s",
                "requests": 0,
                "payloads_tested": self.payloads_tested  # Include payload count even for empty results
            }
        }

    def _get_sqlmap_path(self):
        """Find or install SQLMap"""
        try:
            # First try: Check if sqlmap is in PATH
            result = subprocess.run(["sqlmap", "--version"], 
                                  capture_output=True, 
                                  text=True)
            if result.returncode == 0:
                return "sqlmap"
        except FileNotFoundError:
            print("\n⚠️ SQLMap not found in PATH. Attempting to install...")
            try:
                # Try to install sqlmap using pip
                subprocess.run([sys.executable, "-m", "pip", "install", "sqlmap"], 
                             check=True)
                print("✅ SQLMap installed successfully!")
                return "sqlmap"
            except subprocess.CalledProcessError:
                print("❌ Failed to install SQLMap using pip.")
                print("\nPlease install SQLMap manually:")
                print("1. Run: pip install sqlmap")
                print("   or")
                print("2. Download from: https://github.com/sqlmapproject/sqlmap")
                return None

    def _check_command_exists(self, cmd):
        """Check if a command exists in system PATH"""
        try:
            subprocess.run([cmd, "--version"], 
                          capture_output=True, 
                          text=True)
            return True
        except FileNotFoundError:
            return False
