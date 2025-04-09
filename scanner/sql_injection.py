import subprocess
import re
import os
import time
import logging
from datetime import datetime
import sys
import signal
import shutil
from colorama import init, Fore, Style
import validators
import threading

# Initialize colorama for colored output
init(autoreset=True)

# Global lock for thread-safe printing
print_lock = threading.Lock()

# Define base directories
base_dir = os.path.dirname(os.path.abspath(__file__))
log_dir = os.path.join(base_dir, 'logs')
os.makedirs(log_dir, exist_ok=True)

logging.basicConfig(
    filename=os.path.join(log_dir, "sql_injection.log"),
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

class SQLiScanner:
    def __init__(self, target_url, progress_handler=None, depth=3, risk=1, custom_query=None):
        if not validators.url(target_url):
            raise ValueError("Invalid URL provided.")
        self.target_url = target_url
        self.depth = depth
        self.risk = risk
        self.progress_handler = progress_handler
        self.custom_query = custom_query  # Optional custom SQL query
        self.start_time = None
        self.end_time = None
        self.payloads_tested = 0
        self.progress = 0  # Progress percentage (0-100)
        self.output_dir = os.path.join(base_dir, 'reports')
        os.makedirs(self.output_dir, exist_ok=True)
        # Get terminal dimensions (with fallbacks)
        try:
            dims = shutil.get_terminal_size()
            self.terminal_width = dims.columns
            self.terminal_height = dims.lines
        except Exception:
            self.terminal_width = 80
            self.terminal_height = 24

    def run_scan(self):
        try:
            self.start_time = datetime.now()
            with print_lock:
                print("🚀 Starting SQL Injection scan...")
                print("This may take several minutes. Press Ctrl+C to cancel.\n")
                print(f"[*] Starting SQL injection scan")
                print(f"[*] Target: {self.target_url}")
                if self.custom_query:
                    print(f"[*] Using custom SQL query: {self.custom_query}")
                print("[*] Starting SQLMap process...")

            cmd = self._build_sqlmap_command()
            logging.info("Executing command: %s", " ".join(cmd))
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1
            )

            # Event for signaling thread termination
            termination_event = threading.Event()

            # Start the progress updater thread
            progress_thread = threading.Thread(target=self.progress_bar_updater, args=(termination_event,))
            progress_thread.daemon = True
            progress_thread.start()

            # Set up SIGINT handler for graceful interruption
            original_sigint = signal.getsignal(signal.SIGINT)
            signal.signal(signal.SIGINT, self._sigint_handler(original_sigint, process, termination_event))

            # Start the output reader thread
            reader_thread = threading.Thread(target=self.read_output, args=(process, termination_event))
            reader_thread.start()

            # Wait for output processing to finish
            reader_thread.join()
            termination_event.set()
            progress_thread.join()
            process.wait()
            self.end_time = datetime.now()

            with print_lock:
                print("[*] SQL injection scan completed.")

            results = self._parse_results()
            final_report = self.generate_report(results)
            with print_lock:
                print(final_report)

            return results

        except Exception as e:
            with print_lock:
                print(f"{Fore.RED}[!] Error during scan: {str(e)}")
            logging.error("Error during scan: %s", str(e))
            return {"error": str(e)}

    def progress_bar_updater(self, termination_event):
        """
        Periodically updates the progress bar at the bottom of the terminal.
        It saves the current cursor position, moves to the bottom, prints the progress bar,
        and then restores the cursor.
        """
        while not termination_event.is_set():
            with print_lock:
                sys.stdout.write("\033[s")  # Save current cursor position
                sys.stdout.write(f"\033[{self.terminal_height};0H")  # Move to bottom line
                bar_width = max(self.terminal_width - 30, 10)
                filled_width = int(bar_width * self.progress / 100)
                bar = f"{'█' * filled_width}{'░' * (bar_width - filled_width)}"
                progress_line = f"[{datetime.now().strftime('%H:%M:%S')}] Progress: {self.progress:3d}% [{bar}]"
                sys.stdout.write(progress_line.ljust(self.terminal_width))
                sys.stdout.write("\033[u")  # Restore saved cursor position
                sys.stdout.flush()
            time.sleep(1)

    def read_output(self, process, termination_event):
        """
        Reads and processes each line from SQLMap's stdout.
        Updates the progress value, prints payload lines (with timestamp and payload count)
        and prints other log lines. Stops after reaching 120 payloads.
        """
        while True:
            line = process.stdout.readline()
            if line == '' and process.poll() is not None:
                break
            if line:
                line = line.strip()
                # Update progress based on output content
                self.progress = self._calculate_progress(line, self.progress)
                # Check if this line contains a payload
                if "[PAYLOAD]" in line:
                    if self.payloads_tested < 120:
                        self.payloads_tested += 1
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        payload_line = f"[{timestamp}] [PAYLOAD #{self.payloads_tested}] {self._format_payload(line)}"
                        with print_lock:
                            print(payload_line)
                    else:
                        with print_lock:
                            print("[!] Payload limit of 120 reached. Terminating scan.")
                        process.terminate()
                        break
                else:
                    with print_lock:
                        print(f"[*] {line}")
        termination_event.set()

    def _build_sqlmap_command(self):
        cmd = [
            "sqlmap",
            "-u", self.target_url,
            "--batch",
            "--random-agent",
            "--level", str(self.depth),
            "--risk", str(self.risk),
            "--output-dir", self.output_dir,
            "--flush-session",
            "--threads=10",
            "--timeout=30",
            "--retries=3",
            "--keep-alive",
            "--technique=BEUSTQ",
            "--tamper=space2comment,between",
            "-v", "3"
        ]
        if self.custom_query:
            cmd.extend(["--sql-query", self.custom_query])
        return cmd

    def _sigint_handler(self, original_handler, process, termination_event):
        def handler(sig, frame):
            with print_lock:
                print(f"\n{Fore.YELLOW}[!] Scan interrupted. Terminating process and generating final report...")
            try:
                process.terminate()
            except Exception as ex:
                logging.error("Error terminating process: %s", ex)
            self.end_time = datetime.now()
            termination_event.set()
            results = self._parse_results()
            report = self.generate_report(results)
            with print_lock:
                print(report)
            signal.signal(signal.SIGINT, original_handler)
            sys.exit(1)
        return handler

    def _format_payload(self, line):
        if "[PAYLOAD]" in line:
            # Extract payload text after the marker
            return line.split("[PAYLOAD]", 1)[1].strip()
        return line

    def _calculate_progress(self, line, current_progress):
        """
        Increase the progress counter based on certain SQLMap output patterns.
        Adjust these increments as needed.
        """
        line_lower = line.lower()
        if "testing " in line_lower:
            current_progress += 2
        elif "parameter '" in line_lower:
            current_progress += 5
        elif "the back-end dbms is" in line_lower:
            current_progress += 10
        elif "sqlmap identified" in line_lower:
            current_progress += 15
        # Cap progress at 99 until the scan completes
        return min(current_progress, 99)

    def _parse_results(self):
        try:
            target_host = self.target_url.split('//')[1].split('/')[0]
            target_dir = os.path.join(self.output_dir, target_host)
            vulnerabilities = []
            if not os.path.exists(target_dir):
                logging.warning("No results directory found at %s", target_dir)
                return self._create_empty_result()
            log_file = os.path.join(target_dir, "log")
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    content = f.read()
                    if "might be injectable" in content:
                        vulnerabilities.append({
                            "parameter": self._extract_parameter(content),
                            "type": self._extract_vulnerability_type(content),
                            "severity": "HIGH",
                            "details": self._extract_details(content)
                        })
                    if "appears to be 'AND boolean-based blind" in content:
                        vulnerabilities.append({
                            "parameter": self._extract_parameter(content),
                            "type": "Boolean-based blind SQL injection",
                            "severity": "HIGH",
                            "details": "Parameter is vulnerable to boolean-based blind SQL injection"
                        })
                    if "appears to be 'MySQL >= 5.0 error-based" in content:
                        vulnerabilities.append({
                            "parameter": self._extract_parameter(content),
                            "type": "Error-based SQL injection",
                            "severity": "CRITICAL",
                            "details": "Parameter is vulnerable to error-based SQL injection"
                        })
            return {
                "vulnerabilities": {"SQLi": vulnerabilities},
                "statistics": {
                    "duration": str(self.end_time - self.start_time) if self.end_time else "N/A",
                    "vulnerabilities_found": len(vulnerabilities),
                    "payloads_tested": self.payloads_tested
                }
            }
        except Exception as e:
            logging.error("Error parsing results: %s", str(e))
            return self._create_empty_result()

    def _extract_parameter(self, content):
        match = re.search(r"parameter '([^']+)'", content)
        return match.group(1) if match else "Unknown"

    def _extract_vulnerability_type(self, content):
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
        details = []
        dbms_match = re.search(r"the back-end DBMS is '([^']+)'", content)
        if dbms_match:
            details.append(f"Database: {dbms_match.group(1)}")
        vuln_match = re.search(r"appears to be '([^']+)'", content)
        if vuln_match:
            details.append(f"Vulnerability: {vuln_match.group(1)}")
        return " | ".join(details) if details else "SQL injection vulnerability detected"

    def _create_empty_result(self):
        return {
            "vulnerabilities": {"SQLi": []},
            "statistics": {
                "duration": "0s",
                "vulnerabilities_found": 0,
                "payloads_tested": self.payloads_tested
            }
        }

    def generate_report(self, results):
        vulnerabilities = results.get("vulnerabilities", {}).get("SQLi", [])
        vuln_count = len(vulnerabilities)
        duration = str(self.end_time - self.start_time) if self.end_time else "N/A"
        report = (
            f"\n🎯 SQL INJECTION SCAN REPORT\n"
            f"═══════════════════════════════════════════════════════════════\n"
            f"📅 Scan Date: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"⏱️  Duration: {duration}\n"
            f"🌐 Target: {self.target_url}\n"
            f"🎲 Risk Level: {self.risk}\n"
            f"🧪 Payloads Tested: {self.payloads_tested}\n"
            f"✨ Found Vulnerabilities: {vuln_count}\n\n"
        )
        if vuln_count == 0:
            report += "ℹ️  No SQL injection vulnerabilities were found\n"
        else:
            report += " DETAILED FINDINGS\n"
            report += "═══════════════════════════════════════════════════════════════\n"
            for i, vuln in enumerate(vulnerabilities, 1):
                report += (
                    f"\n{i}. [{vuln.get('severity', 'UNKNOWN')}] {vuln.get('type', 'Unknown')}\n"
                    f"   Parameter: {vuln.get('parameter', 'N/A')}\n"
                    f"   Details: {vuln.get('details', 'N/A')}\n"
                )
        report += "═══════════════════════════════════════════════════════════════"
        return report

if __name__ == "__main__":
    # Example usage for testing
    target = "https://markme.framer.media/"
    custom_sql = "SELECT version()"
    scanner = SQLiScanner(target_url=target, depth=3, risk=1, custom_query=custom_sql)
    scanner.run_scan()
