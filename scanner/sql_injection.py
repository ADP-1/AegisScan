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
import shutil

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
        self.terminal_width = shutil.get_terminal_size().columns
        self.terminal_height = shutil.get_terminal_size().lines
        self.status_message = "Initializing scan..."
        self.last_status_update = time.time()
        self.estimated_time = "calculating..."
        
        # Ensure output directory exists
        os.makedirs(self.output_dir, exist_ok=True)

    def run_scan(self):
        """Runs SQLMap scan on the target URL"""
        try:
            self.start_time = datetime.now()
            
            # Clear terminal and set up display
            self._clear_terminal()
            self._print_header()

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

            # Update status
            self.status_message = "Starting SQLMap process..."
            self._update_status_bar(0)

            # Start SQLMap process
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1
            )

            # Initialize payload display area
            payload_display_height = self.terminal_height - 7  # Reserve space for header and status bar
            payload_lines = ["" for _ in range(payload_display_height)]
            current_progress = 0
            
            # Add signal handler for Ctrl+C
            import signal
            original_sigint = signal.getsignal(signal.SIGINT)
            
            def sigint_handler(sig, frame):
                self._move_cursor_to_status_bar()
                print(f"\n{Fore.YELLOW}[!] Scan interrupted. Generating final report...")
                self.end_time = datetime.now()
                result = self._parse_results()
                report = self.generate_report(result)
                print(report)
                signal.signal(signal.SIGINT, original_sigint)
                sys.exit(1)
                
            signal.signal(signal.SIGINT, sigint_handler)

            # Display initial interface
            self._update_status_bar(0)

            while True:
                output_line = process.stdout.readline()
                if output_line == '' and process.poll() is not None:
                    break
                
                if output_line:
                    output_line = output_line.strip()
                    
                    # Update progress based on output content
                    current_progress = self._calculate_progress(output_line, current_progress)
                    
                    # Update payload counter if a payload is detected
                    if "[PAYLOAD]" in output_line:
                        self.payloads_tested += 1
                        self.status_message = f"Testing payload #{self.payloads_tested}..."
                        
                        # Format the payload line for display
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        payload_line = f"{Fore.BLUE}[{timestamp}] {Fore.YELLOW}[PAYLOAD #{self.payloads_tested}] {Fore.WHITE}{self._format_payload(output_line)}"
                        
                        # Add new payload to display and shift older ones up
                        payload_lines.pop(0)
                        payload_lines.append(payload_line)
                    
                    # Update progress status based on other output patterns
                    elif "testing " in output_line.lower():
                        self.status_message = f"Testing: {output_line}"
                    elif "warning" in output_line.lower():
                        payload_lines.pop(0)
                        payload_lines.append(f"{Fore.YELLOW}[WARNING] {output_line}")
                    elif "info" in output_line.lower():
                        self.status_message = f"Info: {output_line}"
                    
                    # Update the display
                    self._update_payload_display(payload_lines)
                    self._update_status_bar(current_progress)

            # Process return code
            if process.returncode != 0:
                self._move_cursor_to_status_bar()
                print(f"\n{Fore.RED}[!] SQLMap process failed with code {process.returncode}")
                return {"error": "Scan failed"}

            self.end_time = datetime.now()
            self._move_cursor_to_status_bar()
            print(f"\n{Fore.GREEN}[✓] Scan Completed!")
            return self._parse_results()

        except Exception as e:
            self._move_cursor_to_status_bar()
            print(f"\n{Fore.RED}[!] Error during scan: {str(e)}")
            return {"error": str(e)}

    def _clear_terminal(self):
        """Clear terminal for fresh display"""
        os.system('cls' if os.name == 'nt' else 'clear')

    def _print_header(self):
        """Print the scanner header"""
        header = f"""
{Fore.CYAN}╔{'═' * (self.terminal_width - 2)}╗
{Fore.CYAN}║ {Fore.WHITE}SQL INJECTION SCAN {Fore.YELLOW}• {Fore.GREEN}Target: {self.target_url}{' ' * (self.terminal_width - 47 - len(self.target_url))}{Fore.CYAN}║
{Fore.CYAN}╚{'═' * (self.terminal_width - 2)}╝
{Fore.WHITE}"""
        print(header)

    def _format_payload(self, line):
        """Format payload output for display"""
        # Extract actual payload from sqlmap output
        if "[PAYLOAD]" in line:
            payload = line.split("[PAYLOAD]")[1].strip()
            # Truncate if too long for display
            if len(payload) > self.terminal_width - 40:
                payload = payload[:self.terminal_width - 43] + "..."
            return payload
        return line

    def _update_payload_display(self, payload_lines):
        """Update the payload display area"""
        # Move cursor to payload area (after header)
        sys.stdout.write(f"\033[4;0H")  # Move to line 4, column 0
        
        # Print each payload line
        for line in payload_lines:
            # Ensure line doesn't exceed terminal width
            if len(line) > self.terminal_width:
                line = line[:self.terminal_width - 3] + "..."
            
            # Clear the line and print the payload
            sys.stdout.write("\033[K")  # Clear line
            print(line)
        
        sys.stdout.flush()

    def _move_cursor_to_status_bar(self):
        """Move cursor to status bar position"""
        sys.stdout.write(f"\033[{self.terminal_height-3};0H")
        sys.stdout.flush()

    def _update_status_bar(self, progress):
        """Update the fixed status bar at the bottom of the terminal"""
        # Calculate time metrics
        elapsed = (datetime.now() - self.start_time).total_seconds()
        elapsed_str = self._format_time(elapsed)
        
        # Update estimated time remaining every 5 seconds
        if time.time() - self.last_status_update > 5 and progress > 0:
            if progress < 5:  # Too early for accurate prediction
                self.estimated_time = "calculating..."
            else:
                # Calculate ETA
                total_time = elapsed * 100 / progress
                remaining = total_time - elapsed
                self.estimated_time = self._format_time(remaining)
            self.last_status_update = time.time()
        
        # Determine progress bar color
        if progress < 30:
            color = Fore.BLUE
        elif progress < 70:
            color = Fore.YELLOW
        else:
            color = Fore.GREEN
            
        # Create the progress bar
        bar_width = self.terminal_width - 50
        filled_width = int(bar_width * progress / 100)
        bar = f"{color}{'█' * filled_width}{Fore.WHITE}{'░' * (bar_width - filled_width)}"
        
        # Move cursor to status bar position
        self._move_cursor_to_status_bar()
        
        # Draw status bar border
        sys.stdout.write(f"{Fore.CYAN}╔{'═' * (self.terminal_width - 2)}╗\n")
        
        # Format and display status line
        status_line = f"{Fore.CYAN}║ {Fore.WHITE}Progress: {color}{progress}%{Fore.WHITE} [{bar}] "
        status_line += f"Payloads: {Fore.YELLOW}{self.payloads_tested}{Fore.WHITE} | "
        status_line += f"Elapsed: {Fore.MAGENTA}{elapsed_str}{Fore.WHITE} | "
        status_line += f"ETA: {Fore.CYAN}{self.estimated_time}{Fore.WHITE}"
        
        # Ensure status line fits terminal width
        if len(status_line) > self.terminal_width - 3:
            status_line = status_line[:self.terminal_width - 7] + "...{Fore.CYAN}║"
        else:
            status_line += " " * (self.terminal_width - len(status_line) - 3) + f"{Fore.CYAN}║"
        
        sys.stdout.write(status_line + "\n")
        
        # Draw status message line
        message_line = f"{Fore.CYAN}║ {Fore.WHITE}{self.status_message}"
        message_padding = self.terminal_width - len(message_line) - 3 + len(Fore.CYAN) + len(Fore.WHITE)
        message_line += " " * message_padding + f"{Fore.CYAN}║"
        sys.stdout.write(message_line + "\n")
        
        # Draw bottom border
        sys.stdout.write(f"{Fore.CYAN}╚{'═' * (self.terminal_width - 2)}╗\n")
        
        sys.stdout.flush()

    def _format_time(self, seconds):
        """Format seconds into a readable time string"""
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            minutes = int(seconds / 60)
            secs = int(seconds % 60)
            return f"{minutes}m {secs}s"
        else:
            hours = int(seconds / 3600)
            minutes = int((seconds % 3600) / 60)
            return f"{hours}h {minutes}m"

    def _calculate_progress(self, line, current_progress):
        """Calculate scan progress based on output content"""
        # Progress indicators based on the sqlmap output
        if "testing " in line.lower():
            current_progress += 2
        elif "parameter '" in line.lower():
            current_progress += 5
        elif "the back-end dbms is" in line.lower():
            current_progress += 10
        elif "sqlmap identified" in line.lower():
            current_progress += 15
            
        # Update status message based on progress
        if current_progress < 20:
            self.status_message = "Initializing tests..."
        elif current_progress < 40:
            self.status_message = "Testing parameters..."
        elif current_progress < 60:
            self.status_message = "Refining payloads..."
        elif current_progress < 80:
            self.status_message = "Verifying vulnerabilities..."
        elif current_progress < 95:
            self.status_message = "Finalizing scan..."
        else:
            self.status_message = "Generating report..."

        # Ensure progress stays within bounds
        return min(current_progress, 99)

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
                report += f"\n{i}. {Fore.RED}[{vuln.get('severity', 'UNKNOWN')}]{Fore.WHITE} {vuln.get('type', 'Unknown')}\n"
                report += f"   Parameter: {vuln.get('parameter', 'N/A')}\n"
                report += f"   Details: {vuln.get('details', 'N/A')}\n"
                
        else:
            report += f"ℹ️  No SQL injection vulnerabilities were found\n"
            
        report += "\n═══════════════════════════════════════════════════════════════"
        return report

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
