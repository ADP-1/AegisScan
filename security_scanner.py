import argparse
from scanner import SQLiScanner, XSSScanner
from scanner.csrf import CSRFScanner  # Import our new CSRFScanner directly
from reports import ReportGenerator
import sys
import os
import time
import subprocess
import threading
from queue import Queue
import shutil
from utils.progress import ProgressHandler
import logging
from colorama import Fore, Style
from datetime import datetime

# Add after imports
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Add this constant near top of file
ATTACK_MENU_PROMPT = """\nSelect Attack Type:
1. SQL Injection
2. XSS (Cross-Site Scripting) 
3. CSRF (Cross-Site Request Forgery)
4. Run All Scans
5. Go Back
6. Exit

Enter attack choice (1-6): """

def main():
    if len(sys.argv) > 1:
        # Non-interactive mode: show banner once
        print_banner()
        parser = argparse.ArgumentParser(description='AegisScan Web Security Analyzer')
        parser.add_argument('--version', action='version', version='%(prog)s 0.1.0')
        parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
        parser.add_argument('--depth', type=int, default=3, help='Scan depth (1-5)')
        parser.add_argument('--sqlmap', action='store_true', help='Run SQL injection tests')
        parser.add_argument('--xss', action='store_true', help='Run XSS tests')
        parser.add_argument('--csrf', action='store_true', help='Run CSRF tests')  # Add CSRF flag
        parser.add_argument('--all', action='store_true', help='Run all security tests')
        parser.add_argument('-o', '--output', help='Output file for the report')
        parser.add_argument('-f', '--format', help='Output format for the report')
        # ... add other arguments from PRD §3.1 ...

        args = parser.parse_args()
        
        # If no scan type specified, default to all
        if not (args.sqlmap or args.xss or args.csrf or args.all):
            args.all = True
            
        # Run scans based on arguments
        results = {}
        
        if args.sqlmap or args.all:
            print(f"\n{Fore.CYAN}[*] Running SQL Injection scan...{Style.RESET_ALL}")
            sqli_results = execute_security_scan("SQLi", args.url)
            if sqli_results:
                results["SQLi"] = sqli_results
                
        if args.xss or args.all:
            print(f"\n{Fore.CYAN}[*] Running XSS scan...{Style.RESET_ALL}")
            xss_results = execute_security_scan("XSS", args.url)
            if xss_results:
                results["XSS"] = xss_results
                
        if args.csrf or args.all:
            print(f"\n{Fore.CYAN}[*] Running CSRF scan...{Style.RESET_ALL}")
            csrf_results = execute_security_scan("CSRF", args.url)
            if csrf_results:
                results["CSRF"] = csrf_results
        
        # Generate report
        if results:
            report_format = args.format or "txt"
            output_file = args.output or f"aegisscan_report_{int(time.time())}.{report_format}"
            
            report_gen = ReportGenerator(results, args.url)
            report_gen.generate_report(output_file, report_format)
            
            print(f"\n{Fore.GREEN}✅ Scan completed! Report saved to: {output_file}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}❌ No scan results were generated.{Style.RESET_ALL}")
            
    else:
        # Interactive mode
        interactive_mode()

def interactive_mode():
    print_banner()
    while True:
        print_main_menu()
        handle_choice()

def handle_choice():
    try:
        choice = input("\nEnter your choice (1-3): ")
        process_choice(choice)
    except KeyboardInterrupt:
        exit_program()

def process_choice(choice):
    if choice == '1':
        show_about()
    elif choice == '2':
        target = get_target_url()
        if target:
            attack_menu(target)
    elif choice == '3':
        exit_program()
    else:
        invalid_choice()

def print_main_menu():
    print("""\nAegisScan Interactive Mode
1. About AegisScan
2. Set Target for Scanning
3. Exit""")

def check_tool_installed(tool_name):
    """Check if required security tool is installed"""
    try:
        result = subprocess.run([tool_name, '--version'], 
                              capture_output=True, 
                              text=True)
        return result.returncode == 0
    except FileNotFoundError:
        return False

def run_scan_tool(scanner, progress_handler, result_queue):
    """Run the selected security scanner and put results in queue"""
    try:
        # Different scanners have slightly different method names
        if isinstance(scanner, SQLiScanner):
            results = scanner.run_scan()
        elif isinstance(scanner, XSSScanner):
            results = scanner.scan_target()
        elif isinstance(scanner, CSRFScanner):  # Changed from CSRFAnalyzer to CSRFScanner
            results = scanner.scan()
        else:
            results = None
            
        result_queue.put((True, results))
    except Exception as e:
        result_queue.put((False, str(e)))

def display_progress(handler):
    """Animated progress bar that updates in-place"""
    start_time = time.time()
    while handler.running or (time.time() - start_time < 30):  # Add timeout
        current = handler.get_progress()
        bar = f"[{'■' * int(current/5)}{' ' * (20 - int(current/5))}]"
        sys.stdout.write(f"\rScan Progress: {bar} {current}%")
        sys.stdout.flush()
        time.sleep(0.1)
    print("\n")

def get_scan_command(scan_type, target):
    """Return appropriate command for each scan type"""
    scan_commands = {
        "SQLi": ["sqlmap", "-u", target, "--batch", "--output-dir=./reports"],
        "XSS": ["xsstrike", "-u", target, "--crawl"],
        "CSRF": ["csrf-scanner", target]
    }
    
    if scan_type not in scan_commands:
        raise ValueError(f"Invalid scan type: {scan_type}")
    
    return scan_commands[scan_type]

def execute_security_scan(scan_type, target):
    """Execute scan with real SQLMap integration"""
    # First verify required tools are installed
    required_tools = {
        "SQLi": "sqlmap",
        "XSS": "xsstrike",
        # CSRF doesn't require external tools as we've implemented it directly
    }
    
    if scan_type in required_tools:
        tool = required_tools[scan_type]
        if not check_tool_installed(tool):
            print(f"\n❌ Error: {tool} is not installed!")
            print(f"Please install {tool} first:")
            if tool == "sqlmap":
                print("    pip install sqlmap")
                print("    or download from: https://github.com/sqlmapproject/sqlmap")
            return None

    progress = ProgressHandler()
    scanners = {
        "SQLi": SQLiScanner(target, progress),
        "XSS": XSSScanner(target),
        "CSRF": CSRFScanner(target, progress_handler=progress, 
                           config={
                               'depth': 3,
                               'max_forms': 100,
                               'randomness_threshold': 0.75,
                               'token_samples': 8,
                               'threads': 8,
                               'generate_poc': True,
                               'verify_attacks': True
                           })  # Enhanced configuration
    }
    
    if scan_type not in scanners:
        return None

    scanner = scanners[scan_type]
    result_queue = Queue()

    try:
        # Start scan thread
        scan_thread = threading.Thread(
            target=run_scan_tool,
            args=(scanner, progress, result_queue)
        )
        scan_thread.start()

        # Display progress
        print(f"\n🚀 Starting {scan_type} scan...")
        display_progress(progress)
        
        # Get results
        success, output = result_queue.get()
        
        if success:
            # Generate report for CSRF scan
            if scan_type == "CSRF" and output:
                # Create a timestamp-based filename
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                report_file = f"csrf_report_{timestamp}.html"
                report_path = os.path.join(os.path.dirname(__file__), 'reports', report_file)
                
                # Ensure reports directory exists
                os.makedirs(os.path.dirname(report_path), exist_ok=True)
                
                # Generate the report
                report_gen = ReportGenerator({"CSRF": output}, target)
                report_path = report_gen.generate_report(report_path, "html")
                
                print(f"\n{Fore.GREEN}✅ CSRF scan completed! Found {len(output)} vulnerabilities.{Style.RESET_ALL}")
                print(f"{Fore.GREEN}📊 Report saved to: {report_path}{Style.RESET_ALL}")
                
                # Display summary of findings
                if output:
                    severity_counts = {"High": 0, "Medium": 0, "Low": 0}
                    for vuln in output:
                        severity = vuln.get('severity', 'Unknown')
                        if severity in severity_counts:
                            severity_counts[severity] += 1
                    
                    print(f"\n{Fore.YELLOW}📋 Vulnerability Summary:{Style.RESET_ALL}")
                    print(f"   {Fore.RED}High: {severity_counts['High']}{Style.RESET_ALL}")
                    print(f"   {Fore.YELLOW}Medium: {severity_counts['Medium']}{Style.RESET_ALL}")
                    print(f"   {Fore.BLUE}Low: {severity_counts['Low']}{Style.RESET_ALL}")
                    
                    # Show sample of high severity findings
                    high_severity = [v for v in output if v.get('severity') == 'High']
                    if high_severity:
                        print(f"\n{Fore.RED}⚠️ High Severity Findings Sample:{Style.RESET_ALL}")
                        for i, vuln in enumerate(high_severity[:3]):  # Show up to 3 examples
                            print(f"   {i+1}. {vuln.get('url', 'Unknown URL')} - {', '.join(vuln.get('type', []))}")
            
            return output
        else:
            print(f"\n❌ {scan_type} scan failed: {output}")
            return None
            
    except Exception as e:
        print(f"\n❌ Error during {scan_type} scan: {str(e)}")
        return None

def format_scan_results(raw_output, scan_type):
    """Convert tool output to structured report"""
    # Implement parsing logic based on your sample format
    report = {
        "scan_summary": {
            "date": time.strftime("%Y-%m-%d"),
            "target": "https://example.com",
            "vulnerabilities": 3,
            "severity": "CRITICAL"
        },
        "findings": []  # Add parsed findings here
    }
    
    return f"""
[+] {scan_type.upper()} SCAN RESULTS
───────────────────────────────────────────────
  ✅ Vulnerabilities Found: {report['scan_summary']['vulnerabilities']}
  ⚠️  Maximum Severity: {report['scan_summary']['severity']}
───────────────────────────────────────────────
    """

def handle_scan_errors(error):
    """User-friendly error handling"""
    if "FileNotFound" in error or "WinError 2" in error:
        print("\n🔴 Error: Required tool not found!")
        print("  1. Check tool installation")
        print("  2. Verify PATH environment variable")
        print("  3. Use absolute path to tool executable")
    else:
        print(f"\n❌ Scan failed: {error}")

def attack_menu(target):
    last_results = None
    while True:
        print("\n")
        print_banner()
        
        # Persistent target header
        print(f"Active Target: {target}\n" + "=" * shutil.get_terminal_size().columns)
        
        # Show attack menu
        print(ATTACK_MENU_PROMPT, end='')
        
        try:
            choice = input().strip()
            
            if choice == '1':
                # Initialize progress handler
                progress = ProgressHandler()
                scanner = SQLiScanner(target, progress)
                
                print("\n🚀 Starting SQL Injection scan...")
                print("This may take several minutes. Press Ctrl+C to cancel.\n")
                
                # Run the scan
                try:
                    results = scanner.run_scan()
                    # Results and final report are now handled directly by the scanner 
                    # Let the user know they can continue
                    input("\nPress Enter to continue...")
                except KeyboardInterrupt:
                    # The scanner handles its own interrupt
                    input("\nPress Enter to continue...")
                except Exception as e:
                    print(f"\n❌ Error during scan: {str(e)}")
                    input("\nPress Enter to continue...")
            
            elif choice == '2':
                # XSS Scanner
                progress = ProgressHandler()
                scanner = XSSScanner(target, progress)
                
                print("\n🚀 Starting XSS scan...")
                print("This may take several minutes. Press Ctrl+C to cancel.\n")
                
                try:
                    # Clear a line for status updates
                    print("")
                    
                    # Run the scan
                    start_time = time.time()
                    results = scanner.run_scan()
                    end_time = time.time()
                    
                    # Print a newline after the scan to ensure report starts on a clean line
                    print("\n")
                    
                    # Generate and display the detailed report
                    print(scanner.generate_report(results))
                    
                    # Display scan completion message
                    print(f"\n✅ XSS Scan completed in {end_time - start_time:.2f} seconds!")
                    
                    if results and isinstance(results, dict) and 'scan_summary' in results:
                        vuln_count = results['scan_summary'].get('vulnerabilities', 0)
                        if vuln_count > 0:
                            print(f"\n{Fore.RED}⚠️  {vuln_count} XSS vulnerabilities found!{Style.RESET_ALL}")
                        else:
                            print(f"\n{Fore.GREEN}✓ No XSS vulnerabilities found.{Style.RESET_ALL}")
                
                except KeyboardInterrupt:
                    # Handle user interruption
                    print("\n\n⚠️  Scan interrupted by user.")
                    
                    # Try to generate a partial report if possible
                    try:
                        if hasattr(scanner, 'generate_report'):
                            partial_results = {
                                "scan_summary": {
                                    "target": target,
                                    "vulnerabilities": 0,
                                    "severity": "Unknown",
                                    "payloads_tested": getattr(scanner, 'payloads_tested', 0)
                                },
                                "scan_timing": {
                                    "start_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                    "end_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                    "duration": str(datetime.now() - getattr(scanner, 'start_time', datetime.now()))
                                },
                                "findings": [],
                                "interrupted": True
                            }
                            print("\n" + scanner.generate_report(partial_results))
                    except Exception as e:
                        logging.error(f"Error generating partial report: {str(e)}")
                
                except Exception as e:
                    print(f"\n❌ Error during scan: {str(e)}")
                    
                input("\nPress Enter to continue...")
            
            elif choice == '3':
                # Enhanced CSRF scan with detailed configuration
                print("\n🚀 Starting CSRF scan...")
                print("This may take several minutes. Press Ctrl+C to cancel.\n")
                
                try:
                    # Configure the CSRF scanner with enhanced options
                    progress = ProgressHandler()
                    csrf_scanner = CSRFScanner(
                        target, 
                        progress_handler=progress,
                        config={
                            'depth': 3,
                            'max_forms': 100,
                            'randomness_threshold': 0.75,
                            'token_samples': 8,
                            'threads': 8,
                            'generate_poc': True,
                            'verify_attacks': True
                        }
                    )
                    
                    # Run the scan
                    results = csrf_scanner.scan()
                    
                    # Generate report
                    if results:
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        report_file = f"csrf_report_{timestamp}.html"
                        report_path = os.path.join(os.path.dirname(__file__), 'reports', report_file)
                        
                        # Ensure reports directory exists
                        os.makedirs(os.path.dirname(report_path), exist_ok=True)
                        
                        # Generate the report
                        report_gen = ReportGenerator({"CSRF": results}, target)
                        report_path = report_gen.generate_report(report_path, "html")
                        
                        print(f"\n{Fore.GREEN}✅ CSRF scan completed! Found {len(results)} vulnerabilities.{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}📊 Report saved to: {report_path}{Style.RESET_ALL}")
                        
                        # Display summary of findings
                        severity_counts = {"High": 0, "Medium": 0, "Low": 0}
                        for vuln in results:
                            severity = vuln.get('severity', 'Unknown')
                            if severity in severity_counts:
                                severity_counts[severity] += 1
                        
                        print(f"\n{Fore.YELLOW}📋 Vulnerability Summary:{Style.RESET_ALL}")
                        print(f"   {Fore.RED}High: {severity_counts['High']}{Style.RESET_ALL}")
                        print(f"   {Fore.YELLOW}Medium: {severity_counts['Medium']}{Style.RESET_ALL}")
                        print(f"   {Fore.BLUE}Low: {severity_counts['Low']}{Style.RESET_ALL}")
                    else:
                        print(f"\n{Fore.GREEN}✅ CSRF scan completed! No vulnerabilities found.{Style.RESET_ALL}")
                
                except KeyboardInterrupt:
                    print("\n\n⚠️  Scan interrupted by user.")
                except Exception as e:
                    print(f"\n❌ Error during CSRF scan: {str(e)}")
                
                input("\nPress Enter to continue...")
            
            elif choice == '4':
                run_all_scans(target)
            elif choice == '5':
                return  # Exit to main menu
            elif choice == '6':
                exit_program()
            else:
                invalid_choice()
            
        except KeyboardInterrupt:
            print("\n\nScan cancelled by user.")
            input("\nPress Enter to continue...")
            continue

def run_scan(choice, target):
    try:
        scanner = {
            '1': SQLiScanner,
            '2': XSSScanner,
            '3': CSRFAnalyzer,
            '4': None
        }[choice]
        
        if choice == '4':
            return run_all_scans(target)
            
        print(f"\nStarting {scanner.__name__} scan...")
        results = scanner(target).run_scan()
        display_results(results)
        return results
        
    except Exception as e:
        print(f"Scan failed: {str(e)}")
        return None
    finally:
        input("\nPress Enter to return to menu...")

def exit_program():
    print("\n\nExiting AegisScan...")
    sys.exit(0)

def print_banner():
    print(r"""
 █████╗ ███████╗ ██████╗ ██╗███████╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔════╝ ██║██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║
███████║█████╗  ██║  ███╗██║███████╗███████╗██║     ███████║██╔██╗ ██║
██╔══██║██╔══╝  ██║   ██║██║╚════██║╚════██║██║     ██╔══██║██║╚██╗██║
██║  ██║███████╗╚██████╔╝██║███████║███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
-------------------By Aditya Pandey & Masood Aslam--------------------
                                                                      
    """)
    print("AegisScan - Web Application Security Analyzer v0.1.0\n")

def show_about():
    print("""AegisScan v0.1.0
A CLI-based web application security analyzer
Designed for detecting SQLi, XSS, and CSRF vulnerabilities
Developed by Aditya Pandey & Masood Aslam""")
    input("\nPress Enter to return...")

def get_target_url():
    print("Set Target URL\n" + "="*30)
    url = input("\nEnter target URL: ").strip()
    
    if not url.startswith(('http://', 'https://')):
        print("Invalid URL - must start with http:// or https://")
        time.sleep(1.5)
        return None
        
    print(f"\nTarget set to: {url}")
    input("Press Enter to continue...")
    return url

def invalid_choice():
    print("Invalid selection - please choose 1-3")
    time.sleep(1)

def display_results(results):
    if isinstance(results, dict) and 'scan_summary' in results:
        print(SQLiScanner("").generate_report(results))
    else:
        print(f"\nScan Results:\n{'-'*30}")
        for vuln in results:
            print(f"[{vuln['severity']}] {vuln['type']}: {vuln['details']}")

def run_all_scans(target):
    scanners = [SQLiScanner, XSSScanner, CSRFAnalyzer]
    for scanner in scanners:
        run_scan(scanner(target))

if __name__ == "__main__":
    main()