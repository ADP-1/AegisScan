import argparse
from scanner import SQLiScanner, XSSScanner, CSRFAnalyzer
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
        parser.add_argument('-o', '--output', help='Output file for the report')
        parser.add_argument('-f', '--format', help='Output format for the report')
        # ... add other arguments from PRD §3.1 ...
        
        args = parser.parse_args()
        
        if args.sqlmap:
            sqli_scanner = SQLiScanner(args.url, args.depth)
            sqli_scanner.run_scan()
        
        # ... implement other scan types ...
        
        results = {
            'target': args.url,
            'vulnerabilities': {
                'SQLi': [], 
                'XSS': [],
                'CSRF': []
            }
        }
        
        if args.output:
            reporter = ReportGenerator()
            report = reporter.generate(args.format, results)
            with open(args.output, 'w') as f:
                f.write(report)
    else:
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
    try:
        progress_handler.running = True
        scanner.progress_handler = progress_handler
        results = scanner.run_scan()
        result_queue.put((True, results))
    except Exception as e:
        result_queue.put((False, str(e)))
    finally:
        progress_handler.running = False

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
        "CSRF": "csrf-scanner"
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
        "CSRF": CSRFAnalyzer(target)
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
        scan_thread.join()
        
        return format_scan_results(output, scan_type) if success else None

    except Exception as e:
        handle_scan_errors(str(e))
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
                scanner = XSSScanner(target)
                
                print("\n🚀 Starting XSS scan...")
                print("This may take several minutes. Press Ctrl+C to cancel.\n")
                
                try:
                    results = scanner.run_scan()
                    print("\n✅ XSS Scan completed!")
                except Exception as e:
                    print(f"\n❌ Error during scan: {str(e)}")
                    
                input("\nPress Enter to continue...")
            elif choice == '3':
                execute_security_scan("CSRF", target)
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