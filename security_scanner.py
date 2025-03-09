import argparse
from scanner import SQLiScanner, XSSScanner, CSRFAnalyzer
from reports import ReportGenerator
import sys
import os

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
    while True:
        terminal_height = os.get_terminal_size().lines
        if terminal_height < 24:  # Minimum recommended height
            print("\n" * 3)  # Emergency padding
            print("Please increase terminal height for proper display")
        
        clear_screen()
        print_banner()
        print_main_menu(terminal_height)
        handle_choice()

def print_main_menu(term_height):
    menu_lines = 6  # Count of menu text lines
    padding = max(0, term_height - menu_lines - 15)  # 15 lines for banner
    print(f"\nAegisScan Interactive Mode\n{'=' * 30}")
    print("1. About AegisScan\n2. Set Target for Scanning\n3. Exit")
    print("\n" * padding)  # Dynamic padding based on terminal size

def handle_choice():
    try:
        choice = input("\033[FEnter your choice (1-3): ")  # \033[F moves cursor up
        process_choice(choice)
    except KeyboardInterrupt:
        exit_program()

def attack_menu(target):
    while True:
        clear_screen()
        print(f"\nTarget: {target}")
        print("""Select Attack Type:
1. SQL Injection
2. XSS (Cross-Site Scripting) 
3. CSRF (Cross-Site Request Forgery)
4. Run All Scans
5. Go Back
6. Exit""")
        
        choice = input("\nEnter attack choice (1-6): ")
        
        if choice == '1':
            run_scan(SQLiScanner(target))
        elif choice == '2':
            run_scan(XSSScanner(target))
        elif choice == '3':
            run_scan(CSRFAnalyzer(target))
        elif choice == '4':
            run_all_scans(target)
        elif choice == '5':
            return
        elif choice == '6':
            exit_program()
        else:
            invalid_choice()

def run_scan(scanner):
    try:
        print(f"\nStarting {scanner.__class__.__name__} scan...")
        results = scanner.run_scan()
        display_results(results)
        input("\nPress Enter to continue...")
    except Exception as e:
        print(f"Scan failed: {str(e)}")

# Helper functions
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def exit_program():
    print("\nExiting AegisScan...")
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

if __name__ == "__main__":
    main() 