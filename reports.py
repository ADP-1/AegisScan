import json
import os
import time
from datetime import datetime
from colorama import Fore, Style

class ReportGenerator:
    """Generates security reports in various formats"""
    
    def __init__(self, scan_results, target_url):
        self.scan_results = scan_results
        self.target_url = target_url
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.report_dir = os.path.join(os.path.dirname(__file__), 'reports')
        
        # Ensure reports directory exists
        os.makedirs(self.report_dir, exist_ok=True)
    
    def generate_report(self, output_file, format_type='txt'):
        """Generate a security report in the specified format"""
        if format_type.lower() == 'json':
            return self._generate_json_report(output_file)
        elif format_type.lower() == 'html':
            return self._generate_html_report(output_file)
        else:  # Default to txt
            return self._generate_txt_report(output_file)
    
    def _generate_json_report(self, output_file):
        """Generate a JSON format security report"""
        report_data = {
            "scan_info": {
                "target": self.target_url,
                "timestamp": self.timestamp,
                "scan_types": list(self.scan_results.keys())
            },
            "vulnerabilities": {}
        }
        
        # Process each scan type
        for scan_type, results in self.scan_results.items():
            if scan_type == "SQLi":
                report_data["vulnerabilities"]["sql_injection"] = self._format_sqli_findings(results)
            elif scan_type == "XSS":
                report_data["vulnerabilities"]["cross_site_scripting"] = self._format_xss_findings(results)
            elif scan_type == "CSRF":
                report_data["vulnerabilities"]["csrf"] = self._format_csrf_findings(results)
        
        # Write to file
        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        return output_file
    
    def _generate_txt_report(self, output_file):
        """Generate a plain text security report"""
        with open(output_file, 'w') as f:
            f.write(f"AegisScan Security Report\n")
            f.write(f"========================\n\n")
            f.write(f"Target: {self.target_url}\n")
            f.write(f"Scan Date: {self.timestamp}\n")
            f.write(f"Scan Types: {', '.join(self.scan_results.keys())}\n\n")
            
            # Process each scan type
            for scan_type, results in self.scan_results.items():
                f.write(f"\n{scan_type} Scan Results\n")
                f.write(f"{'-' * (len(scan_type) + 13)}\n\n")
                
                if scan_type == "SQLi":
                    self._write_sqli_txt_findings(f, results)
                elif scan_type == "XSS":
                    self._write_xss_txt_findings(f, results)
                elif scan_type == "CSRF":
                    self._write_csrf_txt_findings(f, results)
        
        return output_file
    
    def _generate_html_report(self, output_file):
        """Generate an HTML format security report"""
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>AegisScan Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2, h3 {{ color: #333; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background-color: #f5f5f5; padding: 20px; border-radius: 5px; }}
        .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
        .high {{ color: #d9534f; }}
        .medium {{ color: #f0ad4e; }}
        .low {{ color: #5bc0de; }}
        .info {{ color: #5cb85c; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
        .vulnerability {{ margin-bottom: 15px; padding-bottom: 15px; border-bottom: 1px solid #eee; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>AegisScan Security Report</h1>
            <p><strong>Target:</strong> {self.target_url}</p>
            <p><strong>Scan Date:</strong> {self.timestamp}</p>
            <p><strong>Scan Types:</strong> {', '.join(self.scan_results.keys())}</p>
        </div>
"""
        
        # Process each scan type
        for scan_type, results in self.scan_results.items():
            html_content += f"""
        <div class="section">
            <h2>{scan_type} Scan Results</h2>
"""
            
            if scan_type == "SQLi":
                html_content += self._format_sqli_html_findings(results)
            elif scan_type == "XSS":
                html_content += self._format_xss_html_findings(results)
            elif scan_type == "CSRF":
                html_content += self._format_csrf_html_findings(results)
            
            html_content += """
        </div>
"""
        
        html_content += """
    </div>
</body>
</html>
"""
        
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        return output_file
    
    # SQLi formatting methods
    def _format_sqli_findings(self, results):
        # Existing SQLi formatting logic
        return results
    
    def _write_sqli_txt_findings(self, file, results):
        # Existing SQLi text formatting logic
        file.write(f"SQL Injection findings would be formatted here\n")
    
    def _format_sqli_html_findings(self, results):
        # Existing SQLi HTML formatting logic
        return "<p>SQL Injection findings would be formatted here</p>"
    
    # XSS formatting methods
    def _format_xss_findings(self, results):
        # Existing XSS formatting logic
        return results
    
    def _write_xss_txt_findings(self, file, results):
        # Existing XSS text formatting logic
        file.write(f"XSS findings would be formatted here\n")
    
    def _format_xss_html_findings(self, results):
        # Existing XSS HTML formatting logic
        return "<p>XSS findings would be formatted here</p>"
    
    # CSRF formatting methods
    def _format_csrf_findings(self, results):
        """Format CSRF findings for JSON report"""
        formatted_findings = []
        
        for vuln in results:
            finding = {
                "url": vuln.get('url', 'Unknown URL'),
                "page_url": vuln.get('page_url', 'Unknown Page'),
                "severity": vuln.get('severity', 'Unknown'),
                "vulnerability_types": vuln.get('type', []),
                "description": self._get_csrf_description(vuln),
                "token_present": vuln.get('token_present', False),
                "token_strength": vuln.get('token_strength', {}).get('strength', 0),
                "token_analysis": vuln.get('token_strength', {}).get('reason', 'No analysis available'),
                "header_validation": vuln.get('header_validation', {}),
                "remediation": self._get_csrf_remediation(vuln)
            }
            
            # Add PoC information if available
            if 'poc' in vuln and vuln['poc'].get('file_path'):
                finding["poc_file"] = vuln['poc'].get('file_path')
                finding["poc_description"] = vuln['poc'].get('description', 'Proof of Concept for CSRF vulnerability')
            
            formatted_findings.append(finding)
        
        return formatted_findings
    
    def _write_csrf_txt_findings(self, file, results):
        """Write CSRF findings to text report"""
        if not results:
            file.write("No CSRF vulnerabilities found.\n")
            return
        
        file.write(f"Found {len(results)} CSRF vulnerabilities:\n\n")
        
        for i, vuln in enumerate(results, 1):
            file.write(f"Vulnerability #{i}\n")
            file.write(f"URL: {vuln.get('url', 'Unknown URL')}\n")
            file.write(f"Page: {vuln.get('page_url', 'Unknown Page')}\n")
            file.write(f"Severity: {vuln.get('severity', 'Unknown')}\n")
            file.write(f"Type: {', '.join(vuln.get('type', []))}\n")
            file.write(f"Description: {self._get_csrf_description(vuln)}\n")
            
            # Token information
            file.write(f"Token Present: {'Yes' if vuln.get('token_present', False) else 'No'}\n")
            if vuln.get('token_present', False):
                file.write(f"Token Strength: {vuln.get('token_strength', {}).get('strength', 0)}\n")
                file.write(f"Token Analysis: {vuln.get('token_strength', {}).get('reason', 'No analysis available')}\n")
            
            # Header validation
            header_validation = vuln.get('header_validation', {})
            file.write(f"Origin Validation: {'Yes' if header_validation.get('origin_validation', False) else 'No'}\n")
            file.write(f"Referer Validation: {'Yes' if header_validation.get('referer_validation', False) else 'No'}\n")
            
            # Remediation
            file.write(f"Remediation: {self._get_csrf_remediation(vuln)}\n")
            
            # PoC information
            if 'poc' in vuln and vuln['poc'].get('file_path'):
                file.write(f"Proof of Concept: {vuln['poc'].get('file_path')}\n")
                file.write(f"PoC Description: {vuln['poc'].get('description', 'Proof of Concept for CSRF vulnerability')}\n")
            
            file.write("\n")
    
    def _format_csrf_html_findings(self, results):
        """Format CSRF findings for HTML report"""
        if not results:
            return "<p>No CSRF vulnerabilities found.</p>"
        
        html_content = f"<p>Found {len(results)} CSRF vulnerabilities:</p>"
        
        for i, vuln in enumerate(results, 1):
            severity_class = "high" if vuln.get('severity') == "High" else "medium" if vuln.get('severity') == "Medium" else "low"
            
            html_content += f"""
            <div class="vulnerability">
                <h3>Vulnerability #{i} - <span class="{severity_class}">{vuln.get('severity', 'Unknown')} Severity</span></h3>
                <table>
                    <tr><th>URL</th><td>{vuln.get('url', 'Unknown URL')}</td></tr>
                    <tr><th>Page</th><td>{vuln.get('page_url', 'Unknown Page')}</td></tr>
                    <tr><th>Type</th><td>{', '.join(vuln.get('type', []))}</td></tr>
                    <tr><th>Description</th><td>{self._get_csrf_description(vuln)}</td></tr>
                    <tr><th>Token Present</th><td>{'Yes' if vuln.get('token_present', False) else 'No'}</td></tr>
            """
            
            if vuln.get('token_present', False):
                html_content += f"""
                    <tr><th>Token Strength</th><td>{vuln.get('token_strength', {}).get('strength', 0)}</td></tr>
                    <tr><th>Token Analysis</th><td>{vuln.get('token_strength', {}).get('reason', 'No analysis available')}</td></tr>
                """
            
            # Header validation
            header_validation = vuln.get('header_validation', {})
            html_content += f"""
                    <tr><th>Origin Validation</th><td>{'Yes' if header_validation.get('origin_validation', False) else 'No'}</td></tr>
                    <tr><th>Referer Validation</th><td>{'Yes' if header_validation.get('referer_validation', False) else 'No'}</td></tr>
                    <tr><th>Remediation</th><td>{self._get_csrf_remediation(vuln)}</td></tr>
            """
            
            # PoC information
            if 'poc' in vuln and vuln['poc'].get('file_path'):
                html_content += f"""
                    <tr><th>Proof of Concept</th><td><a href="file://{vuln['poc'].get('file_path')}">{os.path.basename(vuln['poc'].get('file_path'))}</a></td></tr>
                    <tr><th>PoC Description</th><td>{vuln['poc'].get('description', 'Proof of Concept for CSRF vulnerability')}</td></tr>
                """
            
            html_content += """
                </table>
            </div>
            """
        
        return html_content
    
    def _get_csrf_description(self, vuln):
        """Generate a description for the CSRF vulnerability"""
        descriptions = {
            'missing-token': "The form does not contain a CSRF token, making it vulnerable to Cross-Site Request Forgery attacks.",
            'weak-token': "The form contains a CSRF token, but it appears to be weak or predictable.",
            'forgery-possible': "A simulated CSRF attack was successful against this form.",
            'origin-bypass': "The application does not validate Origin or Referer headers, which could be used as an additional layer of CSRF protection."
        }
        
        vuln_types = vuln.get('type', [])
        if not vuln_types:
            return "The form is vulnerable to Cross-Site Request Forgery attacks."
        
        description = ""
        for vuln_type in vuln_types:
            if vuln_type in descriptions:
                description += descriptions[vuln_type] + " "
        
        return description.strip()
    
    def _get_csrf_remediation(self, vuln):
        """Generate remediation advice for the CSRF vulnerability"""
        remediation = "To protect against CSRF attacks, implement the following measures:\n"
        
        vuln_types = vuln.get('type', [])
        
        if 'missing-token' in vuln_types:
            remediation += "- Add a strong, unpredictable CSRF token to all forms and validate it on form submission.\n"
        
        if 'weak-token' in vuln_types:
            remediation += "- Improve the randomness and unpredictability of your CSRF tokens.\n"
        
        if 'origin-bypass' in vuln_types:
            remediation += "- Implement Origin and Referer header validation as an additional layer of protection.\n"
        
        remediation += "- Consider using the SameSite cookie attribute to restrict cookie usage in cross-site requests.\n"
        remediation += "- Implement proper Content-Type headers and validate them on the server side.\n"
        
        return remediation