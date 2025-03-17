class ReportGenerator:
    def __init__(self):
        self.supported_formats = ['txt', 'json', 'html']

    def generate(self, format_type='txt', results=None):
        """Generate a report in the specified format"""
        if not results:
            return "No results to report"
            
        if format_type not in self.supported_formats:
            format_type = 'txt'  # Default to text format
            
        if format_type == 'txt':
            return self._generate_text_report(results)
        elif format_type == 'json':
            return self._generate_json_report(results)
        elif format_type == 'html':
            return self._generate_html_report(results)
    
    def _generate_text_report(self, results):
        """Generate a text-based report"""
        report = f"""
AEGISSCAN SECURITY REPORT
========================
Target: {results['target']}

VULNERABILITIES FOUND:
---------------------"""

        for vuln_type, findings in results['vulnerabilities'].items():
            report += f"\n\n{vuln_type} Vulnerabilities:"
            if not findings:
                report += "\n  None found"
            for finding in findings:
                report += f"\n  - Parameter: {finding.get('parameter', 'N/A')}"
                report += f"\n    Type: {finding.get('type', 'N/A')}"
                
        return report

    def _generate_json_report(self, results):
        """Generate a JSON report"""
        import json
        return json.dumps(results, indent=2)

    def _generate_html_report(self, results):
        """Generate an HTML report"""
        html = """
        <html>
        <head>
            <title>AegisScan Security Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                h1 { color: #2c3e50; }
                .vulnerability { margin: 10px 0; padding: 10px; border: 1px solid #ddd; }
                .critical { border-left: 5px solid #e74c3c; }
                .high { border-left: 5px solid #e67e22; }
                .medium { border-left: 5px solid #f1c40f; }
                .low { border-left: 5px solid #2ecc71; }
            </style>
        </head>
        <body>
        """
        
        html += f"<h1>Security Scan Report</h1>"
        html += f"<h2>Target: {results['target']}</h2>"
        
        for vuln_type, findings in results['vulnerabilities'].items():
            html += f"<h3>{vuln_type} Findings:</h3>"
            if not findings:
                html += "<p>No vulnerabilities found</p>"
            for finding in findings:
                html += f"""
                <div class="vulnerability critical">
                    <h4>Parameter: {finding.get('parameter', 'N/A')}</h4>
                    <p>Type: {finding.get('type', 'N/A')}</p>
                </div>
                """
        
        html += "</body></html>"
        return html 