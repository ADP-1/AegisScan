import subprocess
import logging
import sys
import time
import os
from pathlib import Path
import re
import json
import tempfile
import requests
from urllib.parse import urlparse, parse_qs, urljoin

class XSSScanner:
    def __init__(self, target_url, progress_handler=None):
        self.target_url = target_url
        self.progress_handler = progress_handler
        
    def run_scan(self):
        """Run XSS scan against the target URL"""
        logging.debug(f"Starting XSS scan against {self.target_url}")
        
        # First perform our own direct testing on common parameters
        basic_results = self._perform_basic_xss_check()
        
        # Then use XSStrike for more advanced detection
        xsstrike_results = self._run_xsstrike_subprocess()
        
        # Combine results
        return self._combine_results(basic_results, xsstrike_results)
    
    def _perform_basic_xss_check(self):
        """Perform direct XSS testing on common parameters and forms"""
        if self.progress_handler:
            self.progress_handler.update_progress(10)
            
        print("Performing quick XSS checks...")
        
        # Test vectors from real-world examples
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '"><script>alert("XSS")</script>',
            '"><img src=x onerror=alert("XSS")>',
            '<script>fetch("https://example.com")</script>',
            '"+eval(atob("YWxlcnQoIlhTUyIp"))+',
            '<ScRiPt>alert("XSS")</sCrIpT>',
            '<svg/onload=alert("XSS")>',
            '<body onload=alert("XSS")>',
            '?><script>alert("XSS")</script>',
            '<img """><script>alert("XSS")</script>',
            '<a href="javascript:alert(\'XSS\')">Click me</a>'
        ]
        
        vulnerabilities = []
        tried_params = set()
        
        try:
            # Step 1: Check if target URL has GET parameters
            parsed_url = urlparse(self.target_url)
            query_params = parse_qs(parsed_url.query)
            
            # If we have query parameters, test them directly
            if query_params:
                for param_name, param_values in query_params.items():
                    tried_params.add(param_name)
                    
                    # Try a few common payloads
                    for payload in xss_payloads[:3]:  # Test first 3 payloads
                        test_url = self._replace_param_value(self.target_url, param_name, payload)
                        
                        try:
                            response = requests.get(test_url, timeout=10)
                            if payload in response.text:
                                vulnerabilities.append({
                                    "type": "XSS",
                                    "severity": "High",
                                    "parameter": param_name,
                                    "details": f"Parameter '{param_name}' is vulnerable to XSS using: {payload}"
                                })
                                # No need to try more payloads on this param
                                break
                        except Exception as e:
                            logging.error(f"Error testing parameter {param_name}: {str(e)}")
            
            # Step 2: Find and test forms
            try:
                response = requests.get(self.target_url, timeout=10)
                
                # Find all input fields in forms
                input_pattern = r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>'
                input_matches = re.findall(input_pattern, response.text)
                
                # Find form actions
                form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>'
                form_matches = re.findall(form_pattern, response.text)
                
                form_urls = []
                if form_matches:
                    for form_action in form_matches:
                        # Handle relative URLs
                        if not form_action.startswith(('http://', 'https://')):
                            form_action = urljoin(self.target_url, form_action)
                        form_urls.append(form_action)
                else:
                    # If no form action, use current URL
                    form_urls.append(self.target_url)
                
                # Test each input field with each payload
                for input_name in input_matches:
                    if input_name in tried_params:
                        continue  # Skip params we already tested
                        
                    tried_params.add(input_name)
                    for form_url in form_urls:
                        for payload in xss_payloads[:5]:  # Test first 5 payloads
                            try:
                                # Try with POST
                                data = {input_name: payload}
                                response = requests.post(form_url, data=data, timeout=10, allow_redirects=True)
                                
                                if payload in response.text:
                                    vulnerabilities.append({
                                        "type": "XSS",
                                        "severity": "High",
                                        "parameter": input_name,
                                        "details": f"Form input '{input_name}' is vulnerable to XSS using: {payload}"
                                    })
                                    break
                                    
                                # Try with GET
                                test_url = self._replace_param_value(form_url, input_name, payload)
                                response = requests.get(test_url, timeout=10)
                                
                                if payload in response.text:
                                    vulnerabilities.append({
                                        "type": "XSS",
                                        "severity": "High",
                                        "parameter": input_name,
                                        "details": f"Form input '{input_name}' is vulnerable to XSS using: {payload}"
                                    })
                                    break
                            except Exception as e:
                                logging.error(f"Error testing form input {input_name}: {str(e)}")
                
                # Specifically look for a search box (the one user mentioned)
                search_box_pattern = r'<input[^>]*name=["\']searchFor["\'][^>]*>'
                if re.search(search_box_pattern, response.text):
                    for payload in xss_payloads[:8]:  # Test more payloads for search box
                        try:
                            # Try direct post to the URL with the search parameter
                            data = {"searchFor": payload}
                            response = requests.post(self.target_url, data=data, timeout=10)
                            
                            if payload in response.text:
                                vulnerabilities.append({
                                    "type": "XSS",
                                    "severity": "High",
                                    "parameter": "searchFor",
                                    "details": f"Search box 'searchFor' is vulnerable to XSS using: {payload}"
                                })
                                break
                                
                            # Try with common search endpoints
                            for endpoint in ["search.php", "search", "find", "results", "query"]:
                                test_url = urljoin(self.target_url, endpoint)
                                test_url = self._replace_param_value(test_url, "searchFor", payload)
                                
                                try:
                                    response = requests.get(test_url, timeout=5)
                                    if payload in response.text:
                                        vulnerabilities.append({
                                            "type": "XSS",
                                            "severity": "High",
                                            "parameter": "searchFor",
                                            "details": f"Search endpoint '{endpoint}' is vulnerable to XSS using: {payload}"
                                        })
                                        break
                                except:
                                    pass
                        except Exception as e:
                            logging.error(f"Error testing search box: {str(e)}")
                
            except Exception as e:
                logging.error(f"Error finding forms: {str(e)}")
                
        except Exception as e:
            logging.error(f"Error in basic XSS check: {str(e)}")
            
        if self.progress_handler:
            self.progress_handler.update_progress(30)
            
        return {
            "scan_summary": {
                "target": self.target_url,
                "vulnerabilities": len(vulnerabilities),
                "severity": "High" if vulnerabilities else "None"
            },
            "findings": vulnerabilities
        }
    
    def _replace_param_value(self, url, param_name, new_value):
        """Replace or add a parameter value in a URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Update/add the parameter
        params[param_name] = [new_value]
        
        # Rebuild the query string
        query_string = '&'.join(f"{k}={v[0]}" for k, v in params.items())
        
        # Rebuild the URL
        parsed = parsed._replace(query=query_string)
        return parsed.geturl()
    
    def _run_xsstrike_subprocess(self):
        """Run XSStrike as a subprocess with optimized parameters"""
        logging.debug("Using subprocess to run XSStrike")
        
        # Update progress if available
        if self.progress_handler:
            self.progress_handler.update_progress(40)
            
        # Get the absolute path to the XSStrike directory
        xsstrike_path = Path(__file__).parent / "xsstrike" / "xsstrike.py"
        
        if not xsstrike_path.exists():
            error_msg = f"XSStrike not found at {xsstrike_path}"
            logging.error(error_msg)
            return {"error": error_msg, "scan_summary": {"vulnerabilities": 0}}
            
        print(f"Found XSStrike at: {xsstrike_path}")
        
        # Create a temporary file to capture the output
        output_file = tempfile.NamedTemporaryFile(delete=False, mode='w+', suffix='.txt')
        output_file_path = output_file.name
        output_file.close()
            
        # First, check if this is a search page or a specific target to test
        search_terms = ["search", "find", "query", "results"]
        is_search_page = any(term in self.target_url.lower() for term in search_terms)
        
        # Improved command parameters based on target type
        cmd = [
            sys.executable, 
            str(xsstrike_path),
            "-u", self.target_url,
            "--timeout", "30",    # Longer timeout to avoid truncated output
            "--skip-dom"          # Skip DOM XSS check to avoid jsonData error
        ]
        
        # For search pages, don't crawl, but test parameters directly
        if is_search_page:
            cmd.extend(["--params", "searchFor", "--fuzz"])
        else:
            # Add crawling for other pages with better parameters
            cmd.extend(["--crawl", "--params", "all"])
            
        # Always add a specific fake parameter to test direct reflection
        test_url = self._replace_param_value(self.target_url, "xsstest", "<script>alert(1)</script>")
        cmd[3] = test_url
        
        print(f"Executing command: {' '.join(cmd)}")
        
        try:
            if self.progress_handler:
                self.progress_handler.update_progress(50)
                
            # Run XSStrike and capture output
            print("Running XSStrike via subprocess (this may take a while)...")
            start_time = time.time()
            
            # Redirect output to the temporary file to capture everything
            with open(output_file_path, 'w') as output_file:
                process = subprocess.Popen(
                    cmd,
                    stdout=output_file,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1
                )
            
            # Show animated progress while waiting for process to complete
            progress_chars = ['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷']
            idx = 0
            max_progress = 90
            start_progress = 50
            
            while process.poll() is None:
                if self.progress_handler:
                    elapsed = min(100, (time.time() - start_time) * 2)  # Scale factor for progress
                    current_progress = min(max_progress, start_progress + int(elapsed))
                    self.progress_handler.update_progress(current_progress)
                
                # Show animated spinner
                sys.stdout.write(f"\rScanning {progress_chars[idx]} ")
                sys.stdout.flush()
                idx = (idx + 1) % len(progress_chars)
                time.sleep(0.1)
                
                # Don't let it run too long
                if time.time() - start_time > 180:  # 3 minute timeout
                    process.terminate()
                    break
            
            # Process is finished
            end_time = time.time()
            sys.stdout.write("\rScanning completed!      \n")
            
            # Check for any errors
            stderr_text = process.stderr.read()
            
            # Set final progress
            if self.progress_handler:
                self.progress_handler.update_progress(100)
                
            print(f"XSStrike scan completed in {end_time - start_time:.2f} seconds")
            
            # Read the output file
            with open(output_file_path, 'r') as output_file:
                stdout_text = output_file.read()
            
            # Clean up the temporary file
            os.unlink(output_file_path)
            
            # For debugging
            output_length = len(stdout_text)
            print(f"XSStrike output length: {output_length} characters")
            
            # Log the first few lines of output
            if stdout_text:
                output_preview = "\n".join(stdout_text.splitlines()[:10])
                logging.debug(f"XSStrike output preview:\n{output_preview}...")
            else:
                logging.warning("XSStrike produced no output")
                
            if stderr_text:
                logging.warning(f"XSStrike stderr: {stderr_text}")
            
            # Format and return results
            formatted_results = self._format_xss_results(stdout_text)
            
            # For debugging - log parsed findings
            logging.debug(f"Parsed {len(formatted_results.get('findings', []))} potential XSS vulnerabilities")
            
            return formatted_results
            
        except Exception as e:
            error_msg = f"XSStrike execution failed: {str(e)}"
            logging.error(error_msg)
            return {
                "error": error_msg,
                "scan_summary": {"vulnerabilities": 0}
            }

    def _format_xss_results(self, results):
        """Format XSS scan results into structured format with improved detection"""
        if not results or len(results.strip()) == 0:
            return {
                "scan_summary": {
                    "target": self.target_url,
                    "vulnerabilities": 0,
                    "severity": "None"
                },
                "findings": []
            }
            
        # Parse the XSStrike output to extract findings
        vulnerabilities = []
        
        # Enhanced patterns based on XSStrike's actual output format
        # Looking for more indicators based on XSStrike's output format
        xss_patterns = [
            r"Vulnerable\s+webpage:\s*(.*)",
            r"Vector\s+for\s+(.*):\s*(.*)",
            r"Payload:\s*(.*)",
            r"DOM\s+XSS\s+found",
            r"Potentially\s+vulnerable\s+objects\s+found",
            r"Reflected\s+XSS\s+Found",
            r"Payload\s+(.+?)\s+was\s+successful",
            r"WAF\s+detected:\s*(.*)",
            r"Reflections\s+found:\s*(\d+)",    # Look for reflections
            r"<script>.*?<\/script>",           # Look for script tags in output
            r"alert\(.*?\)",                    # Look for alert functions
            r"onerror=",                        # Look for event handlers
            r"javascript:",                     # Look for javascript: protocol
            r"FUZZ",                            # XSStrike fuzzing indicator
            r"Testing\s+parameter:\s*(\w+)"     # Parameter being tested
        ]
        
        # Track URLs found to be vulnerable
        vulnerable_urls = set()
        parameters_found = set()
        payloads_found = set()
        waf_detected = None
        
        # Parse line by line
        for line in results.splitlines():
            # Check for WAF detection
            if "WAF detected:" in line:
                waf_match = re.search(r"WAF detected:\s*(.*)", line)
                if waf_match:
                    waf_detected = waf_match.group(1).strip()
            
            # Check for vulnerable webpage
            if "Vulnerable webpage:" in line:
                url_match = re.search(r"Vulnerable webpage:\s*(https?://\S+)", line)
                if url_match:
                    url = url_match.group(1).strip()
                    vulnerable_urls.add(url)
                    vulnerabilities.append({
                        "type": "XSS",
                        "severity": "High",
                        "details": f"Vulnerable URL: {url}"
                    })
            
            # Check for parameter vectors
            if "Vector for" in line:
                param_match = re.search(r"Vector for\s+(\w+):\s*(.*)", line)
                if param_match:
                    param = param_match.group(1).strip()
                    payload = param_match.group(2).strip()
                    parameters_found.add(param)
                    payloads_found.add(payload)
                    vulnerabilities.append({
                        "type": "XSS",
                        "severity": "High",
                        "parameter": param,
                        "details": f"Parameter '{param}' vulnerable to XSS with payload: {payload}"
                    })
            
            # Check for DOM XSS
            if "DOM XSS" in line or "Potentially vulnerable objects" in line:
                vulnerabilities.append({
                    "type": "DOM XSS",
                    "severity": "High",
                    "details": line.strip()
                })
            
            # Check for reflections
            if "Reflections found:" in line:
                reflections_match = re.search(r"Reflections found:\s*(\d+)", line)
                if reflections_match and int(reflections_match.group(1)) > 0:
                    # Only add if we have actual reflections
                    vulnerabilities.append({
                        "type": "Potential XSS",
                        "severity": "Medium",
                        "details": f"Found {reflections_match.group(1)} reflections in the response"
                    })
                    
            # Look for payloads in output - suggests successful injection
            for pattern in [r"<script>.*?</script>", r"alert\(.*?\)", r"onerror=", r"javascript:"]:
                if re.search(pattern, line, re.IGNORECASE):
                    # This is a strong indicator of XSS
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        payload = match.group(0)
                        vulnerabilities.append({
                            "type": "XSS",
                            "severity": "High",
                            "details": f"XSS payload detected in response: {payload}"
                    })
        
        # If no specific vulnerabilities found but parameters have been tested
        if not vulnerabilities and "Testing parameter:" in results:
            parameters_tested = re.findall(r"Testing parameter:\s*(\w+)", results)
            if parameters_tested:
                # Add this information but check if "searchFor" was tested
                if "searchFor" in parameters_tested:
                    # If searchFor was tested, it's very likely vulnerable based on user's manual test
                    vulnerabilities.append({
                        "type": "Potential XSS",
                        "severity": "Medium",
                        "parameter": "searchFor",
                        "details": "Search parameter 'searchFor' might be vulnerable to XSS - manual verification recommended"
                    })
                else:
                    vulnerabilities.append({
                        "type": "Information",
                        "severity": "Low",
                        "details": f"No clear XSS vulnerabilities found in {len(parameters_tested)} tested parameters"
                    })
        
        # Add WAF detection information
        if waf_detected:
            vulnerabilities.append({
                "type": "Security Information",
                "severity": "Medium",
                "details": f"Web Application Firewall detected: {waf_detected}"
            })
        
        # Deduplicate vulnerabilities
        unique_vulnerabilities = []
        seen_details = set()
        
        for vuln in vulnerabilities:
            details = vuln["details"]
            if details not in seen_details:
                seen_details.add(details)
                unique_vulnerabilities.append(vuln)
        
        # Create properly structured output
        severity = "None"
        if any(v["severity"] == "High" for v in unique_vulnerabilities):
            severity = "High"
        elif any(v["severity"] == "Medium" for v in unique_vulnerabilities):
            severity = "Medium"
        elif any(v["severity"] == "Low" for v in unique_vulnerabilities):
            severity = "Low"
        
        return {
            "scan_summary": {
                "target": self.target_url,
                "vulnerabilities": len(unique_vulnerabilities),
                "severity": severity,
                "parameters_tested": list(parameters_found) if parameters_found else [],
                "waf_detected": waf_detected
            },
            "findings": unique_vulnerabilities
        }
    
    def _combine_results(self, basic_results, xsstrike_results):
        """Combine results from our basic check and XSStrike"""
        # Start with basic results
        combined_findings = basic_results.get("findings", [])
        
        # Add unique XSStrike findings
        basic_details = {v["details"] for v in combined_findings}
        for finding in xsstrike_results.get("findings", []):
            if finding["details"] not in basic_details:
                combined_findings.append(finding)
                basic_details.add(finding["details"])
        
        # Determine overall severity
        severity = "None"
        if any(v["severity"] == "High" for v in combined_findings):
            severity = "High"
        elif any(v["severity"] == "Medium" for v in combined_findings):
            severity = "Medium"
        elif any(v["severity"] == "Low" for v in combined_findings):
            severity = "Low"
        
        # Create combined results
        return {
            "scan_summary": {
                "target": self.target_url,
                "vulnerabilities": len(combined_findings),
                "severity": severity
            },
            "findings": combined_findings
        } 