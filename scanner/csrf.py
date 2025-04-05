import re
import time
import requests
from bs4 import BeautifulSoup
import math
import random
import string
import urllib.parse
import os
from colorama import Fore, Style
from concurrent.futures import ThreadPoolExecutor
import logging

class CSRFScanner:
    """Scanner for detecting Cross-Site Request Forgery vulnerabilities"""
    
    def __init__(self, target_url, cookies=None, config=None, progress_handler=None, depth=3):
        self.target_url = target_url
        self.cookies = cookies or {}
        self.config = config or {}
        self.progress_handler = progress_handler
        self.depth = depth
        self.visited_urls = set()
        self.forms_found = []
        self.vulnerabilities = []
        self.start_time = None
        self.end_time = None
        self.current_phase = "Initialization"
        self.status_message = "Initializing CSRF scanner..."
        
        # Default token patterns (can be overridden via config)
        self.token_patterns = self.config.get('token_patterns', [
            'csrf', '_csrf', 'csrf_token', 'csrftoken', 'xsrf', '_token', 
            'token', 'authenticity_token', 'anti-csrf', 'request_token',
            'csrfmiddlewaretoken', '__RequestVerificationToken'
        ])
        
        # Configure scan depth
        self.max_depth = self.config.get('depth', self.depth)
        self.max_forms = self.config.get('max_forms', 50)
        self.randomness_threshold = self.config.get('randomness_threshold', 0.7)
        self.num_token_samples = self.config.get('token_samples', 5)
        self.threads = self.config.get('threads', 5)
        
        # User agent for requests
        self.headers = {
            'User-Agent': 'AegisScan CSRF Scanner/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml',
            'Accept-Language': 'en-US,en;q=0.9',
        }
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('CSRFScanner')
    
    def update_status(self, message, phase=None, progress=None):
        """Update the current status message and optionally the phase"""
        self.status_message = message
        if phase:
            self.current_phase = phase
            
        # Update progress handler if available
        if self.progress_handler and progress is not None:
            self.progress_handler.update_progress(progress)
        
        # Print status
        print(f"{Fore.CYAN}[*] {message}{Style.RESET_ALL}")
        self.logger.info(message)
    
    def crawl(self):
        """Crawl the target website to discover forms"""
        self.update_status(f"Starting crawl of {self.target_url}", "Crawling", 10)
        
        # Start with the target URL
        urls_to_visit = [self.target_url]
        self.visited_urls = set()
        
        # Track depth
        current_depth = 0
        
        while urls_to_visit and current_depth < self.max_depth:
            current_depth += 1
            next_urls = []
            
            self.update_status(f"Crawling depth {current_depth}/{self.max_depth}", "Crawling", 
                              10 + (current_depth / self.max_depth) * 20)
            
            # Use ThreadPoolExecutor for parallel processing
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                # Process each URL in the current depth level
                results = list(executor.map(self._process_url, urls_to_visit))
                
                # Collect new URLs and forms
                for new_urls, forms in results:
                    next_urls.extend(new_urls)
                    self.forms_found.extend(forms)
            
            # Update URLs to visit for next depth level
            urls_to_visit = [url for url in next_urls if url not in self.visited_urls]
            
            # Limit the number of URLs to process
            if len(urls_to_visit) > 100:
                urls_to_visit = urls_to_visit[:100]
                self.update_status(f"Limiting crawl to 100 URLs at depth {current_depth}", "Crawling")
        
        self.update_status(f"Crawl completed. Found {len(self.forms_found)} forms across {len(self.visited_urls)} pages.", 
                          "Form Analysis", 30)
        return self.forms_found
    
    def _process_url(self, url):
        """Process a single URL: fetch, extract forms, and find links"""
        if url in self.visited_urls:
            return [], []
        
        self.visited_urls.add(url)
        new_urls = []
        forms = []
        
        try:
            response = requests.get(url, headers=self.headers, cookies=self.cookies, timeout=10)
            if response.status_code == 200 and 'text/html' in response.headers.get('Content-Type', ''):
                # Extract forms
                page_forms = self.extract_forms(response.text)
                for form in page_forms:
                    form['page_url'] = url
                forms.extend(page_forms)
                
                # Extract links for further crawling
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    # Resolve relative URLs
                    full_url = urllib.parse.urljoin(url, href)
                    # Only include URLs from the same domain
                    if self._is_same_domain(full_url, self.target_url) and full_url not in self.visited_urls:
                        new_urls.append(full_url)
        except Exception as e:
            self.logger.error(f"Error processing URL {url}: {str(e)}")
        
        return new_urls, forms
    
    def _is_same_domain(self, url1, url2):
        """Check if two URLs belong to the same domain"""
        try:
            domain1 = urllib.parse.urlparse(url1).netloc
            domain2 = urllib.parse.urlparse(url2).netloc
            return domain1 == domain2
        except:
            return False
    
    def extract_forms(self, html):
        """Extract forms from HTML content"""
        forms = []
        soup = BeautifulSoup(html, 'html.parser')
        
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').lower(),
                'inputs': []
            }
            
            # Extract all input fields
            for input_field in form.find_all(['input', 'textarea', 'select']):
                input_type = input_field.get('type', '')
                if input_type.lower() in ['submit', 'button', 'image', 'reset']:
                    continue
                
                input_data = {
                    'name': input_field.get('name', ''),
                    'type': input_type,
                    'value': input_field.get('value', '')
                }
                form_data['inputs'].append(input_data)
            
            # Only include POST forms (GET forms are not typically vulnerable to CSRF)
            if form_data['method'] == 'post':
                forms.append(form_data)
        
        return forms
    
    def detect_token(self, form):
        """Check if the form contains an anti-CSRF token"""
        for input_field in form['inputs']:
            field_name = input_field.get('name', '').lower()
            
            # Check if field name matches any token pattern
            for pattern in self.token_patterns:
                if pattern.lower() in field_name:
                    return {
                        'present': True,
                        'field_name': input_field['name'],
                        'value': input_field.get('value', '')
                    }
        
        # No token found
        return {'present': False}
    
    def test_origin_referer(self, form):
        """Test if the form submission validates Origin/Referer headers"""
        form_url = urllib.parse.urljoin(form['page_url'], form['action'])
        
        # Prepare form data
        form_data = {}
        for input_field in form['inputs']:
            if input_field.get('name'):
                form_data[input_field['name']] = input_field.get('value', '')
        
        # Send a normal request with all headers
        normal_headers = self.headers.copy()
        normal_headers['Referer'] = form['page_url']
        normal_headers['Origin'] = urllib.parse.urlparse(self.target_url).scheme + '://' + urllib.parse.urlparse(self.target_url).netloc
        
        try:
            # Send normal request
            normal_response = requests.post(
                form_url, 
                data=form_data, 
                headers=normal_headers,
                cookies=self.cookies,
                timeout=10,
                allow_redirects=False
            )
            
            # Now try without Referer
            no_referer_headers = normal_headers.copy()
            del no_referer_headers['Referer']
            
            no_referer_response = requests.post(
                form_url, 
                data=form_data, 
                headers=no_referer_headers,
                cookies=self.cookies,
                timeout=10,
                allow_redirects=False
            )
            
            # Try with a different Origin
            bad_origin_headers = normal_headers.copy()
            bad_origin_headers['Origin'] = 'https://evil-site.com'
            
            bad_origin_response = requests.post(
                form_url, 
                data=form_data, 
                headers=bad_origin_headers,
                cookies=self.cookies,
                timeout=10,
                allow_redirects=False
            )
            
            # Compare responses
            referer_check = self._compare_responses(normal_response, no_referer_response)
            origin_check = self._compare_responses(normal_response, bad_origin_response)
            
            return {
                'referer_validation': not referer_check['similar'],
                'origin_validation': not origin_check['similar'],
                'details': {
                    'referer_check': referer_check,
                    'origin_check': origin_check
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error testing Origin/Referer for {form_url}: {str(e)}")
            return {
                'referer_validation': False,
                'origin_validation': False,
                'error': str(e)
            }
    
    def _compare_responses(self, resp1, resp2):
        """Compare two responses to determine if they're similar"""
        # Check status codes
        if resp1.status_code != resp2.status_code:
            return {
                'similar': False,
                'reason': f"Different status codes: {resp1.status_code} vs {resp2.status_code}"
            }
        
        # For redirects, check if they redirect to the same place
        if resp1.status_code in [301, 302, 303, 307, 308]:
            if resp1.headers.get('Location') != resp2.headers.get('Location'):
                return {
                    'similar': False,
                    'reason': f"Different redirect locations: {resp1.headers.get('Location')} vs {resp2.headers.get('Location')}"
                }
        
        # For success responses, compare content length (simple heuristic)
        if abs(len(resp1.content) - len(resp2.content)) > 100:
            return {
                'similar': False,
                'reason': f"Content length differs significantly: {len(resp1.content)} vs {len(resp2.content)}"
            }
        
        # If we get here, responses are similar
        return {'similar': True}
    
    def analyze_token_strength(self, form):
        """Analyze the strength of CSRF tokens by collecting multiple samples"""
        token_info = self.detect_token(form)
        if not token_info['present']:
            return {'strength': 0, 'reason': 'No token present'}
        
        token_field = token_info['field_name']
        form_url = urllib.parse.urljoin(form['page_url'], form['action'])
        page_url = form['page_url']
        
        # Collect multiple tokens
        tokens = []
        for _ in range(self.num_token_samples):
            try:
                # Get the page to obtain a fresh token
                response = requests.get(page_url, headers=self.headers, cookies=self.cookies, timeout=10)
                if response.status_code == 200:
                    page_forms = self.extract_forms(response.text)
                    for page_form in page_forms:
                        if page_form['action'] == form['action']:
                            token_data = self.detect_token(page_form)
                            if token_data['present'] and token_data['field_name'] == token_field:
                                tokens.append(token_data['value'])
                                break
            except Exception as e:
                self.logger.error(f"Error collecting token sample: {str(e)}")
            
            # Small delay between requests
            time.sleep(0.5)
        
        # Analyze token uniqueness and entropy
        if len(tokens) < 2:
            return {'strength': 0.5, 'reason': 'Could not collect enough token samples'}
        
        # Check uniqueness
        unique_tokens = len(set(tokens))
        uniqueness_ratio = unique_tokens / len(tokens)
        
        # Calculate entropy
        entropy = self._calculate_entropy(tokens[0]) if tokens else 0
        
        # Determine strength based on uniqueness and entropy
        if uniqueness_ratio == 1.0 and entropy > 3.0:
            strength = 1.0  # Strong
            reason = 'Tokens are unique and have high entropy'
        elif uniqueness_ratio > 0.7:
            strength = 0.7  # Medium
            reason = 'Tokens have good uniqueness but may have lower entropy'
        else:
            strength = 0.3  # Weak
            reason = 'Tokens are predictable or repeat frequently'
        
        return {
            'strength': strength,
            'uniqueness_ratio': uniqueness_ratio,
            'entropy': entropy,
            'reason': reason,
            'samples': len(tokens),
            'unique_samples': unique_tokens
        }
    
    def _calculate_entropy(self, token):
        """Calculate Shannon entropy of a string"""
        if not token:
            return 0
        
        entropy = 0
        for x in range(256):
            p_x = token.count(chr(x)) / len(token)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        
        return entropy
    
    def attempt_forgery(self, form):
        """Test if the form is vulnerable to CSRF by attempting to forge a submission"""
        form_url = urllib.parse.urljoin(form['page_url'], form['action'])
        
        # Prepare form data
        form_data = {}
        for input_field in form['inputs']:
            if input_field.get('name'):
                # Use a dummy value for text fields
                if input_field.get('type') in ['text', 'email', 'password']:
                    form_data[input_field['name']] = 'test_value'
                else:
                    form_data[input_field['name']] = input_field.get('value', '')
        
        # Detect token
        token_info = self.detect_token(form)
        
        # Test 1: Submit without the token
        if token_info['present']:
            test_data = form_data.copy()
            del test_data[token_info['field_name']]
            
            try:
                no_token_response = requests.post(
                    form_url,
                    data=test_data,
                    headers=self.headers,
                    cookies=self.cookies,
                    timeout=10,
                    allow_redirects=False
                )
                
                # Test 2: Submit with an invalid token
                test_data = form_data.copy()
                test_data[token_info['field_name']] = 'invalid_token_value'
                
                invalid_token_response = requests.post(
                    form_url,
                    data=test_data,
                    headers=self.headers,
                    cookies=self.cookies,
                    timeout=10,
                    allow_redirects=False
                )
                
                # Compare responses to a normal submission
                normal_response = requests.post(
                    form_url,
                    data=form_data,
                    headers=self.headers,
                    cookies=self.cookies,
                    timeout=10,
                    allow_redirects=False
                )
                
                no_token_check = self._compare_responses(normal_response, no_token_response)
                invalid_token_check = self._compare_responses(normal_response, invalid_token_response)
                
                return {
                    'vulnerable_no_token': no_token_check['similar'],
                    'vulnerable_invalid_token': invalid_token_check['similar'],
                    'details': {
                        'no_token': no_token_check,
                        'invalid_token': invalid_token_check
                    }
                }
                
            except Exception as e:
                self.logger.error(f"Error testing forgery for {form_url}: {str(e)}")
                return {'error': str(e)}
        else:
            # No token to begin with, try a basic submission
            try:
                response = requests.post(
                    form_url,
                    data=form_data,
                    headers=self.headers,
                    cookies=self.cookies,
                    timeout=10,
                    allow_redirects=False
                )
                
                # If submission succeeds without a token, it's vulnerable
                return {
                    'vulnerable_no_token': response.status_code < 400,
                    'details': {
                        'status_code': response.status_code
                    }
                }
                
            except Exception as e:
                self.logger.error(f"Error testing forgery for {form_url}: {str(e)}")
                return {'error': str(e)}
    
    def generate_poc(self, finding):
        """Generate a proof-of-concept HTML page for the CSRF vulnerability"""
        form = finding['form']
        form_url = urllib.parse.urljoin(form['page_url'], form['action'])
        
        # Create a simple HTML form that auto-submits
        poc_html = f"""<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC for {form_url}</title>
    <meta charset="UTF-8">
</head>
<body>
    <h1>CSRF Proof of Concept</h1>
    <p>This form will automatically submit to {form_url} when the page loads.</p>
    <form id="csrf-form" action="{form_url}" method="POST">
"""
        
        # Add form fields
        for input_field in form['inputs']:
            if input_field.get('name'):
                # Skip the CSRF token if present
                token_info = self.detect_token(form)
                if token_info['present'] and input_field['name'] == token_info['field_name']:
                    continue
                
                # Use dummy values for text fields
                if input_field.get('type') in ['text', 'email', 'password']:
                    value = 'csrf_test_value'
                else:
                    value = input_field.get('value', '')
                
                poc_html += f'        <input type="hidden" name="{input_field["name"]}" value="{value}">\n'
        
        # Add auto-submit script
        poc_html += """    </form>
    <script>
        window.onload = function() {
            document.getElementById("csrf-form").submit();
        }
    </script>
</body>
</html>"""
        
        # Save the PoC to a file
        poc_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'reports', 'csrf_poc')
        os.makedirs(poc_dir, exist_ok=True)
        
        # Create a filename based on the URL
        filename = f"csrf_poc_{urllib.parse.quote_plus(form_url)}.html"
        filepath = os.path.join(poc_dir, filename)
        
        with open(filepath, 'w') as f:
            f.write(poc_html)
        
        return {
            'html': poc_html,
            'filepath': filepath,
            'filename': filename
        }
    
    def scan(self):
        """Main scanning method that orchestrates the CSRF testing process"""
        self.start_time = time.time()
        self.vulnerabilities = []
        
        try:
            # Step 1: Crawl the website to find forms
            self.update_status("Starting CSRF scan", "Initialization", 5)
            forms = self.crawl()
            
            if not forms:
                self.update_status("No forms found during crawl", "Completed", 100)
                self.end_time = time.time()
                return []
            
            # Step 2: Analyze each form for CSRF vulnerabilities
            self.update_status(f"Analyzing {len(forms)} forms for CSRF vulnerabilities", "Form Analysis", 30)
            
            for i, form in enumerate(forms):
                progress = 30 + (i / len(forms)) * 40
                self.update_status(f"Testing form {i+1}/{len(forms)}: {form.get('action', 'unknown')}", "Form Analysis", progress)
                
                # Skip forms that don't use POST method
                if form['method'] != 'post':
                    continue
                
                # Check for CSRF token
                token_info = self.detect_token(form)
                
                # Test Origin/Referer validation
                header_validation = self.test_origin_referer(form)
                
                # If token is present, analyze its strength
                token_strength = {'strength': 0, 'reason': 'No token present'}
                if token_info['present']:
                    token_strength = self.analyze_token_strength(form)
                
                # Test forgery attempts
                forgery_result = self.attempt_forgery(form)
                
                # Determine if the form is vulnerable
                is_vulnerable = False
                vulnerability_type = []
                severity = "Low"
                
                if not token_info['present'] and not (header_validation.get('referer_validation', False) or 
                                                    header_validation.get('origin_validation', False)):
                    is_vulnerable = True
                    vulnerability_type.append('missing-token')
                    severity = "High"
                
                if token_info['present'] and token_strength['strength'] < self.randomness_threshold:
                    is_vulnerable = True
                    vulnerability_type.append('weak-token')
                    severity = "Medium"
                
                if forgery_result.get('vulnerable_no_token', False) or forgery_result.get('vulnerable_invalid_token', False):
                    is_vulnerable = True
                    vulnerability_type.append('forgery-possible')
                    severity = "High"
                
                if not header_validation.get('referer_validation', False) and not header_validation.get('origin_validation', False):
                    vulnerability_type.append('origin-bypass')
                
                # If vulnerable, generate a finding
                if is_vulnerable:
                    finding = {
                        'url': urllib.parse.urljoin(form['page_url'], form['action']),
                        'page_url': form['page_url'],
                        'form': form,
                        'type': vulnerability_type,
                        'severity': severity,
                        'token_present': token_info['present'],
                        'token_strength': token_strength,
                        'header_validation': header_validation,
                        'forgery_result': forgery_result
                    }
                    
                    # Generate PoC for the vulnerability
                    poc_result = self.generate_poc(finding)
                    finding['poc'] = poc_result
                    
                    self.vulnerabilities.append(finding)
            
            self.update_status(f"CSRF scan completed. Found {len(self.vulnerabilities)} vulnerabilities.", "Completed", 100)
            self.end_time = time.time()
            return self.vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Error during CSRF scan: {str(e)}")
            self.update_status(f"Error during scan: {str(e)}", "Error", 100)
            self.end_time = time.time()
            return []
    
    def run_scan(self):
        """Compatibility method to match the interface of other scanners"""
        return self.scan()