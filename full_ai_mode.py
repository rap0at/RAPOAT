
import os
import subprocess
import configparser
import google.genai as genai
import anthropic
import time
from datetime import datetime
import threading
import queue

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
                # genai.configure(api_key=self.gemini_api_key) # Replaced due to AttributeError
                # Bypass the helper and set the key on the default client directly
                from google.generativeai import client as genai_client
                genai_client.get_default_generative_client().api_key = self.gemini_api_key
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

    def _run_ai_pentest(self, scan_results):
        """The main AI-driven attack loop."""
        self._log("--- Starting Phase 2: AI-Driven Attack ---")

        initial_prompt = f"""
You are an elite, autonomous penetration testing AI. Your goal is to find and exploit vulnerabilities in the target: {self.target}.
You will proceed step-by-step. At each step, you will be given the results of your previous action and must decide on the next one.
You must provide your response as a shell command to be executed. I will run the command and give you the output.
Example: `nmap -sV {self.domain}` or `sqlmap -u "{self.target}/vuln.php?id=1" --dbs`.
Do not provide any explanation, just the raw command. Start with analysis and enumeration.
If you believe the test is complete or you cannot proceed, respond with the single word: "COMPLETE".

Here is the initial information from Nmap, Nikto, and Nuclei scans:

--- NMAP RESULTS ---
{scan_results.get('nmap', 'Not available.')}

--- NIKTO RESULTS ---
{scan_results.get('nikto', 'Not available.')}

--- NUCLEI RESULTS ---
{scan_results.get('nuclei', 'Not available.')}

Based on these results, what is your first command?
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
            commands_to_run = {}
            while not response_queue.empty():
                ai_name, command = response_queue.get()
                if command and command.strip().upper() != "COMPLETE":
                    commands_to_run[ai_name] = command.strip()
                else:
                    self._log(f"AI model '{ai_name}' has completed its task.")

            if not commands_to_run:
                self._log("All AI models have completed their tasks or failed. Ending pentest.")
                break

            # Execute commands from AIs
            command_outputs = {}
            for ai_name, command in commands_to_run.items():
                self._log(f"Executing command from {ai_name}: {command}")
                # For safety, we should probably have a whitelist of commands, but for now, we execute as requested.
                # This is a placeholder for a more secure execution environment.
                try:
                    # We need to handle commands that might be interactive or long-running.
                    # Using a timeout is crucial.
                    process = subprocess.run(
                        command,
                        shell=True, # shell=True is risky, but needed for complex commands from AI
                        capture_output=True,
                        text=True,
                        encoding='utf-8',
                        errors='ignore',
                        timeout=300 # 5-minute timeout per command
                    )
                    output = f"--- STDOUT ---\n{process.stdout}\n--- STDERR ---\n{process.stderr}"
                    command_outputs[ai_name] = output
                    self._log(f"Output from {ai_name}'s command:\n{output}")
                except subprocess.TimeoutExpired:
                    timeout_msg = "Command timed out after 5 minutes."
                    command_outputs[ai_name] = timeout_msg
                    self._log(f"[ERROR] {timeout_msg}")
                except Exception as e:
                    error_msg = f"An error occurred executing command: {e}"
                    command_outputs[ai_name] = error_msg
                    self._log(f"[ERROR] {error_msg}")

            # Update histories and get next commands
            next_threads = []
            
            def get_next_gemini(output):
                gemini_history.extend([commands_to_run.get('gemini'), output])
                prompt = f"Your last command produced this output. What is your next command?\n\n{output}"
                response = self._get_ai_response('gemini', prompt, gemini_history)
                response_queue.put(('gemini', response))

            def get_next_claude(output):
                claude_history.extend([commands_to_run.get('claude'), output])
                prompt = f"Your last command produced this output. What is your next command?\n\n{output}"
                response = self._get_ai_response('claude', prompt, claude_history)
                response_queue.put(('claude', response))

            if 'gemini' in command_outputs:
                next_threads.append(threading.Thread(target=get_next_gemini, args=(command_outputs['gemini'],)))
            if 'claude' in command_outputs:
                next_threads.append(threading.Thread(target=get_next_claude, args=(command_outputs['claude'],)))

            for t in next_threads:
                t.start()
            for t in next_threads:
                t.join()

        self._log("--- Finished Phase 2: AI-Driven Attack ---")

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
