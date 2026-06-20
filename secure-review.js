/* ═══════════════════════════════════════════════════════════════════════════════
   SecureAudit Pro – Analysis Engine + UI Controller
   Version 2.4 | Client-side static analysis | All processing in-browser
   ═══════════════════════════════════════════════════════════════════════════════ */

'use strict';

/* ═══════════════════════════════════════════════════════════════════════════════
   VULNERABILITY DATABASE
   Each rule: { id, name, pattern(regex), severity, cwe, owasp, owaspCode,
                description, impact, remediation, secureCode, insecureCode }
   ═══════════════════════════════════════════════════════════════════════════════ */
const VULN_DB = {

  python: [
    {
      id: 'PY001', name: 'SQL Injection via String Formatting',
      pattern: /(?:\.execute|\.executemany|\.query)\s*\(\s*(?:f["']|["'][^"']*(?:%s|%d|{)|\w+\s*\+)/i,
      severity: 'critical', cwe: 'CWE-89', owasp: 'A03:2021 – Injection', owaspCode: 'injection',
      description: 'SQL queries are assembled with f-strings, % formatting, or string concatenation involving potentially user-controlled variables. An attacker can inject arbitrary SQL to read, modify, or delete data.',
      impact: 'Full database compromise, authentication bypass, data exfiltration, data destruction.',
      remediation: 'Use parameterized queries (prepared statements) exclusively. Never concatenate or format user input into SQL strings.',
      secureCode: '# Correct: parameterized query\ncursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))\n# With psycopg2:\ncursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
      insecureCode: '# Vulnerable: string concatenation / f-string\nquery = "SELECT * FROM users WHERE id = " + user_id\ncursor.execute(f"SELECT * FROM users WHERE name = \'{username}\'")',
    },
    {
      id: 'PY002', name: 'eval() – Arbitrary Code Execution',
      pattern: /\beval\s*\(/,
      severity: 'critical', cwe: 'CWE-95', owasp: 'A03:2021 – Injection', owaspCode: 'injection',
      description: 'eval() executes any Python expression passed as a string. If any part of the string is derived from user input, attackers can execute arbitrary Python code on the server.',
      impact: 'Remote code execution, complete system compromise, data theft.',
      remediation: 'Use ast.literal_eval() for safe parsing of Python literals. Restructure logic to avoid dynamic code evaluation entirely.',
      secureCode: 'import ast\n# Safe: only parses strings, bytes, numbers, tuples, lists, dicts, booleans, None\nresult = ast.literal_eval(user_input)',
      insecureCode: '# Critical: executes arbitrary Python code\nresult = eval(user_input)',
    },
    {
      id: 'PY003', name: 'exec() – Arbitrary Code Execution',
      pattern: /\bexec\s*\(/,
      severity: 'critical', cwe: 'CWE-95', owasp: 'A03:2021 – Injection', owaspCode: 'injection',
      description: 'exec() executes arbitrary Python statements. More powerful than eval(), it can run complete programs. Highly dangerous with any user-controlled input.',
      impact: 'Remote code execution, complete system compromise.',
      remediation: 'Eliminate exec() usage. Refactor dynamic logic to use dictionaries of pre-defined functions.',
      secureCode: '# Use a dispatch table instead\nops = {"add": lambda a, b: a + b, "sub": lambda a, b: a - b}\nresult = ops.get(operation, lambda *a: None)(x, y)',
      insecureCode: 'exec(f"result = {user_expression}")  # Remote code execution!',
    },
    {
      id: 'PY004', name: 'Insecure Deserialization (pickle)',
      pattern: /\bpickle\s*\.\s*loads?\s*\(/,
      severity: 'critical', cwe: 'CWE-502', owasp: 'A08:2021 – Software and Data Integrity Failures', owaspCode: 'integrity',
      description: 'pickle.load/loads can execute arbitrary Python code during deserialization. Any application that deserializes attacker-controlled pickle data is vulnerable to remote code execution.',
      impact: 'Remote code execution, privilege escalation, full system compromise.',
      remediation: 'Never deserialize pickle from untrusted sources. Use JSON (json module) or structured data formats instead.',
      secureCode: 'import json\n# Safe for untrusted data\ndata = json.loads(request_body)',
      insecureCode: 'import pickle\n# Critical: executes code during deserialization\nobj = pickle.loads(request.data)',
    },
    {
      id: 'PY005', name: 'Command Injection (subprocess shell=True)',
      pattern: /subprocess\s*\.\s*(?:call|run|Popen|check_output|check_call|getoutput|getstatusoutput)\s*\([^)]*shell\s*=\s*True/,
      severity: 'critical', cwe: 'CWE-78', owasp: 'A03:2021 – Injection', owaspCode: 'injection',
      description: 'Using shell=True with subprocess functions passes the command to /bin/sh for parsing. An attacker who controls any part of the command can use shell metacharacters (; | && ` $()) to run additional commands.',
      impact: 'Arbitrary OS command execution with application process privileges.',
      remediation: 'Use shell=False (the default) and pass arguments as a list. If shell=True is unavoidable, rigorously validate and sanitize all input with shlex.quote().',
      secureCode: '# Safe: list args, no shell\nresult = subprocess.run(["ls", "-la", safe_directory], capture_output=True, shell=False)',
      insecureCode: '# Vulnerable: shell=True with user input\nresult = subprocess.run("ls -la " + user_dir, shell=True)',
    },
    {
      id: 'PY006', name: 'Weak Hashing Algorithm (MD5 / SHA-1)',
      pattern: /hashlib\s*\.\s*(?:md5|sha1)\s*\(/,
      severity: 'high', cwe: 'CWE-327', owasp: 'A02:2021 – Cryptographic Failures', owaspCode: 'crypto',
      description: 'MD5 and SHA-1 are cryptographically broken. MD5 was broken in 2004; SHA-1 in 2017. Both are vulnerable to collision attacks and are trivially cracked for passwords using rainbow tables or GPUs.',
      impact: 'Password cracking, hash collision attacks, authentication bypass.',
      remediation: 'For passwords: use bcrypt, argon2-cffi, or scrypt. For general hashing: use hashlib.sha256() or hashlib.sha3_256().',
      secureCode: 'import bcrypt\n# Password hashing\nhashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())\n# General hashing\nimport hashlib\nhash = hashlib.sha256(data).hexdigest()',
      insecureCode: 'import hashlib\nhashed = hashlib.md5(password.encode()).hexdigest()  # Broken!',
    },
    {
      id: 'PY007', name: 'Hardcoded Credentials / API Keys',
      pattern: /(?:password|passwd|secret|api[_-]?key|auth[_-]?token|access[_-]?key|private[_-]?key)\s*=\s*["'][^"']{5,}["']/i,
      severity: 'high', cwe: 'CWE-798', owasp: 'A07:2021 – Identification and Authentication Failures', owaspCode: 'auth',
      description: 'Secrets hardcoded in source code are committed to version control and are visible to anyone with repository access (past or present). They persist in git history even after deletion.',
      impact: 'Unauthorized API access, account takeover, credential theft, financial cost (cloud services).',
      remediation: 'Store secrets in environment variables, .env files (excluded from git), or secret managers (HashiCorp Vault, AWS Secrets Manager). Use python-dotenv for local development.',
      secureCode: 'import os\nfrom dotenv import load_dotenv\nload_dotenv()\napi_key = os.environ.get("API_KEY")  # From environment',
      insecureCode: 'API_KEY = "sk-abc123def456ghi789"  # Exposed in version control!',
    },
    {
      id: 'PY008', name: 'Debug Mode Enabled in Production',
      pattern: /(?:app\.run\s*\([^)]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True)/,
      severity: 'high', cwe: 'CWE-94', owasp: 'A05:2021 – Security Misconfiguration', owaspCode: 'misconfig',
      description: 'Flask debug mode enables an interactive Python debugger accessible via browser, and Django\'s DEBUG=True shows full stack traces with local variable values to all users.',
      impact: 'Remote code execution via Flask debugger, sensitive data disclosure, environment variable exposure.',
      remediation: 'Always set DEBUG=False in production. Drive this from an environment variable to prevent accidental deployment.',
      secureCode: 'import os\napp.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")\n# Django: DEBUG = False  (set via env)',
      insecureCode: 'app.run(debug=True)  # Never in production!',
    },
    {
      id: 'PY009', name: 'Insecure Random Number Generation',
      pattern: /\brandom\s*\.\s*(?:random|randint|choice|randrange|shuffle|sample|uniform)\s*\(/,
      severity: 'medium', cwe: 'CWE-338', owasp: 'A02:2021 – Cryptographic Failures', owaspCode: 'crypto',
      description: 'The random module uses Mersenne Twister (MT19937), a PRNG not suitable for cryptographic use. Its internal state can be reconstructed from 624 consecutive 32-bit outputs.',
      impact: 'Predictable tokens, session IDs, OTPs, and nonces leading to authentication bypass.',
      remediation: 'Use the secrets module (Python 3.6+) for all security-sensitive random values.',
      secureCode: 'import secrets\ntoken = secrets.token_urlsafe(32)  # 256-bit cryptographically secure\notp = str(secrets.randbelow(1000000)).zfill(6)',
      insecureCode: 'import random\ntoken = random.randint(0, 999999)  # Predictable!',
    },
    {
      id: 'PY010', name: 'Command Injection (os.system)',
      pattern: /\bos\s*\.\s*system\s*\(/,
      severity: 'high', cwe: 'CWE-78', owasp: 'A03:2021 – Injection', owaspCode: 'injection',
      description: 'os.system() passes its argument directly to the shell, making it susceptible to command injection when any user-controlled data is included.',
      impact: 'Arbitrary OS command execution with application process privileges.',
      remediation: 'Replace os.system() with subprocess.run() using a list argument and shell=False.',
      secureCode: 'import subprocess\nresult = subprocess.run(["ping", "-c", "1", hostname], capture_output=True)',
      insecureCode: 'os.system("ping -c 1 " + hostname)  # Command injection!',
    },
    {
      id: 'PY011', name: 'SSL Certificate Verification Disabled',
      pattern: /verify\s*=\s*False/,
      severity: 'high', cwe: 'CWE-295', owasp: 'A02:2021 – Cryptographic Failures', owaspCode: 'crypto',
      description: 'Setting verify=False in requests disables TLS certificate validation, allowing man-in-the-middle (MITM) attacks where attackers can intercept and modify traffic.',
      impact: 'MITM attacks, credential interception, data tampering.',
      remediation: 'Always verify SSL certificates. For self-signed certs, provide the CA bundle path. Never disable verification in production.',
      secureCode: 'requests.get(url, verify=True)  # Default; validates cert\nrequests.get(url, verify="/path/to/ca-bundle.crt")',
      insecureCode: 'requests.get(url, verify=False)  # MITM vulnerable!',
    },
    {
      id: 'PY012', name: 'Insecure YAML Deserialization',
      pattern: /yaml\s*\.\s*load\s*\(/,
      severity: 'high', cwe: 'CWE-502', owasp: 'A08:2021 – Software and Data Integrity Failures', owaspCode: 'integrity',
      description: 'yaml.load() without a safe Loader can deserialize Python objects (using !!python/object tags), enabling remote code execution with specially crafted YAML.',
      impact: 'Remote code execution via malicious YAML payload.',
      remediation: 'Always use yaml.safe_load() which only handles basic types (str, int, float, list, dict, bool, None).',
      secureCode: 'import yaml\ndata = yaml.safe_load(yaml_string)  # Only basic types',
      insecureCode: 'import yaml\ndata = yaml.load(yaml_string)  # RCE via !!python/object!',
    },
  ],

  javascript: [
    {
      id: 'JS001', name: 'eval() – Code Injection',
      pattern: /\beval\s*\(/,
      severity: 'critical', cwe: 'CWE-95', owasp: 'A03:2021 – Injection', owaspCode: 'injection',
      description: 'eval() parses and executes a string as JavaScript code. With any user-controlled input, attackers can execute arbitrary JavaScript in the context of your application.',
      impact: 'XSS amplification, credential theft, DOM manipulation, data exfiltration.',
      remediation: 'Replace eval() with JSON.parse() for data. Restructure code to eliminate dynamic execution.',
      secureCode: 'const data = JSON.parse(userInput);  // Safe for JSON data',
      insecureCode: 'const result = eval(userInput);  // RCE / XSS!',
    },
    {
      id: 'JS002', name: 'XSS via innerHTML Assignment',
      pattern: /\.innerHTML\s*[+]?=/,
      severity: 'high', cwe: 'CWE-79', owasp: 'A03:2021 – Injection', owaspCode: 'injection',
      description: 'Assigning user-controlled content to innerHTML parses it as HTML, executing any script tags or event handlers. This is the most common XSS vector in web applications.',
      impact: 'Session hijacking, credential theft, defacement, malware distribution, phishing.',
      remediation: 'Use textContent for plain text. Use DOMPurify.sanitize() before assigning to innerHTML.',
      secureCode: '// For plain text:\nelement.textContent = userInput;\n// For trusted HTML:\nelement.innerHTML = DOMPurify.sanitize(userInput);',
      insecureCode: 'element.innerHTML = userInput;  // XSS!',
    },
    {
      id: 'JS003', name: 'document.write() – XSS Risk',
      pattern: /document\s*\.\s*write\s*\(/,
      severity: 'high', cwe: 'CWE-79', owasp: 'A03:2021 – Injection', owaspCode: 'injection',
      description: 'document.write() with user input can inject arbitrary HTML/JavaScript. It also synchronously blocks rendering and overwrites the entire document if called after page load.',
      impact: 'XSS attacks, page hijacking, performance degradation.',
      remediation: 'Use DOM manipulation APIs (createElement, appendChild, textContent) instead.',
      secureCode: 'const p = document.createElement("p");\np.textContent = userText;\ndocument.body.appendChild(p);',
      insecureCode: 'document.write("<p>" + userText + "</p>");  // XSS!',
    },
    {
      id: 'JS004', name: 'Hardcoded API Key / Secret',
      pattern: /(?:apiKey|api_key|API_KEY|secret|SECRET|token|TOKEN|password|PASSWORD)\s*[:=]\s*["'][a-zA-Z0-9+/=_\-]{10,}["']/,
      severity: 'high', cwe: 'CWE-798', owasp: 'A07:2021 – Identification and Authentication Failures', owaspCode: 'auth',
      description: 'API keys and secrets in client-side JavaScript are fully visible to any user who views the page source or uses browser DevTools. They will also be committed to version control.',
      impact: 'API key theft, unauthorized use of third-party services, potential financial cost.',
      remediation: 'Move all secrets to backend services. Proxy API calls through your own server that stores credentials securely.',
      secureCode: '// Call your backend — it holds the secret\nconst response = await fetch("/api/proxy-endpoint");',
      insecureCode: 'const API_KEY = "sk-abc123def456ghi789";  // Visible in source!',
    },
    {
      id: 'JS005', name: 'Sensitive Data in localStorage',
      pattern: /localStorage\s*\.\s*setItem\s*\(\s*["'][^"']*["']\s*,\s*(?:.*(?:token|password|secret|key|auth|jwt|session))/i,
      severity: 'medium', cwe: 'CWE-922', owasp: 'A02:2021 – Cryptographic Failures', owaspCode: 'crypto',
      description: 'localStorage is accessible to any JavaScript running on the same origin, including scripts injected via XSS. Tokens stored here are trivially stolen by XSS payloads.',
      impact: 'Token theft via XSS, session hijacking, account takeover.',
      remediation: 'Store authentication tokens in HttpOnly, Secure, SameSite=Strict cookies which are inaccessible to JavaScript.',
      secureCode: '// Set server-side (cannot be accessed by JS)\nSet-Cookie: token=...; HttpOnly; Secure; SameSite=Strict',
      insecureCode: 'localStorage.setItem("authToken", token);  // Stolen by XSS!',
    },
    {
      id: 'JS006', name: 'new Function() – Code Injection',
      pattern: /\bnew\s+Function\s*\(/,
      severity: 'critical', cwe: 'CWE-95', owasp: 'A03:2021 – Injection', owaspCode: 'injection',
      description: 'new Function() constructs a JavaScript function from strings, similar to eval(). With user-controlled arguments, this enables arbitrary code execution.',
      impact: 'XSS, remote code execution in Node.js environments.',
      remediation: 'Avoid new Function() with dynamic strings. Define functions statically.',
      secureCode: '// Define functions statically\nconst handlers = { add: (a, b) => a + b };',
      insecureCode: 'const fn = new Function("return " + userInput);\nfn();  // Code injection!',
    },
    {
      id: 'JS007', name: 'Prototype Pollution (__proto__)',
      pattern: /\[\s*["']__proto__["']\s*\]|\.__proto__\s*=/,
      severity: 'high', cwe: 'CWE-1321', owasp: 'A03:2021 – Injection', owaspCode: 'injection',
      description: 'Writing to __proto__ modifies Object.prototype, affecting all objects in the application. This can override security checks and enable privilege escalation.',
      impact: 'Privilege escalation, authentication bypass, remote code execution in server-side contexts.',
      remediation: 'Use Object.create(null) for maps. Validate object keys against an allowlist when merging untrusted objects.',
      secureCode: 'const safeObj = Object.create(null);\n// Or use Map for arbitrary key-value storage',
      insecureCode: 'obj["__proto__"]["isAdmin"] = true;  // Poisons all objects!',
    },
    {
      id: 'JS008', name: 'postMessage Without Origin Validation',
      pattern: /window\s*\.\s*addEventListener\s*\(\s*["']message["']/,
      severity: 'medium', cwe: 'CWE-346', owasp: 'A07:2021 – Identification and Authentication Failures', owaspCode: 'auth',
      description: 'Handling postMessage events without validating event.origin allows messages from any page to be processed, enabling cross-origin attacks.',
      impact: 'Data injection, cross-origin request forgery, XSS via message injection.',
      remediation: 'Always validate event.origin against an explicit allowlist before processing event.data.',
      secureCode: 'window.addEventListener("message", (event) => {\n  if (event.origin !== "https://trusted-partner.com") return;\n  processData(event.data);\n});',
      insecureCode: 'window.addEventListener("message", (event) => {\n  processData(event.data);  // No origin check!\n});',
    },
    {
      id: 'JS009', name: 'setTimeout/setInterval with String Argument',
      pattern: /(?:setTimeout|setInterval)\s*\(\s*["'`]/,
      severity: 'medium', cwe: 'CWE-95', owasp: 'A03:2021 – Injection', owaspCode: 'injection',
      description: 'Passing a string to setTimeout/setInterval causes the string to be eval()-d. This is effectively equivalent to using eval() and carries the same risks.',
      impact: 'Code injection if any part of the string is user-controlled.',
      remediation: 'Always pass a function reference or arrow function. Never use string arguments.',
      secureCode: 'setTimeout(() => doAction(safeParam), 1000);',
      insecureCode: 'setTimeout("doAction(" + userParam + ")", 1000);  // Eval!',
    },
    {
      id: 'JS010', name: 'dangerouslySetInnerHTML (React XSS)',
      pattern: /dangerouslySetInnerHTML/,
      severity: 'high', cwe: 'CWE-79', owasp: 'A03:2021 – Injection', owaspCode: 'injection',
      description: 'React\'s dangerouslySetInnerHTML bypasses React\'s built-in XSS protection. Unsanitized user content passed here will be rendered as HTML and can execute scripts.',
      impact: 'XSS in React applications, session hijacking.',
      remediation: 'Sanitize content with DOMPurify before passing to dangerouslySetInnerHTML.',
      secureCode: 'import DOMPurify from "dompurify";\n<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }} />',
      insecureCode: '<div dangerouslySetInnerHTML={{ __html: userContent }} />  // XSS!',
    },
    {
      id: 'JS011', name: 'Insecure Math.random() for Security',
      pattern: /\bMath\s*\.\s*random\s*\(\s*\)/,
      severity: 'medium', cwe: 'CWE-338', owasp: 'A02:2021 – Cryptographic Failures', owaspCode: 'crypto',
      description: 'Math.random() uses a deterministic PRNG seeded at startup. Its output is statistically predictable and must not be used for security-sensitive values.',
      impact: 'Predictable tokens, OTPs, session IDs, CSRF tokens.',
      remediation: 'Use crypto.getRandomValues() in browsers or crypto.randomBytes() in Node.js.',
      secureCode: '// Browser:\nconst arr = new Uint8Array(32);\ncrypto.getRandomValues(arr);\nconst token = btoa(String.fromCharCode(...arr));',
      insecureCode: 'const token = Math.random().toString(36).slice(2);  // Predictable!',
    },
    {
      id: 'JS012', name: 'Sensitive Data in console.log()',
      pattern: /console\s*\.\s*(?:log|info|debug|warn)\s*\([^)]*(?:password|token|secret|key|auth|credential|ssn|credit)/i,
      severity: 'low', cwe: 'CWE-532', owasp: 'A09:2021 – Security Logging and Monitoring Failures', owaspCode: 'logging',
      description: 'Logging sensitive values to the console exposes them in browser DevTools, server log files, and log aggregation systems.',
      impact: 'Credential exposure in logs, facilitates insider attacks and external breaches.',
      remediation: 'Remove all debug logs in production. Use structured logging with automatic PII/credential redaction.',
      secureCode: 'console.log(`Login attempt for: ${username}`);  // Log non-sensitive info only',
      insecureCode: 'console.log("User password:", password);  // Exposed in logs!',
    },
  ],

  java: [
    {
      id: 'JV001', name: 'SQL Injection via String Concatenation',
      pattern: /(?:createStatement|prepareStatement|executeQuery|executeUpdate|execute)\s*\(\s*(?:"|')[^"']*(?:"|")\s*\+/,
      severity: 'critical', cwe: 'CWE-89', owasp: 'A03:2021 – Injection', owaspCode: 'injection',
      description: 'SQL queries built with string concatenation allow SQL injection. An attacker who controls any concatenated value can alter the query structure to bypass authentication, extract all data, or execute DDL commands.',
      impact: 'Full database compromise, data exfiltration, authentication bypass, data destruction.',
      remediation: 'Use PreparedStatement with positional parameters exclusively.',
      secureCode: 'PreparedStatement stmt = conn.prepareStatement(\n    "SELECT * FROM users WHERE id = ? AND active = ?"\n);\nstmt.setInt(1, userId);\nstmt.setBoolean(2, true);\nResultSet rs = stmt.executeQuery();',
      insecureCode: 'Statement stmt = conn.createStatement();\nResultSet rs = stmt.executeQuery(\n    "SELECT * FROM users WHERE id = " + userId  // Injection!\n);',
    },
    {
      id: 'JV002', name: 'Insecure Deserialization (ObjectInputStream)',
      pattern: /new\s+ObjectInputStream\s*\(/,
      severity: 'critical', cwe: 'CWE-502', owasp: 'A08:2021 – Software and Data Integrity Failures', owaspCode: 'integrity',
      description: 'Java\'s native deserialization can be exploited through "gadget chains" present in common libraries (commons-collections, Spring, etc.) to execute arbitrary code during readObject().',
      impact: 'Remote code execution, privilege escalation, denial of service.',
      remediation: 'Avoid native Java deserialization of untrusted data. Use JSON/XML/protobuf. Implement a look-ahead deserialization filter (JEP 290).',
      secureCode: '// Use JSON (Jackson) instead\nObjectMapper mapper = new ObjectMapper();\nmapper.activateDefaultTyping(LaissezFaireSubTypeValidator.instance, ObjectMapper.DefaultTyping.NONE);\nUserData data = mapper.readValue(jsonString, UserData.class);',
      insecureCode: 'ObjectInputStream ois = new ObjectInputStream(request.getInputStream());\nObject obj = ois.readObject();  // RCE via gadget chain!',
    },
    {
      id: 'JV003', name: 'Hardcoded Credentials',
      pattern: /(?:String\s+)?(?:password|passwd|secret|apiKey|API_KEY|apiSecret)\s*=\s*["'][^"']{4,}["']/i,
      severity: 'high', cwe: 'CWE-798', owasp: 'A07:2021 – Identification and Authentication Failures', owaspCode: 'auth',
      description: 'Hardcoded credentials will be visible in version control, compiled .class files (decompilable with javap or CFR), and deployment artifacts.',
      impact: 'Unauthorized database/API access, credential theft from artifacts.',
      remediation: 'Read secrets from System.getenv(), system properties, or a secrets manager (Vault, AWS SSM).',
      secureCode: 'String password = System.getenv("DB_PASSWORD");\n// Or from config:\nString password = config.getString("db.password");',
      insecureCode: 'String password = "admin123";  // In .class files!',
    },
    {
      id: 'JV004', name: 'Command Injection (Runtime.exec)',
      pattern: /Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(/,
      severity: 'critical', cwe: 'CWE-78', owasp: 'A03:2021 – Injection', owaspCode: 'injection',
      description: 'When user-controlled data is included in a Runtime.exec() string argument, attackers can inject shell metacharacters to run additional commands.',
      impact: 'Arbitrary OS command execution with JVM process privileges.',
      remediation: 'Use ProcessBuilder with an explicit string array for arguments. Validate all inputs against an allowlist.',
      secureCode: 'ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", validatedHostname);\npb.redirectErrorStream(true);\nProcess process = pb.start();',
      insecureCode: 'Runtime.getRuntime().exec("ping " + userHostname);  // Injection!',
    },
    {
      id: 'JV005', name: 'Weak Cryptographic Algorithm (MD5/SHA-1)',
      pattern: /MessageDigest\s*\.\s*getInstance\s*\(\s*["'](?:MD5|SHA-?1|SHA1)["']\s*\)/i,
      severity: 'high', cwe: 'CWE-327', owasp: 'A02:2021 – Cryptographic Failures', owaspCode: 'crypto',
      description: 'MD5 and SHA-1 are cryptographically broken and should not be used for password hashing, digital signatures, or data integrity.',
      impact: 'Hash collision attacks, password cracking, integrity bypass.',
      remediation: 'Use SHA-256 or SHA-3 for hashing. Use BCrypt or Argon2 for passwords.',
      secureCode: 'MessageDigest digest = MessageDigest.getInstance("SHA-256");\nbyte[] hash = digest.digest(data);',
      insecureCode: 'MessageDigest digest = MessageDigest.getInstance("MD5");  // Broken!',
    },
    {
      id: 'JV006', name: 'Insecure Random (java.util.Random)',
      pattern: /\bnew\s+Random\s*\(\s*\)/,
      severity: 'medium', cwe: 'CWE-338', owasp: 'A02:2021 – Cryptographic Failures', owaspCode: 'crypto',
      description: 'java.util.Random is not cryptographically secure. Its seed can be determined from a small number of outputs, making all future values predictable.',
      impact: 'Predictable session tokens, OTPs, nonces, CSRF tokens.',
      remediation: 'Use java.security.SecureRandom for all security-sensitive random values.',
      secureCode: 'SecureRandom sr = new SecureRandom();\nbyte[] token = new byte[32];\nsr.nextBytes(token);',
      insecureCode: 'Random r = new Random();\nint token = r.nextInt(1000000);  // Predictable!',
    },
    {
      id: 'JV007', name: 'Stack Trace Disclosure (printStackTrace)',
      pattern: /\.printStackTrace\s*\(\s*\)/,
      severity: 'medium', cwe: 'CWE-209', owasp: 'A09:2021 – Security Logging and Monitoring Failures', owaspCode: 'logging',
      description: 'printStackTrace() outputs internal class names, file paths, library versions, and business logic details. In web apps, this can be surfaced to end users.',
      impact: 'Information disclosure that facilitates more targeted attacks.',
      remediation: 'Use a logging framework (SLF4J, Log4j 2) at ERROR level. Return generic error messages to users.',
      secureCode: 'logger.error("Unexpected error processing request", e);\n// Return: {"error": "Internal server error"}',
      insecureCode: 'catch (Exception e) {\n    e.printStackTrace();  // Exposes internals to logs/users!\n}',
    },
    {
      id: 'JV008', name: 'XML External Entity (XXE) Injection',
      pattern: /DocumentBuilderFactory\s*\.\s*newInstance\s*\(\s*\)/,
      severity: 'high', cwe: 'CWE-611', owasp: 'A05:2021 – Security Misconfiguration', owaspCode: 'misconfig',
      description: 'Default XML parsers resolve external entities, enabling attackers to read local files (/etc/passwd), perform SSRF, or cause DoS via entity expansion attacks (billion laughs).',
      impact: 'Local file disclosure, SSRF, DoS, in some cases RCE.',
      remediation: 'Disable DTD processing and external entities on all XML parsers.',
      secureCode: 'DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\ndbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\ndbf.setFeature("http://xml.org/sax/features/external-general-entities", false);\ndbf.setXIncludeAware(false);\ndbf.setExpandEntityReferences(false);',
      insecureCode: 'DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n// Missing XXE protection — reads /etc/passwd!',
    },
  ],

  c: [
    {
      id: 'C001', name: 'Buffer Overflow – strcpy()',
      pattern: /\bstrcpy\s*\(/,
      severity: 'critical', cwe: 'CWE-120', owasp: 'A06:2021 – Vulnerable and Outdated Components', owaspCode: 'components',
      description: 'strcpy() copies without checking destination buffer size. If source exceeds destination capacity, adjacent memory is overwritten, corrupting heap/stack data or control flow.',
      impact: 'Memory corruption, arbitrary code execution, privilege escalation, crash.',
      remediation: 'Use strncpy() or strlcpy() with explicit size. In C++, prefer std::string.',
      secureCode: '// C: use strncpy with null termination\nstrncpy(dest, src, sizeof(dest) - 1);\ndest[sizeof(dest) - 1] = \'\\0\';\n// Or strlcpy if available\nstrlcpy(dest, src, sizeof(dest));',
      insecureCode: 'strcpy(dest, user_input);  // No bounds check – overflow!',
    },
    {
      id: 'C002', name: 'Buffer Overflow – gets() (Removed in C11)',
      pattern: /\bgets\s*\(/,
      severity: 'critical', cwe: 'CWE-242', owasp: 'A06:2021 – Vulnerable and Outdated Components', owaspCode: 'components',
      description: 'gets() reads unlimited input from stdin into a fixed-size buffer with no bounds checking whatsoever. It is literally impossible to use safely and was removed from C11.',
      impact: 'Stack smashing, arbitrary code execution, classic buffer overflow exploits.',
      remediation: 'Replace gets() with fgets() providing an explicit buffer size.',
      secureCode: 'char buffer[256];\nif (fgets(buffer, sizeof(buffer), stdin) == NULL) {\n    /* handle error */\n}\n// Remove trailing newline if present\nbuffer[strcspn(buffer, "\\n")] = \'\\0\';',
      insecureCode: 'char buffer[64];\ngets(buffer);  // Always vulnerable – removed in C11!',
    },
    {
      id: 'C003', name: 'Format String Attack – printf(user_input)',
      pattern: /\b(?:printf|fprintf|sprintf|snprintf|vprintf)\s*\(\s*\w+\s*\)/,
      severity: 'critical', cwe: 'CWE-134', owasp: 'A03:2021 – Injection', owaspCode: 'injection',
      description: 'Passing a user-controlled string directly as the format argument to printf() allows attackers to use format specifiers (%n, %x, %s) to read stack memory, write to arbitrary addresses, and execute code.',
      impact: 'Arbitrary memory read/write, stack disclosure, code execution.',
      remediation: 'Always use a literal format string: printf("%s", user_input)',
      secureCode: 'printf("%s", user_input);   // Safe: user input is data, not format\nfprintf(stderr, "%s\\n", message);',
      insecureCode: 'printf(user_input);  // Format string attack!',
    },
    {
      id: 'C004', name: 'Buffer Overflow – strcat()',
      pattern: /\bstrcat\s*\(/,
      severity: 'high', cwe: 'CWE-120', owasp: 'A06:2021 – Vulnerable and Outdated Components', owaspCode: 'components',
      description: 'strcat() appends to a string without checking whether the destination buffer has enough space, potentially overflowing the buffer.',
      impact: 'Heap/stack overflow, memory corruption, potential code execution.',
      remediation: 'Use strncat() with the remaining space as the size parameter.',
      secureCode: 'strncat(dest, src, sizeof(dest) - strlen(dest) - 1);',
      insecureCode: 'strcat(dest, user_input);  // No size check!',
    },
    {
      id: 'C005', name: 'Command Injection – system()',
      pattern: /\bsystem\s*\(/,
      severity: 'critical', cwe: 'CWE-78', owasp: 'A03:2021 – Injection', owaspCode: 'injection',
      description: 'system() passes its argument to the shell for execution. Any user-controlled content in the string enables command injection via shell metacharacters.',
      impact: 'Arbitrary OS command execution with process privileges.',
      remediation: 'Use execve() with an argument array. Validate and sanitize all inputs rigorously.',
      secureCode: 'char *args[] = {"/bin/ping", "-c", "1", safe_host, NULL};\nexecv(args[0], args);  // No shell involved',
      insecureCode: 'char cmd[256];\nsnprintf(cmd, sizeof(cmd), "ping %s", user_host);\nsystem(cmd);  // Shell injection!',
    },
    {
      id: 'C006', name: 'Integer Overflow in malloc() Sizing',
      pattern: /\bmalloc\s*\(\s*\w+\s*\*\s*\w+\s*\)/,
      severity: 'high', cwe: 'CWE-190', owasp: 'A06:2021 – Vulnerable and Outdated Components', owaspCode: 'components',
      description: 'Multiplying two integers to compute a malloc size without overflow checking can wrap around to a small positive value, causing malloc to allocate far less memory than intended.',
      impact: 'Heap buffer overflow when the allocated region is written to.',
      remediation: 'Use calloc() (safer) or check for overflow before multiplying.',
      secureCode: '/* Overflow-safe allocation */\nif (count > SIZE_MAX / sizeof(Item)) abort();\nItem *arr = malloc(count * sizeof(Item));\nif (!arr) abort();\nmemset(arr, 0, count * sizeof(Item));',
      insecureCode: 'int *arr = malloc(count * element_size);  // Integer overflow!',
    },
    {
      id: 'C007', name: 'Use-After-Free Risk',
      pattern: /\bfree\s*\(\s*\w+\s*\)\s*;(?!\s*\w+\s*=\s*NULL)/,
      severity: 'high', cwe: 'CWE-416', owasp: 'A06:2021 – Vulnerable and Outdated Components', owaspCode: 'components',
      description: 'Accessing memory after free() is undefined behavior. Freed memory may be reallocated, causing data corruption. Attackers can exploit this to manipulate heap metadata or execute code.',
      impact: 'Memory corruption, information disclosure, code execution.',
      remediation: 'Set pointer to NULL immediately after free() and check before use.',
      secureCode: 'free(ptr);\nptr = NULL;  // Prevent use-after-free\n// Before use:\nif (ptr != NULL) { /* use ptr */ }',
      insecureCode: 'free(ptr);\n/* ... */\n*ptr = value;  // Use-after-free!',
    },
    {
      id: 'C008', name: 'Unsafe sprintf() – No Size Limit',
      pattern: /\bsprintf\s*\(/,
      severity: 'high', cwe: 'CWE-120', owasp: 'A06:2021 – Vulnerable and Outdated Components', owaspCode: 'components',
      description: 'sprintf() writes to a buffer without checking its size. If the output is longer than the buffer, adjacent memory is overwritten.',
      impact: 'Stack/heap overflow, memory corruption.',
      remediation: 'Replace sprintf() with snprintf() and always specify the buffer size.',
      secureCode: 'char buf[256];\nint n = snprintf(buf, sizeof(buf), "Hello, %s!", name);\nif (n < 0 || n >= (int)sizeof(buf)) { /* truncated */ }',
      insecureCode: 'char buf[64];\nsprintf(buf, "Hello, %s!", very_long_name);  // Overflow!',
    },
  ],

  php: [
    {
      id: 'PHP001', name: 'SQL Injection via Direct Input',
      pattern: /(?:mysql_query|mysqli_query|->query)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/,
      severity: 'critical', cwe: 'CWE-89', owasp: 'A03:2021 – Injection', owaspCode: 'injection',
      description: 'Superglobal variables ($_GET, $_POST, etc.) are directly interpolated into SQL queries, allowing SQL injection. PHP is particularly vulnerable as string interpolation in double-quoted strings can silently insert variables.',
      impact: 'Full database dump, authentication bypass, data manipulation.',
      remediation: 'Use PDO or MySQLi prepared statements. Never use deprecated mysql_* functions.',
      secureCode: '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id AND active = 1");\n$stmt->execute([":id" => $_GET["id"]]);\n$user = $stmt->fetch(PDO::FETCH_ASSOC);',
      insecureCode: '$id = $_GET["id"];\n$result = mysql_query("SELECT * FROM users WHERE id=$id");  // Injection!',
    },
    {
      id: 'PHP002', name: 'XSS via Unescaped Output',
      pattern: /echo\s+\$_(?:GET|POST|REQUEST|COOKIE)/,
      severity: 'high', cwe: 'CWE-79', owasp: 'A03:2021 – Injection', owaspCode: 'injection',
      description: 'Directly echoing superglobal values outputs user-controlled content as raw HTML, enabling reflected XSS attacks.',
      impact: 'Session hijacking, credential theft, defacement.',
      remediation: 'Always wrap output in htmlspecialchars() with ENT_QUOTES and UTF-8 charset.',
      secureCode: 'echo htmlspecialchars($_GET["name"], ENT_QUOTES | ENT_HTML5, "UTF-8");',
      insecureCode: 'echo $_GET["name"];  // XSS: <script>alert(1)</script>',
    },
    {
      id: 'PHP003', name: 'eval() – Remote Code Execution',
      pattern: /\beval\s*\(/,
      severity: 'critical', cwe: 'CWE-95', owasp: 'A03:2021 – Injection', owaspCode: 'injection',
      description: 'eval() executes arbitrary PHP code. This is the ultimate injection vulnerability — one user-controlled input can give an attacker a complete web shell.',
      impact: 'Full remote code execution, web shell installation, complete server compromise.',
      remediation: 'Never use eval() with user input. Refactor to eliminate dynamic code execution.',
      secureCode: '// Static dispatch instead of eval\n$allowed = ["add", "subtract"];\nif (in_array($op, $allowed, true)) {\n    $result = $operations[$op]($a, $b);\n}',
      insecureCode: 'eval($_GET["code"]);  // Instant web shell!',
    },
    {
      id: 'PHP004', name: 'Local/Remote File Inclusion (LFI/RFI)',
      pattern: /(?:include|require|include_once|require_once)\s*[\(\s]\s*\$_/,
      severity: 'critical', cwe: 'CWE-98', owasp: 'A03:2021 – Injection', owaspCode: 'injection',
      description: 'Including files based on user-controlled path allows Local File Inclusion (reading /etc/passwd, application config) and if allow_url_include is on, Remote File Inclusion (loading remote PHP).',
      impact: 'Arbitrary file read, remote code execution, configuration exposure.',
      remediation: 'Use a whitelist of allowable page identifiers. Never use user input directly in file paths.',
      secureCode: '$allowed_pages = ["home", "about", "products", "contact"];\n$page = in_array($_GET["page"], $allowed_pages, true) ? $_GET["page"] : "home";\ninclude __DIR__ . "/pages/" . $page . ".php";',
      insecureCode: 'include $_GET["page"] . ".php";  // LFI: ../../etc/passwd%00',
    },
    {
      id: 'PHP005', name: 'Weak Password Hashing (MD5/SHA1)',
      pattern: /\b(?:md5|sha1)\s*\(\s*\$/,
      severity: 'high', cwe: 'CWE-327', owasp: 'A02:2021 – Cryptographic Failures', owaspCode: 'crypto',
      description: 'MD5 and SHA1 are general-purpose fast hash functions entirely unsuitable for password storage. They can be cracked in milliseconds using GPU-based rainbow table attacks.',
      impact: 'Password cracking at billions of hashes per second, mass account compromise.',
      remediation: 'Use PHP\'s built-in password_hash() with PASSWORD_BCRYPT or PASSWORD_ARGON2ID (PHP 7.2+).',
      secureCode: '$hash = password_hash($password, PASSWORD_ARGON2ID);\n// Verify:\nif (password_verify($input, $hash)) { /* authenticated */ }',
      insecureCode: '$hash = md5($password);  // Cracked in milliseconds!',
    },
    {
      id: 'PHP006', name: 'extract() with User Superglobals',
      pattern: /\bextract\s*\(\s*\$_/,
      severity: 'high', cwe: 'CWE-95', owasp: 'A03:2021 – Injection', owaspCode: 'injection',
      description: 'extract() creates local variables from array keys. Applied to $_POST/$_GET, an attacker can overwrite any local variable including $authenticated, $admin, $config.',
      impact: 'Authentication bypass, privilege escalation, variable injection.',
      remediation: 'Never call extract() on user-supplied data. Access superglobal keys explicitly.',
      secureCode: '$username = filter_input(INPUT_POST, "username", FILTER_SANITIZE_STRING);\n$role     = filter_input(INPUT_POST, "role",     FILTER_SANITIZE_STRING);',
      insecureCode: 'extract($_POST);  // Attacker sets $admin=true, $authenticated=1!',
    },
    {
      id: 'PHP007', name: 'Command Injection (shell_exec / system)',
      pattern: /(?:shell_exec|system|exec|passthru|popen)\s*\([^)]*\$_/,
      severity: 'critical', cwe: 'CWE-78', owasp: 'A03:2021 – Injection', owaspCode: 'injection',
      description: 'Calling shell functions with unsanitized user input allows OS command injection. Attackers chain additional commands using |, ;, &&, $(...).',
      impact: 'Arbitrary OS command execution, web shell installation.',
      remediation: 'Use escapeshellarg() on all user input. Prefer PHP native functions over shell commands.',
      secureCode: '$host = escapeshellarg($_GET["host"]);\n$output = shell_exec("ping -c 1 " . $host);',
      insecureCode: '$output = shell_exec("ping -c 1 " . $_GET["host"]);  // Injection!',
    },
    {
      id: 'PHP008', name: 'Error Display Enabled in Production',
      pattern: /ini_set\s*\(\s*["']display_errors["']\s*,\s*["']?1["']?\s*\)|error_reporting\s*\(\s*E_ALL\s*\)/,
      severity: 'medium', cwe: 'CWE-209', owasp: 'A05:2021 – Security Misconfiguration', owaspCode: 'misconfig',
      description: 'Displaying PHP errors in production reveals file paths, database credentials (from DSN errors), class/method names, and SQL queries to end users.',
      impact: 'Information disclosure aiding targeted attacks.',
      remediation: 'Disable display_errors in php.ini. Log errors to file. Show generic error pages to users.',
      secureCode: 'ini_set("display_errors", "0");\nini_set("log_errors",     "1");\nini_set("error_log",      "/var/log/php-errors.log");\nerror_reporting(E_ALL);  // Log all, display none',
      insecureCode: 'ini_set("display_errors", "1");\nerror_reporting(E_ALL);  // Exposes internals!',
    },
  ],

  go: [
    {
      id: 'GO001', name: 'SQL Injection via fmt.Sprintf',
      pattern: /(?:\.Query|\.Exec|\.QueryRow)\s*\(\s*fmt\.Sprintf/,
      severity: 'critical', cwe: 'CWE-89', owasp: 'A03:2021 – Injection', owaspCode: 'injection',
      description: 'Using fmt.Sprintf to construct SQL queries with user data enables SQL injection. The database/sql package\'s parameterized query support should always be used instead.',
      impact: 'Full database compromise, authentication bypass, data exfiltration.',
      remediation: 'Use parameterized queries with ? (SQLite/MySQL) or $N (PostgreSQL) placeholders.',
      secureCode: '// Parameterized query — safe\nrows, err := db.Query("SELECT * FROM users WHERE id = ? AND active = ?", userID, true)',
      insecureCode: '// Vulnerable\nquery := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)\nrows, err := db.Query(query)',
    },
    {
      id: 'GO002', name: 'Command Injection (exec.Command with user input)',
      pattern: /exec\.Command\s*\([^)]*(?:r\.FormValue|r\.URL\.Query|os\.Args\[|flag\.)/,
      severity: 'critical', cwe: 'CWE-78', owasp: 'A03:2021 – Injection', owaspCode: 'injection',
      description: 'Passing request parameters directly to exec.Command arguments enables command injection. Even without shell=true, an attacker can pass arguments to control the executed command\'s behavior.',
      impact: 'Arbitrary OS command execution.',
      remediation: 'Validate inputs against an allowlist before using as command arguments.',
      secureCode: '// Validate host against allowlist\nif !isAllowedHost(host) { http.Error(w, "Invalid host", 400); return }\ncmd := exec.Command("ping", "-c", "1", host)',
      insecureCode: 'host := r.FormValue("host")\ncmd := exec.Command("ping", host)  // Argument injection!',
    },
    {
      id: 'GO003', name: 'Weak Cryptography (crypto/md5 or crypto/sha1)',
      pattern: /(?:"crypto\/md5"|"crypto\/sha1")/,
      severity: 'high', cwe: 'CWE-327', owasp: 'A02:2021 – Cryptographic Failures', owaspCode: 'crypto',
      description: 'MD5 and SHA-1 are cryptographically broken. The Go standard library includes them only for legacy compatibility. They must not be used for security purposes.',
      impact: 'Hash collision attacks, authentication bypass.',
      remediation: 'Import crypto/sha256 or crypto/sha512. For passwords, use golang.org/x/crypto/bcrypt or argon2.',
      secureCode: 'import "crypto/sha256"\nhash := sha256.Sum256(data)\n// For passwords:\nimport "golang.org/x/crypto/bcrypt"\nhashed, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)',
      insecureCode: 'import "crypto/md5"\nhash := md5.Sum(data)  // Broken algorithm!',
    },
    {
      id: 'GO004', name: 'Insecure PRNG (math/rand)',
      pattern: /\bmath\/rand\b/,
      severity: 'medium', cwe: 'CWE-338', owasp: 'A02:2021 – Cryptographic Failures', owaspCode: 'crypto',
      description: 'math/rand is a deterministic PRNG not suitable for security-sensitive operations. With a known or guessable seed, all outputs can be predicted.',
      impact: 'Predictable tokens, session IDs, OTPs.',
      remediation: 'Use crypto/rand for security-sensitive random values.',
      secureCode: 'import "crypto/rand"\ntoken := make([]byte, 32)\nif _, err := rand.Read(token); err != nil { panic(err) }',
      insecureCode: 'import "math/rand"\ntoken := rand.Int63()  // Predictable!',
    },
    {
      id: 'GO005', name: 'TLS Certificate Verification Disabled',
      pattern: /InsecureSkipVerify\s*:\s*true/,
      severity: 'high', cwe: 'CWE-295', owasp: 'A02:2021 – Cryptographic Failures', owaspCode: 'crypto',
      description: 'Setting InsecureSkipVerify: true in tls.Config disables all certificate validation, making TLS connections completely vulnerable to MITM attacks.',
      impact: 'Man-in-the-middle attacks, credential interception, data tampering.',
      remediation: 'Remove InsecureSkipVerify. For custom CAs, provide the RootCAs certificate pool.',
      secureCode: 'tlsConfig := &tls.Config{\n    MinVersion: tls.VersionTLS13,\n    // No InsecureSkipVerify\n}\n// For custom CA:\ncertPool := x509.NewCertPool()\ncertPool.AppendCertsFromPEM(caCert)\ntlsConfig.RootCAs = certPool',
      insecureCode: 'tlsConfig := &tls.Config{\n    InsecureSkipVerify: true,  // MITM!',
    },
    {
      id: 'GO006', name: 'Hardcoded Credentials',
      pattern: /(?:password|secret|apiKey|api_key|token|TOKEN)\s*:?=\s*["'][^"']{6,}["']/i,
      severity: 'high', cwe: 'CWE-798', owasp: 'A07:2021 – Identification and Authentication Failures', owaspCode: 'auth',
      description: 'Secrets hardcoded in Go source code are compiled into the binary and visible via strings inspection. They also appear in version control history.',
      impact: 'Unauthorized access, credential theft from compiled binaries.',
      remediation: 'Use os.Getenv() or a secrets manager library.',
      secureCode: 'password := os.Getenv("DB_PASSWORD")\nif password == "" {\n    log.Fatal("DB_PASSWORD environment variable not set")\n}',
      insecureCode: 'password := "admin123"  // In compiled binary!',
    },
    {
      id: 'GO007', name: 'Path Traversal via User Input',
      pattern: /filepath\.Join\s*\([^)]*(?:r\.FormValue|r\.URL\.Query|os\.Args)/,
      severity: 'high', cwe: 'CWE-22', owasp: 'A01:2021 – Broken Access Control', owaspCode: 'broken-access',
      description: 'Joining user-supplied path components without validation enables path traversal (../../etc/passwd). filepath.Clean alone does not prevent escaping the base directory.',
      impact: 'Unauthorized file read/write, configuration and credential exposure.',
      remediation: 'After filepath.Clean, verify the result has the expected base directory prefix.',
      secureCode: 'baseDir := "/var/www/uploads"\nuserFile := r.FormValue("file")\nsafePath := filepath.Clean(filepath.Join(baseDir, userFile))\nif !strings.HasPrefix(safePath, baseDir+"/") {\n    http.Error(w, "Invalid path", http.StatusBadRequest)\n    return\n}',
      insecureCode: 'filePath := filepath.Join(baseDir, r.FormValue("file"))  // Traversal!',
    },
  ],
};

/* ═══════════════════════════════════════════════════════════════════════════════
   SAMPLE VULNERABLE CODE (one per language)
   ═══════════════════════════════════════════════════════════════════════════════ */
const SAMPLE_CODE = {
  python: `import pickle, hashlib, random, subprocess, sqlite3, os, yaml
from flask import Flask, request

app = Flask(__name__)
app.debug = True  # Debug mode in production!

# Hardcoded credentials (CWE-798)
DB_PASSWORD = "SuperSecret123"
API_KEY     = "sk-proj-abc123def456ghi789jkl"

@app.route('/login')
def login():
    username = request.args.get('username')
    password = request.args.get('password')
    conn = sqlite3.connect('users.db')
    # SQL Injection (CWE-89)
    cursor = conn.execute("SELECT * FROM users WHERE name='" + username + "'")
    # Weak hashing (CWE-327)
    hashed = hashlib.md5(password.encode()).hexdigest()
    # Insecure random token (CWE-338)
    token = random.randint(0, 999999)
    return str(cursor.fetchone())

@app.route('/run')
def run_cmd():
    cmd = request.args.get('cmd')
    # Command injection (CWE-78)
    result = subprocess.check_output(cmd, shell=True)
    return result

@app.route('/load')
def load_data():
    # Insecure deserialization (CWE-502)
    obj = pickle.loads(request.get_data())
    return str(obj)

@app.route('/eval')
def eval_expr():
    expr = request.args.get('expr')
    # Code injection (CWE-95)
    return str(eval(expr))

@app.route('/config')
def load_config():
    config_data = request.get_data(as_text=True)
    # Unsafe YAML (CWE-502)
    config = yaml.load(config_data)
    return str(config)

@app.route('/ping')
def ping_host():
    host = request.args.get('host')
    # OS command injection (CWE-78)
    os.system("ping -c 1 " + host)

@app.route('/fetch')
def fetch_url():
    import requests
    url = request.args.get('url')
    # TLS verification disabled (CWE-295)
    return requests.get(url, verify=False).text

if __name__ == '__main__':
    app.run(debug=True)`,

  javascript: `// Vulnerable JavaScript Application — SecureAudit Pro Demo

const API_KEY    = "sk-live-xK7mN2pQ9rT4vW8yZ1aB3cE5";
const SECRET_KEY = "prod-secret-jwt-key-do-not-share";

// XSS via innerHTML (CWE-79)
function displayUserProfile(userData) {
  document.getElementById('profile').innerHTML = userData.bio;
  document.write('<h1>' + userData.name + '</h1>');
}

// Code injection via eval() (CWE-95)
function calculateExpression(userInput) {
  const result = eval(userInput);
  console.log("Result:", result);
  return result;
}

// Insecure localStorage (CWE-922)
function storeSession(token, password) {
  localStorage.setItem('authToken', token);
  localStorage.setItem('userPassword', password);
  console.log("Stored auth token:", token);
}

// New Function() injection (CWE-95)
function runDynamicCode(userCode) {
  const fn = new Function('return ' + userCode);
  return fn();
}

// Weak random (CWE-338)
function generateOTP() {
  return Math.floor(Math.random() * 1000000);
}

// postMessage no origin check (CWE-346)
window.addEventListener('message', function(event) {
  const cmd = event.data.command;
  document.getElementById('output').innerHTML = cmd;
});

// React XSS
function UserContent({ html }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

// Prototype pollution
function merge(target, source) {
  for (const key of Object.keys(source)) {
    target[key] = source[key];  // __proto__ attack!
  }
}

// setTimeout with string
function delayedAction(userParam) {
  setTimeout("runAction(" + userParam + ")", 500);
}`,

  java: `import java.sql.*;
import java.security.*;
import java.util.Random;
import java.io.*;

public class VulnerableApp {

    // Hardcoded credentials (CWE-798)
    private static final String DB_PASSWORD = "admin123";
    private static final String API_KEY = "live_sk_xyz789abc123def456";

    // SQL Injection (CWE-89)
    public User getUserById(Connection conn, String userId) throws SQLException {
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(
            "SELECT * FROM users WHERE id = " + userId
        );
        return mapUser(rs);
    }

    // Insecure Deserialization (CWE-502)
    public Object deserializeRequest(InputStream input) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(input);
        return ois.readObject();  // Gadget chain RCE!
    }

    // Weak crypto (CWE-327)
    public String hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes());
        return new String(hash);
    }

    // Insecure random (CWE-338)
    public int generateToken() {
        Random random = new Random();
        return random.nextInt(1000000);
    }

    // Command injection (CWE-78)
    public String pingHost(String host) throws IOException {
        Process p = Runtime.getRuntime().exec("ping -c 1 " + host);
        return new String(p.getInputStream().readAllBytes());
    }

    // XXE Injection (CWE-611)
    public void parseXml(InputStream xmlInput) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        db.parse(xmlInput);  // XXE: reads /etc/passwd!
    }

    // Information disclosure (CWE-209)
    public String processRequest(String input) {
        try {
            return process(input);
        } catch (Exception e) {
            e.printStackTrace();  // Stack trace to user!
            return null;
        }
    }
}`,

  c: `#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Buffer overflow via strcpy (CWE-120)
void copyUsername(char *username) {
    char buffer[64];
    strcpy(buffer, username);  // No bounds check!
    printf("Hello, %s\\n", buffer);
}

// Always-vulnerable gets() (CWE-242)
void readInput() {
    char buf[128];
    gets(buf);  // Removed from C11 — always vulnerable!
    processInput(buf);
}

// Format string vulnerability (CWE-134)
void logMessage(char *user_message) {
    printf(user_message);  // %n writes to memory!
    fprintf(stderr, user_message);
}

// Buffer overflow via strcat (CWE-120)
void buildPath(char *user_segment) {
    char path[128] = "/var/data/";
    strcat(path, user_segment);  // No bounds check!
}

// Command injection via system() (CWE-78)
void pingHost(char *host) {
    char cmd[256];
    sprintf(cmd, "ping -c 1 %s", host);  // Also unsafe sprintf!
    system(cmd);  // Shell injection via ; | &&
}

// Integer overflow in malloc (CWE-190)
int *allocateArray(int count) {
    int *arr = malloc(count * sizeof(int));  // Overflow if count large!
    return arr;
}

// Use-after-free (CWE-416)
void processData(char *data) {
    char *buffer = malloc(strlen(data) + 1);
    strcpy(buffer, data);
    process(buffer);
    free(buffer);
    // buffer still used after free below!
    log_data(buffer);
}`,

  php: `<?php
// SQL Injection (CWE-89)
$id = $_GET['id'];
$result = mysql_query("SELECT * FROM users WHERE id=$id");
$user = mysqli_query($conn, "SELECT * FROM accounts WHERE email='" . $_GET['email'] . "'");

// XSS (CWE-79)
echo $_GET['name'];
echo "Welcome " . $_POST['username'];

// RCE via eval() (CWE-95)
eval($_GET['code']);

// File inclusion (CWE-98)
include $_GET['page'] . '.php';
require $_POST['module'];

// Weak password hashing (CWE-327)
$hash = md5($password);
$stored = sha1($_POST['password']);

// extract() injection (CWE-95)
extract($_POST);

// Command injection (CWE-78)
$output = shell_exec("ping -c 1 " . $_GET['host']);
$result = system("nslookup " . $_REQUEST['domain']);

// Error disclosure (CWE-209)
error_reporting(E_ALL);
ini_set('display_errors', '1');

// Session fixation risk
session_start();
$_SESSION['user'] = $_POST['username'];
?>`,

  go: `package main

import (
    "crypto/md5"
    "database/sql"
    "fmt"
    "math/rand"
    "net/http"
    "os/exec"
    "path/filepath"
    "crypto/tls"
    "net"
)

// Hardcoded credentials (CWE-798)
const (
    DBPassword = "production-db-pass-123"
    APISecret  = "jwt-signing-secret-prod"
)

// SQL Injection (CWE-89)
func getUser(db *sql.DB, userID string) {
    query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)
    rows, _ := db.Query(query)
    defer rows.Close()
}

// Command injection (CWE-78)
func pingHost(w http.ResponseWriter, r *http.Request) {
    host := r.FormValue("host")
    cmd := exec.Command("ping", "-c", "1", host)
    out, _ := cmd.Output()
    w.Write(out)
}

// Weak crypto (CWE-327)
func hashData(data []byte) [16]byte {
    return md5.Sum(data)
}

// Insecure PRNG (CWE-338)
func generateToken() int64 {
    return rand.Int63()
}

// TLS verification disabled (CWE-295)
func insecureClient() *http.Client {
    tlsConfig := &tls.Config{
        InsecureSkipVerify: true,
    }
    transport := &http.Transport{TLSClientConfig: tlsConfig}
    return &http.Client{Transport: transport}
}

// Path traversal (CWE-22)
func serveFile(w http.ResponseWriter, r *http.Request) {
    baseDir := "/var/www/files"
    filePath := filepath.Join(baseDir, r.FormValue("file"))
    http.ServeFile(w, r, filePath)
}

func main() {
    http.HandleFunc("/ping",  pingHost)
    http.HandleFunc("/files", serveFile)
    http.ListenAndServe(":8080", nil)
}`,
};

/* ═══════════════════════════════════════════════════════════════════════════════
   BEST PRACTICES DATA
   ═══════════════════════════════════════════════════════════════════════════════ */
const BEST_PRACTICES = [
  {
    icon: '🔏', title: 'Input Validation & Sanitization',
    items: [
      { text: '<strong>Validate on the server side.</strong> Client-side validation is a UX feature, not a security control. Always re-validate on the server.' },
      { text: '<strong>Use allowlists, not denylists.</strong> Define what is valid and reject everything else. Denylists miss edge cases.' },
      { text: '<strong>Parameterize SQL queries.</strong> Never concatenate or format user input into SQL strings. Use prepared statements in every framework.' },
      { text: '<strong>Encode output.</strong> HTML-encode all user content before rendering. Use context-appropriate encoding (HTML, URL, JS, CSS).' },
      { text: '<strong>Validate data types.</strong> Expect an integer? Reject strings. Expect a hostname? Validate against RFC patterns.' },
    ]
  },
  {
    icon: '🔐', title: 'Authentication & Session Management',
    items: [
      { text: '<strong>Use bcrypt, Argon2, or scrypt for passwords.</strong> These are slow-by-design algorithms that resist brute force. Never use MD5, SHA-1, or SHA-256 alone.' },
      { text: '<strong>Implement MFA.</strong> Require a second factor (TOTP, WebAuthn) for privileged accounts and sensitive actions.' },
      { text: '<strong>Store tokens in HttpOnly cookies.</strong> Not localStorage. Use Secure + SameSite=Strict attributes.' },
      { text: '<strong>Regenerate session IDs after login.</strong> Prevent session fixation attacks by issuing a new session upon authentication.' },
      { text: '<strong>Implement account lockout.</strong> Rate-limit and lock accounts after N consecutive failures. Use exponential backoff.' },
    ]
  },
  {
    icon: '🔑', title: 'Secret & Key Management',
    items: [
      { text: '<strong>Never commit secrets to version control.</strong> Rotate any key that has been committed — even momentarily.' },
      { text: '<strong>Use a secrets manager.</strong> HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager, or Azure Key Vault.' },
      { text: '<strong>Use environment variables for config.</strong> Follow the 12-factor app methodology. Use .env files locally (add to .gitignore).' },
      { text: '<strong>Rotate secrets regularly.</strong> Automate rotation. Short-lived credentials (e.g., AWS IAM roles, OIDC tokens) are preferred.' },
      { text: '<strong>Limit secret scope.</strong> API keys should have only the minimum necessary permissions (principle of least privilege).' },
    ]
  },
  {
    icon: '🔒', title: 'Cryptography',
    items: [
      { text: '<strong>Don\'t roll your own crypto.</strong> Use battle-tested libraries: libsodium, OpenSSL, BouncyCastle, Go\'s crypto/... packages.' },
      { text: '<strong>Use TLS 1.2+ for all communications.</strong> Disable TLS 1.0, 1.1, and SSLv3. Never disable certificate verification.' },
      { text: '<strong>Use AES-256-GCM for symmetric encryption.</strong> Always use authenticated encryption modes. Never use ECB mode.' },
      { text: '<strong>Use CSPRNGs.</strong> crypto.getRandomValues() (browser), secrets module (Python), crypto/rand (Go), SecureRandom (Java).' },
      { text: '<strong>Protect keys at rest.</strong> Derive encryption keys from master keys using PBKDF2, bcrypt, or HKDF. Store master keys in HSMs.' },
    ]
  },
  {
    icon: '🛡️', title: 'Authorization & Access Control',
    items: [
      { text: '<strong>Enforce least privilege.</strong> Grant the minimum permissions required. Default to deny.' },
      { text: '<strong>Validate authorization on every request.</strong> Don\'t rely on UI hiding. Enforce access control server-side on every endpoint.' },
      { text: '<strong>Use RBAC or ABAC.</strong> Implement structured role-based or attribute-based access control rather than ad-hoc permission checks.' },
      { text: '<strong>Protect against IDOR.</strong> Use indirect references (opaque IDs, UUIDs). Verify ownership before serving any resource.' },
      { text: '<strong>Implement CSRF protection.</strong> Use SameSite cookies + CSRF tokens for state-changing requests.' },
    ]
  },
  {
    icon: '📝', title: 'Secure Logging & Error Handling',
    items: [
      { text: '<strong>Never log secrets or PII.</strong> Redact passwords, tokens, credit card numbers, and SSNs before logging.' },
      { text: '<strong>Return generic error messages to users.</strong> Log detailed errors server-side. Never expose stack traces, SQL errors, or file paths.' },
      { text: '<strong>Log security-relevant events.</strong> Failed logins, privilege changes, data access, admin actions. Include timestamp, user ID, IP.' },
      { text: '<strong>Protect log integrity.</strong> Write logs to append-only storage. Consider forwarding to a SIEM for monitoring and alerting.' },
      { text: '<strong>Set appropriate log retention.</strong> Keep security logs for at least 90 days. Compliance frameworks (PCI, SOC 2) may require longer.' },
    ]
  },
  {
    icon: '📦', title: 'Dependency & Supply Chain Security',
    items: [
      { text: '<strong>Keep dependencies updated.</strong> Automate updates with Dependabot, Renovate, or similar tools. Subscribe to security advisories.' },
      { text: '<strong>Audit before adding dependencies.</strong> Check download counts, maintenance status, known CVEs, and license compatibility.' },
      { text: '<strong>Use lockfiles.</strong> Commit package-lock.json, Pipfile.lock, go.sum, etc. to ensure reproducible builds.' },
      { text: '<strong>Run SCA tools.</strong> npm audit, pip-audit, Snyk, or OWASP Dependency-Check as part of CI/CD.' },
      { text: '<strong>Verify package integrity.</strong> Use checksums (SHAs) and signature verification. Beware of typosquatting.' },
    ]
  },
  {
    icon: '⚙️', title: 'Secure Configuration',
    items: [
      { text: '<strong>Disable debug mode in production.</strong> Debug interfaces expose code execution, sensitive variables, and detailed errors.' },
      { text: '<strong>Apply security headers.</strong> Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy.' },
      { text: '<strong>Minimize attack surface.</strong> Disable unused features, services, ports, and accounts. Remove default credentials.' },
      { text: '<strong>Run with minimal OS privileges.</strong> Use dedicated service accounts with no sudo. Drop capabilities after binding ports.' },
      { text: '<strong>Scan Docker images.</strong> Use Trivy, Snyk, or Docker Scout. Run containers as non-root. Use read-only filesystems where possible.' },
    ]
  },
];

/* ═══════════════════════════════════════════════════════════════════════════════
   OWASP TOP 10 (2021)
   ═══════════════════════════════════════════════════════════════════════════════ */
const OWASP_TOP10 = [
  { rank: 'A01', name: 'Broken Access Control', color: '#ff2d55', desc: 'Access control enforces policy such that users cannot act outside their intended permissions. Failures lead to unauthorized information disclosure, modification, or destruction of all data, or performing a business function outside the user\'s limits.', examples: ['IDOR', 'Path Traversal', 'Missing RBAC', 'CORS Misconfiguration'] },
  { rank: 'A02', name: 'Cryptographic Failures', color: '#ff6b35', desc: 'Failures related to cryptography which often leads to exposure of sensitive data. Includes use of weak algorithms, poor key management, missing encryption at rest or in transit, and improper PRNG usage.', examples: ['MD5/SHA-1 Passwords', 'Cleartext Data', 'Weak TLS Config', 'Insecure PRNG'] },
  { rank: 'A03', name: 'Injection', color: '#ff9500', desc: 'Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. SQL, NoSQL, OS, LDAP, SSTI, and many other injection types can occur when an attacker can supply hostile data.', examples: ['SQL Injection', 'XSS', 'Command Injection', 'SSTI'] },
  { rank: 'A04', name: 'Insecure Design', color: '#ffcc02', desc: 'A broad category representing different weaknesses in design and architecture. Insecure design cannot be fixed by a perfect implementation as, by definition, the security controls required to defend against threats were never created.', examples: ['No Rate Limiting', 'Insecure Recovery', 'Missing Controls', 'Flawed Business Logic'] },
  { rank: 'A05', name: 'Security Misconfiguration', color: '#34c759', desc: 'The most commonly seen issue. Commonly a result of insecure default configurations, incomplete or ad hoc configurations, open cloud storage, misconfigured HTTP headers, and verbose error messages containing sensitive information.', examples: ['Debug Mode On', 'Default Credentials', 'Open Cloud Buckets', 'Missing Security Headers'] },
  { rank: 'A06', name: 'Vulnerable & Outdated Components', color: '#00c7be', desc: 'Components such as libraries, frameworks, and other software modules run with the same privileges as the application. If a vulnerable component is exploited, such an attack can facilitate serious data loss or server takeover.', examples: ['Unpatched Libraries', 'Deprecated APIs', 'EOL Software', 'No CVE Monitoring'] },
  { rank: 'A07', name: 'Identification & Auth Failures', color: '#0a84ff', desc: 'Confirmation of the user\'s identity, authentication, and session management is critical. Authentication failures can allow attackers to assume other users\' identities temporarily or permanently.', examples: ['Weak Passwords', 'No MFA', 'Session Fixation', 'Credential Stuffing'] },
  { rank: 'A08', name: 'Software & Data Integrity Failures', color: '#5e5ce6', desc: 'Relates to code and infrastructure that does not protect against integrity violations. An example is where an application relies upon plugins, libraries, or modules from untrusted sources, repositories, and content delivery networks (CDNs).', examples: ['Insecure Deserialization', 'Auto-update without Signing', 'CI/CD Compromise', 'pickle/yaml.load'] },
  { rank: 'A09', name: 'Security Logging & Monitoring Failures', color: '#bf5af2', desc: 'Without logging and monitoring, breaches cannot be detected. Insufficient logging, detection, monitoring, and active response occurs at any time and allows attackers to further attack systems, maintain persistence, pivot to more systems.', examples: ['No Audit Logs', 'Stack Traces to Users', 'Log Injection', 'No Alerting'] },
  { rank: 'A10', name: 'Server-Side Request Forgery (SSRF)', color: '#ff375f', desc: 'SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination.', examples: ['Internal Service Access', 'AWS Metadata Exfil', 'Port Scanning', 'Blind SSRF'] },
];

/* ═══════════════════════════════════════════════════════════════════════════════
   STATE
   ═══════════════════════════════════════════════════════════════════════════════ */
let editor = null;
let severityChart = null;
let lastFindings = [];
let currentFilter = 'all';
let isDark = true;

/* ═══════════════════════════════════════════════════════════════════════════════
   INIT
   ═══════════════════════════════════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', () => {
  initEditor();
  initChart();
  buildBestPractices();
  buildOWASP();
  bindEvents();
  addGaugeDefs();
});

function addGaugeDefs() {
  // Add SVG gradient defs for the gauge
  const svg = document.querySelector('.score-gauge');
  if (!svg) return;
  const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
  defs.innerHTML = `
    <linearGradient id="gaugeGradient" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%"   stop-color="#ff2d55"/>
      <stop offset="50%"  stop-color="#ffcc02"/>
      <stop offset="100%" stop-color="#00e68a"/>
    </linearGradient>
    <filter id="glow">
      <feGaussianBlur stdDeviation="3" result="blur"/>
      <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>`;
  svg.prepend(defs);
}

/* ── CodeMirror ── */
function initEditor() {
  const langModes = {
    python: 'python', javascript: 'javascript', java: 'text/x-java',
    c: 'text/x-csrc', php: 'application/x-httpd-php', go: 'text/x-go',
  };

  editor = CodeMirror.fromTextArea(document.getElementById('codeEditor'), {
    theme: 'dracula',
    lineNumbers: true,
    mode: 'python',
    indentUnit: 4,
    tabSize: 4,
    lineWrapping: false,
    autofocus: false,
    extraKeys: { 'Ctrl-Enter': runScan },
    gutters: ['CodeMirror-linenumbers'],
  });

  editor.on('change', updateEditorStats);

  document.getElementById('languageSelect').addEventListener('change', e => {
    const lang = e.target.value;
    editor.setOption('mode', langModes[lang]);
    document.getElementById('langIndicator').textContent = e.target.options[e.target.selectedIndex].text.replace(/^.\s/, '');
  });
}

function updateEditorStats() {
  const code = editor.getValue();
  const lines = code.split('\n').length;
  document.getElementById('lineCount').textContent = `${lines} line${lines !== 1 ? 's' : ''}`;
  document.getElementById('charCount').textContent = `${code.length} chars`;
}

/* ── Chart.js ── */
function initChart() {
  const ctx = document.getElementById('severityChart').getContext('2d');
  severityChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{
        data: [0, 0, 0, 0],
        backgroundColor: ['#ff2d55', '#ff6b35', '#ffcc02', '#00d4ff'],
        borderColor: 'transparent',
        borderWidth: 2,
        hoverBorderColor: ['#ff2d55', '#ff6b35', '#ffcc02', '#00d4ff'],
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      cutout: '68%',
      plugins: {
        legend: {
          position: 'right',
          labels: {
            color: '#8892a4', font: { family: 'Inter', size: 11 },
            padding: 12, usePointStyle: true, pointStyleWidth: 8,
          }
        },
        tooltip: {
          backgroundColor: '#1a2035', borderColor: '#232d42', borderWidth: 1,
          titleColor: '#e8eaf0', bodyColor: '#8892a4',
          titleFont: { family: 'Inter', weight: '600' },
          bodyFont: { family: 'Inter' }, padding: 10,
        }
      }
    }
  });
}

/* ── Build Best Practices Tab ── */
function buildBestPractices() {
  const grid = document.getElementById('bpGrid');
  grid.innerHTML = BEST_PRACTICES.map((bp, i) => `
    <div class="bp-card" id="bp-card-${i}">
      <div class="bp-card-header" onclick="toggleBP(${i})">
        <span class="bp-card-icon">${bp.icon}</span>
        <span class="bp-card-title">${bp.title}</span>
        <span class="bp-card-chevron">▼</span>
      </div>
      <div class="bp-card-body">
        ${bp.items.map(item => `
          <div class="bp-item">
            <span class="bp-bullet">›</span>
            <span class="bp-item-text">${item.text}</span>
          </div>`).join('')}
      </div>
    </div>`).join('');
}

window.toggleBP = (i) => {
  const card = document.getElementById(`bp-card-${i}`);
  card.classList.toggle('open');
};

/* ── Build OWASP Tab ── */
function buildOWASP() {
  const grid = document.getElementById('owaspGrid');
  grid.innerHTML = OWASP_TOP10.map(o => `
    <div class="owasp-card" style="--owasp-color:${o.color}">
      <style>#owaspGrid .owasp-card[style*="${o.color}"]::before { background:${o.color}; }</style>
      <div class="owasp-rank" style="color:${o.color}">${o.rank}:2021</div>
      <div class="owasp-name">${o.name}</div>
      <div class="owasp-desc">${o.desc}</div>
      <div class="owasp-examples">
        ${o.examples.map(e => `<span class="owasp-tag">${e}</span>`).join('')}
      </div>
    </div>`).join('');
}

/* ── Event Bindings ── */
function bindEvents() {
  document.getElementById('scanBtn').addEventListener('click', runScan);
  document.getElementById('loadSampleBtn').addEventListener('click', loadSample);
  document.getElementById('clearCodeBtn').addEventListener('click', () => { editor.setValue(''); updateEditorStats(); });
  document.getElementById('exportBtn').addEventListener('click', exportReport);
  document.getElementById('themeToggle').addEventListener('click', toggleTheme);
  document.getElementById('modalCloseBtn').addEventListener('click', closeModal);
  document.getElementById('modalOverlay').addEventListener('click', e => { if (e.target === e.currentTarget) closeModal(); });

  // Tab navigation
  document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });

  // Findings filter
  document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentFilter = btn.dataset.filter;
      applyFilter();
    });
  });

  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });
}

/* ── Tab Switching ── */
function switchTab(tab) {
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.toggle('active', p.id === `tab-${tab}`));
}

/* ── Theme Toggle ── */
function toggleTheme() {
  isDark = !isDark;
  document.body.classList.toggle('dark-mode', isDark);
  document.body.classList.toggle('light-mode', !isDark);
  document.getElementById('themeToggle').querySelector('.theme-icon').textContent = isDark ? '🌙' : '☀️';
  if (editor) editor.setOption('theme', isDark ? 'dracula' : 'default');
  // Update chart colors
  if (severityChart) {
    severityChart.options.plugins.legend.labels.color = isDark ? '#8892a4' : '#475569';
    severityChart.update();
  }
}

/* ── Load Sample Code ── */
function loadSample() {
  const lang = document.getElementById('languageSelect').value;
  editor.setValue(SAMPLE_CODE[lang]);
  updateEditorStats();
}

/* ═══════════════════════════════════════════════════════════════════════════════
   CORE ANALYSIS ENGINE
   ═══════════════════════════════════════════════════════════════════════════════ */
function runScan() {
  const code = editor.getValue().trim();
  if (!code) {
    shakeElement(document.getElementById('scanBtn'));
    return;
  }

  const lang = document.getElementById('languageSelect').value;
  const scanBtn = document.getElementById('scanBtn');
  scanBtn.disabled = true;
  scanBtn.classList.add('scanning');
  scanBtn.innerHTML = '<span>Scanning...</span>';

  showScanOverlay();

  // Simulate async staged scan
  const stages = [
    'Loading source code...',
    'Tokenizing and parsing...',
    'Running injection checks...',
    'Analyzing cryptographic usage...',
    'Checking authentication patterns...',
    'Scanning dangerous API calls...',
    'Detecting secret exposure...',
    'Checking deserialization risks...',
    'Generating security report...',
  ];

  let stage = 0;
  const stepsLog = document.getElementById('scanStepsLog');
  stepsLog.innerHTML = '';

  const interval = setInterval(() => {
    const pct = Math.round(((stage + 1) / stages.length) * 100);
    document.getElementById('scanBarFill').style.width = pct + '%';
    document.getElementById('scanStatusText').textContent = stages[stage];

    const step = document.createElement('div');
    step.className = 'scan-step done';
    step.textContent = stages[stage];
    stepsLog.appendChild(step);
    stepsLog.scrollTop = stepsLog.scrollHeight;
    stage++;

    if (stage >= stages.length) {
      clearInterval(interval);
      setTimeout(() => {
        const findings = analyzeCode(code, lang);
        hideScanOverlay();
        displayResults(findings, lang);
        scanBtn.disabled = false;
        scanBtn.classList.remove('scanning');
        scanBtn.innerHTML = `<svg class="scan-btn-icon" viewBox="0 0 20 20" fill="currentColor"><path d="M9 9a2 2 0 114 0 2 2 0 01-4 0z"/><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-13a4 4 0 00-3.446 6.032l-2.261 2.26a1 1 0 101.414 1.415l2.261-2.261A4 4 0 1011 5z" clip-rule="evenodd"/></svg> Run Security Scan`;
      }, 300);
    }
  }, 340);
}

function analyzeCode(code, language) {
  const rules = VULN_DB[language] || [];
  const lines = code.split('\n');
  const findings = [];
  const seen = new Set();

  for (const rule of rules) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line || line.startsWith('//') || line.startsWith('#') || line.startsWith('/*') || line.startsWith('*')) continue;

      if (rule.pattern.test(lines[i])) {
        const key = `${rule.id}:${i}`;
        if (seen.has(key)) continue;
        seen.add(key);

        findings.push({
          ...rule,
          lineNumber: i + 1,
          lineContent: lines[i].trim(),
        });
        // found a match, continue scanning file
      }
    }
  }

  // Sort by severity
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);

  return findings;
}

/* ═══════════════════════════════════════════════════════════════════════════════
   DISPLAY RESULTS
   ═══════════════════════════════════════════════════════════════════════════════ */
function displayResults(findings, lang) {
  lastFindings = findings;

  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  findings.forEach(f => counts[f.severity]++);

  // Update summary cards
  document.getElementById('countCritical').textContent = counts.critical;
  document.getElementById('countHigh').textContent = counts.high;
  document.getElementById('countMedium').textContent = counts.medium;
  document.getElementById('countLow').textContent = counts.low;

  // Update chart
  severityChart.data.datasets[0].data = [counts.critical, counts.high, counts.medium, counts.low];
  severityChart.update('active');

  // Calculate security score (0–100)
  const penalty = counts.critical * 25 + counts.high * 10 + counts.medium * 5 + counts.low * 2;
  const score = Math.max(0, Math.min(100, 100 - penalty));
  animateGauge(score);

  // Findings list
  const list = document.getElementById('findingsList');
  const placeholder = document.getElementById('findingsPlaceholder');

  if (findings.length === 0) {
    list.innerHTML = '';
    const clean = document.createElement('div');
    clean.className = 'findings-placeholder';
    clean.innerHTML = `
      <div class="placeholder-icon">✅</div>
      <p class="placeholder-title">No Vulnerabilities Detected</p>
      <p class="placeholder-sub">The analyzer found no known vulnerability patterns in the provided code. Always combine automated scanning with manual review.</p>`;
    list.appendChild(clean);
  } else {
    list.innerHTML = findings.map((f, idx) => `
      <div class="finding-item" data-severity="${f.severity}" data-idx="${idx}" onclick="openFinding(${idx})" tabindex="0" role="button" aria-label="View details for ${f.name}">
        <div class="finding-sev-bar sev-bar-${f.severity}"></div>
        <div class="finding-info">
          <div class="finding-name">${f.name}</div>
          <div class="finding-meta">
            <span class="finding-line">Line ${f.lineNumber}</span>
            <span class="finding-cwe">${f.cwe}</span>
            <span class="finding-owasp ${getOwaspClass(f.owaspCode)}">${f.owasp.split('–')[0].trim()}</span>
          </div>
        </div>
        <span class="finding-arrow">›</span>
      </div>`).join('');
  }

  document.getElementById('findingsTitle').textContent = `Findings (${findings.length})`;
  document.getElementById('exportBtn').disabled = findings.length === 0;
  applyFilter();
}

function getOwaspClass(code) {
  const map = { injection: 'owasp-injection', crypto: 'owasp-crypto', auth: 'owasp-auth' };
  return map[code] || 'owasp-other';
}

function applyFilter() {
  document.querySelectorAll('.finding-item').forEach(el => {
    const sev = el.dataset.severity;
    el.classList.toggle('hidden', currentFilter !== 'all' && sev !== currentFilter);
  });
}

/* ─── Gauge Animation ─── */
function animateGauge(score) {
  const TOTAL_ARC = 282.74; // π * 90
  const fill = document.getElementById('gaugeFill');
  const scoreText = document.getElementById('gaugeScoreText');
  const grade = document.getElementById('scoreGrade');

  const offset = TOTAL_ARC - (score / 100) * TOTAL_ARC;
  fill.style.strokeDashoffset = offset;

  // Update stroke color by score
  const color = score >= 80 ? '#00e68a' : score >= 60 ? '#34c759' : score >= 40 ? '#ffcc02' : score >= 20 ? '#ff6b35' : '#ff2d55';
  fill.style.stroke = color;
  fill.style.filter = `drop-shadow(0 0 6px ${color})`;

  // Animate number
  let current = 0;
  const duration = 1200;
  const start = performance.now();
  const animate = (ts) => {
    const progress = Math.min((ts - start) / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    current = Math.round(eased * score);
    scoreText.textContent = current;
    scoreText.setAttribute('fill', color);
    if (progress < 1) requestAnimationFrame(animate);
  };
  requestAnimationFrame(animate);

  // Grade label
  let gradeText, gradeClass;
  if (score >= 85)      { gradeText = 'A – Secure';       gradeClass = 'grade-secure'; }
  else if (score >= 70) { gradeText = 'B – Good';         gradeClass = 'grade-good'; }
  else if (score >= 50) { gradeText = 'C – Moderate';     gradeClass = 'grade-moderate'; }
  else if (score >= 30) { gradeText = 'D – Poor';         gradeClass = 'grade-poor'; }
  else                  { gradeText = 'F – Critical Risk'; gradeClass = 'grade-critical'; }

  grade.className = `score-grade ${gradeClass}`;
  grade.textContent = gradeText;
}

/* ═══════════════════════════════════════════════════════════════════════════════
   FINDING DETAIL MODAL
   ═══════════════════════════════════════════════════════════════════════════════ */
window.openFinding = (idx) => {
  const f = lastFindings[idx];
  if (!f) return;

  const overlay = document.getElementById('modalOverlay');
  document.getElementById('modalTitle').textContent = f.name;
  document.getElementById('modalSevBadge').textContent = f.severity.toUpperCase();
  document.getElementById('modalSevBadge').className = `modal-sev-badge badge-${f.severity}`;

  document.getElementById('modalBody').innerHTML = `
    <div class="modal-section">
      <div class="modal-section-title">Reference Information</div>
      <div class="modal-meta-chips">
        <div class="meta-chip"><span class="meta-chip-label">Severity</span><span class="meta-chip-value" style="color:var(--sev-${f.severity})">${f.severity.toUpperCase()}</span></div>
        <div class="meta-chip"><span class="meta-chip-label">CWE</span><span class="meta-chip-value">${f.cwe}</span></div>
        <div class="meta-chip"><span class="meta-chip-label">OWASP</span><span class="meta-chip-value">${f.owasp}</span></div>
        <div class="meta-chip"><span class="meta-chip-label">Line</span><span class="meta-chip-value">${f.lineNumber}</span></div>
      </div>
    </div>

    <div class="modal-section">
      <div class="modal-section-title">Description</div>
      <p>${f.description}</p>
    </div>

    <div class="modal-section">
      <div class="modal-section-title">Detected Code (Line ${f.lineNumber})</div>
      <div class="code-block insecure">${escapeHtml(f.lineContent)}</div>
    </div>

    <div class="modal-section">
      <div class="modal-section-title">Impact</div>
      <p>${f.impact}</p>
    </div>

    <div class="modal-section">
      <div class="modal-section-title">Remediation</div>
      <p>${f.remediation}</p>
    </div>

    <div class="modal-section">
      <div class="modal-section-title">Code Comparison</div>
      <div class="code-compare">
        <div class="code-block-wrap">
          <div class="code-block-label label-bad">❌ Insecure</div>
          <div class="code-block insecure">${escapeHtml(f.insecureCode)}</div>
        </div>
        <div class="code-block-wrap">
          <div class="code-block-label label-good">✅ Secure</div>
          <div class="code-block secure">${escapeHtml(f.secureCode)}</div>
        </div>
      </div>
    </div>`;

  overlay.classList.add('open');
  document.body.style.overflow = 'hidden';
};

function closeModal() {
  document.getElementById('modalOverlay').classList.remove('open');
  document.body.style.overflow = '';
}

/* ═══════════════════════════════════════════════════════════════════════════════
   SCAN OVERLAY
   ═══════════════════════════════════════════════════════════════════════════════ */
function showScanOverlay() {
  const overlay = document.getElementById('scanOverlay');
  overlay.classList.add('active');
  document.getElementById('scanBarFill').style.width = '0%';
  document.getElementById('scanStepsLog').innerHTML = '';
}
function hideScanOverlay() {
  document.getElementById('scanOverlay').classList.remove('active');
}

/* ═══════════════════════════════════════════════════════════════════════════════
   EXPORT HTML REPORT
   ═══════════════════════════════════════════════════════════════════════════════ */
function exportReport() {
  if (!lastFindings.length) return;

  const lang = document.getElementById('languageSelect').value;
  const now = new Date().toLocaleString();
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  lastFindings.forEach(f => counts[f.severity]++);
  const penalty = counts.critical * 25 + counts.high * 10 + counts.medium * 5 + counts.low * 2;
  const score = Math.max(0, Math.min(100, 100 - penalty));

  const findingsHtml = lastFindings.map((f, i) => `
    <div style="border:1px solid #2a2a2a;border-radius:8px;margin-bottom:16px;overflow:hidden;font-family:monospace">
      <div style="background:#1a1a2e;padding:12px 16px;display:flex;align-items:center;gap:10px;border-bottom:1px solid #2a2a2a">
        <span style="background:${sevColor(f.severity)};color:#000;padding:2px 10px;border-radius:4px;font-size:11px;font-weight:700">${f.severity.toUpperCase()}</span>
        <strong style="color:#e8eaf0;font-size:14px">${f.name}</strong>
        <span style="margin-left:auto;color:#666;font-size:12px">${f.cwe} · ${f.owasp}</span>
      </div>
      <div style="padding:16px;background:#0f0f1a">
        <div style="margin-bottom:12px"><span style="color:#888;font-size:11px;text-transform:uppercase">Detected at Line ${f.lineNumber}</span><br><code style="background:#1a1a2e;padding:8px 12px;border-radius:4px;display:block;margin-top:6px;color:#ff6b6b;font-size:12px;border:1px solid #2a2a2a">${escapeHtml(f.lineContent)}</code></div>
        <div style="margin-bottom:10px"><span style="color:#888;font-size:11px;text-transform:uppercase">Description</span><p style="color:#ccc;font-size:13px;margin-top:4px;line-height:1.6">${f.description}</p></div>
        <div style="margin-bottom:10px"><span style="color:#888;font-size:11px;text-transform:uppercase">Impact</span><p style="color:#ccc;font-size:13px;margin-top:4px;line-height:1.6">${f.impact}</p></div>
        <div><span style="color:#888;font-size:11px;text-transform:uppercase">Remediation</span><p style="color:#ccc;font-size:13px;margin-top:4px;line-height:1.6">${f.remediation}</p></div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:12px">
          <div><div style="font-size:11px;color:#ff4757;margin-bottom:4px">❌ INSECURE</div><code style="background:#2a0a0a;padding:10px;border-radius:4px;display:block;color:#ff8080;font-size:11px;border:1px solid #4a1515;white-space:pre;overflow-x:auto">${escapeHtml(f.insecureCode)}</code></div>
          <div><div style="font-size:11px;color:#00e68a;margin-bottom:4px">✅ SECURE</div><code style="background:#0a2a1a;padding:10px;border-radius:4px;display:block;color:#80ffba;font-size:11px;border:1px solid #154a2a;white-space:pre;overflow-x:auto">${escapeHtml(f.secureCode)}</code></div>
        </div>
      </div>
    </div>`).join('');

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Audit Report – ${now}</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: Inter, system-ui, sans-serif; background: #080c18; color: #e8eaf0; padding: 32px; }
  .header { border-bottom: 1px solid #1a2035; padding-bottom: 24px; margin-bottom: 32px; display: flex; align-items: flex-start; justify-content: space-between; }
  .title { font-size: 28px; font-weight: 800; color: #00d4ff; }
  .subtitle { font-size: 14px; color: #8892a4; margin-top: 4px; }
  .meta { font-size: 12px; color: #4a5568; text-align: right; }
  .score-box { display: flex; gap: 20px; margin-bottom: 32px; flex-wrap: wrap; }
  .score-card { background: #111827; border: 1px solid #1a2035; border-radius: 12px; padding: 20px 28px; text-align: center; }
  .score-big { font-size: 48px; font-weight: 900; color: ${score >= 70 ? '#00e68a' : score >= 40 ? '#ffcc02' : '#ff2d55'}; }
  .sev-card { background: #111827; border: 1px solid #1a2035; border-radius: 12px; padding: 16px 24px; text-align: center; min-width: 100px; }
  h2 { font-size: 18px; font-weight: 700; margin-bottom: 16px; color: #c8d0e0; border-left: 3px solid #00d4ff; padding-left: 12px; }
  .disclaimer { background: rgba(255,170,0,0.06); border: 1px solid rgba(255,170,0,0.2); border-radius: 8px; padding: 12px 16px; font-size: 12px; color: #8892a4; margin-top: 32px; line-height: 1.6; }
</style>
</head>
<body>
  <div class="header">
    <div>
      <div class="title">🛡️ SecureAudit Pro – Security Audit Report</div>
      <div class="subtitle">Language: ${lang.toUpperCase()} | Generated by SecureAudit Pro v2.4</div>
    </div>
    <div class="meta">
      <div>Generated: ${now}</div>
      <div>Total Findings: ${lastFindings.length}</div>
    </div>
  </div>

  <div class="score-box">
    <div class="score-card">
      <div style="font-size:12px;color:#8892a4;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">Security Score</div>
      <div class="score-big">${score}</div>
      <div style="font-size:12px;color:#8892a4">/100</div>
    </div>
    <div class="sev-card"><div style="color:#ff2d55;font-size:28px;font-weight:800">${counts.critical}</div><div style="font-size:11px;color:#8892a4;text-transform:uppercase">Critical</div></div>
    <div class="sev-card"><div style="color:#ff6b35;font-size:28px;font-weight:800">${counts.high}</div><div style="font-size:11px;color:#8892a4;text-transform:uppercase">High</div></div>
    <div class="sev-card"><div style="color:#ffcc02;font-size:28px;font-weight:800">${counts.medium}</div><div style="font-size:11px;color:#8892a4;text-transform:uppercase">Medium</div></div>
    <div class="sev-card"><div style="color:#00d4ff;font-size:28px;font-weight:800">${counts.low}</div><div style="font-size:11px;color:#8892a4;text-transform:uppercase">Low</div></div>
  </div>

  <h2>Detailed Findings</h2>
  ${findingsHtml}

  <div class="disclaimer">
    <strong>⚠️ Disclaimer:</strong> This report was generated by SecureAudit Pro using client-side pattern-based static analysis. It may contain false positives or miss complex vulnerabilities. This report supplements — but does not replace — manual code review, penetration testing, or dedicated SAST/DAST tools. Treat all findings as leads requiring manual validation.
  </div>
</body>
</html>`;

  const blob = new Blob([html], { type: 'text/html' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `security-audit-${lang}-${Date.now()}.html`;
  a.click();
  URL.revokeObjectURL(a.href);
}

function sevColor(s) {
  return { critical: '#ff2d55', high: '#ff6b35', medium: '#ffcc02', low: '#00d4ff' }[s] || '#8892a4';
}

/* ═══════════════════════════════════════════════════════════════════════════════
   UTILITIES
   ═══════════════════════════════════════════════════════════════════════════════ */
function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function shakeElement(el) {
  el.style.animation = 'none';
  el.offsetHeight; // Reflow
  el.style.animation = 'shake 0.4s ease';
  el.addEventListener('animationend', () => el.style.animation = '', { once: true });
}

// Shake keyframes
const styleSheet = document.createElement('style');
styleSheet.textContent = `@keyframes shake { 0%,100%{transform:translateX(0)} 20%{transform:translateX(-6px)} 40%{transform:translateX(6px)} 60%{transform:translateX(-4px)} 80%{transform:translateX(4px)} }`;
document.head.appendChild(styleSheet);
