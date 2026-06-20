/* ═══════════════════════════════════════════════════════════════════════════════
   SecureAudit Pro – Feature Module
   🔥 Vulnerability Heatmap | 🤖 Secure Code Generator | 📦 Dependency CVE Scanner
   ═══════════════════════════════════════════════════════════════════════════════ */
'use strict';

/* ════════════════════════════════════════════════════════
   ████  CVE DATABASE  ████
   50+ real CVEs across Python, npm, Go packages
   ════════════════════════════════════════════════════════ */
const CVE_DATABASE = {
  python: [
    { name:'django',      lt:'4.2.10', cve:'CVE-2024-27351', severity:'medium', title:'ReDoS in Truncator',              desc:'django.utils.text.Truncator is vulnerable to regular expression denial of service via crafted input strings.', fixed:'4.2.10 / 5.0.3' },
    { name:'django',      lt:'3.2.25', cve:'CVE-2024-24680', severity:'high',   title:'DoS via intcomma filter',         desc:'The intcomma template filter is vulnerable to a potential DoS attack via extremely long strings.', fixed:'3.2.25 / 4.2.9 / 5.0.2' },
    { name:'django',      lt:'2.2.28', cve:'CVE-2022-28347', severity:'critical',title:'SQL Injection via QuerySet.annotate', desc:'QuerySet.annotate(), aggregate(), and extra() methods are vulnerable to SQL injection via crafted dictionary keys.', fixed:'3.2.13 / 4.0.4' },
    { name:'requests',    lt:'2.32.0', cve:'CVE-2024-35195', severity:'medium', title:'Proxy-Authorization Header Leak', desc:'Requests forwards the Proxy-Authorization header to destination servers after HTTP redirects, potentially leaking credentials.', fixed:'2.32.0' },
    { name:'pillow',      lt:'10.3.0', cve:'CVE-2024-28219', severity:'high',   title:'Buffer Overflow in Image Processing',desc:'Pillow is affected by a buffer overflow in its handling of certain image formats, allowing potential code execution.', fixed:'10.3.0' },
    { name:'pillow',      lt:'9.3.0',  cve:'CVE-2022-44799', severity:'high',   title:'Arbitrary Code via BMP Files',   desc:'A crafted BMP file can cause a buffer overflow in Pillow leading to arbitrary code execution.', fixed:'9.3.0' },
    { name:'cryptography',lt:'42.0.4', cve:'CVE-2024-26130', severity:'high',   title:'NULL Pointer Dereference in PKCS12',desc:'If a PKCS12 key and certificate do not match, a NULL pointer dereference occurs during PKCS12 serialization, causing a crash.', fixed:'42.0.4' },
    { name:'jinja2',      lt:'3.1.4',  cve:'CVE-2024-34064', severity:'medium', title:'XSS via xmlattr Filter',         desc:'The xmlattr filter does not properly escape attribute names, allowing XSS attacks via specially crafted attribute names.', fixed:'3.1.4' },
    { name:'jinja2',      lt:'3.1.3',  cve:'CVE-2024-22195', severity:'medium', title:'XSS via ngettext',               desc:'The ngettext expression in templates is vulnerable to XSS via injected HTML in the singular form string.', fixed:'3.1.3' },
    { name:'werkzeug',    lt:'3.0.3',  cve:'CVE-2024-34069', severity:'high',   title:'Debugger PIN Bypass → RCE',      desc:'The Werkzeug debugger PIN is predictable in certain Docker container configurations, enabling RCE via the debugger interface.', fixed:'3.0.3' },
    { name:'werkzeug',    lt:'2.3.8',  cve:'CVE-2023-46136', severity:'high',   title:'DoS via Multipart Parsing',      desc:'Werkzeug multipart form parsing is vulnerable to a DoS attack via specially crafted multipart data.', fixed:'2.3.8 / 3.0.1' },
    { name:'pyyaml',      lt:'6.0',    cve:'CVE-2017-18342', severity:'critical',title:'RCE via yaml.load()',            desc:'yaml.load() without a Loader allows arbitrary Python object deserialization and code execution via !!python/object YAML tags.', fixed:'5.1+ (always use yaml.safe_load())' },
    { name:'paramiko',    lt:'3.4.0',  cve:'CVE-2023-48795', severity:'medium', title:'Terrapin SSH Attack',            desc:'Paramiko is vulnerable to the Terrapin attack which allows downgrade of SSH connection security features via prefix truncation.', fixed:'3.4.0' },
    { name:'urllib3',     lt:'2.2.2',  cve:'CVE-2024-37891', severity:'medium', title:'Proxy-Authorization Header Leak',desc:'urllib3 forwards the Proxy-Authorization header to destination servers on cross-origin redirects.', fixed:'2.2.2 / 1.26.19' },
    { name:'urllib3',     lt:'1.26.5', cve:'CVE-2021-33503', severity:'high',   title:'ReDoS via evil Regex in URL parsing',desc:'An attacker can cause urllib3 to hang via a specially crafted URL that triggers catastrophic backtracking.', fixed:'1.26.5' },
    { name:'sqlalchemy',  lt:'1.3.0',  cve:'CVE-2019-7548',  severity:'high',   title:'SQL Injection via order_by',     desc:'SQLAlchemy order_by() can be exploited for SQL injection when user-supplied column names are used directly.', fixed:'1.3.0' },
    { name:'flask',       lt:'2.3.2',  cve:'CVE-2023-30861', severity:'high',   title:'Cookie Session Without Expiry',  desc:'Flask does not set cookie expiry in certain configurations, which can enable session fixation attacks in some deployments.', fixed:'2.3.2 / 2.2.5' },
    { name:'aiohttp',     lt:'3.9.4',  cve:'CVE-2024-23334', severity:'high',   title:'Path Traversal in Static Files', desc:'Improperly sanitized paths in aiohttp static file serving allow path traversal attacks to read arbitrary files on the server.', fixed:'3.9.4' },
    { name:'aiohttp',     lt:'3.8.6',  cve:'CVE-2023-49081', severity:'medium', title:'HTTP Header Injection',          desc:'aiohttp is vulnerable to HTTP header injection via misconfigured proxy responses in certain edge cases.', fixed:'3.9.0' },
    { name:'certifi',     lt:'2023.7.22',cve:'CVE-2023-37920',severity:'high',  title:'Distrusted Root CA Certificate', desc:'Certifi includes an e-Tugra root certificate that was distrusted due to compliance failures, potentially enabling MITM attacks.', fixed:'2023.7.22' },
    { name:'setuptools',  lt:'65.5.1', cve:'CVE-2022-40897', severity:'medium', title:'ReDoS in package_index',         desc:'A ReDoS vulnerability exists in package_index.py when parsing very long package version strings.', fixed:'65.5.1' },
    { name:'numpy',       lt:'1.24.0', cve:'CVE-2021-33430', severity:'medium', title:'Buffer Overflow in Array Operations',desc:'A buffer overflow vulnerability in NumPy buffer protocol operations can cause crashes or potential information disclosure.', fixed:'1.24.0' },
    { name:'lxml',        lt:'4.9.1',  cve:'CVE-2022-2309',  severity:'medium', title:'NULL Pointer Dereference',       desc:'lxml is vulnerable to a NULL pointer dereference when parsing specially crafted XML documents.', fixed:'4.9.1' },
    { name:'twisted',     lt:'22.10.0',cve:'CVE-2022-39348', severity:'medium', title:'SSH Host Key Confusion',         desc:'Twisted SSH client is vulnerable to host key confusion when handling certain key exchange algorithms.', fixed:'22.10.0' },
    { name:'httpx',       lt:'0.23.0', cve:'CVE-2021-41945', severity:'high',   title:'CRLF Injection',                 desc:'httpx is vulnerable to CRLF injection via specially crafted URLs, allowing HTTP header injection attacks.', fixed:'0.23.0' },
  ],

  npm: [
    { name:'lodash',              lt:'4.17.21', cve:'CVE-2021-23337', severity:'high',   title:'Command Injection via template()',  desc:'The lodash template function is vulnerable to command injection via the variable option when user-controlled data is used.', fixed:'4.17.21' },
    { name:'lodash',              lt:'4.17.19', cve:'CVE-2020-8203',  severity:'high',   title:'Prototype Pollution via merge()',   desc:'lodash merge(), mergeWith(), defaultsDeep() are vulnerable to prototype pollution via specially crafted objects.', fixed:'4.17.19' },
    { name:'lodash',              lt:'4.17.12', cve:'CVE-2019-10744', severity:'critical',title:'Prototype Pollution via defaultsDeep',desc:'The defaultsDeep method allows prototype pollution, affecting all objects and potentially enabling privilege escalation.', fixed:'4.17.12' },
    { name:'axios',               lt:'1.6.0',   cve:'CVE-2023-45857', severity:'medium', title:'CSRF via XSRF-TOKEN Header Leak',   desc:'axios leaks the X-XSRF-TOKEN header to third-party hosts when the scheme is not checked correctly during redirects.', fixed:'1.6.0' },
    { name:'axios',               lt:'0.21.2',  cve:'CVE-2020-28168', severity:'medium', title:'Server-Side Request Forgery',       desc:'axios is vulnerable to SSRF via URL parsing inconsistencies between different Node.js HTTP modules.', fixed:'0.21.2' },
    { name:'moment',              lt:'2.29.4',  cve:'CVE-2022-31129', severity:'high',   title:'ReDoS via Locale String',           desc:'A ReDoS vulnerability allows denial of service via specially crafted locale strings passed to moment.js functions.', fixed:'2.29.4' },
    { name:'moment',              lt:'2.29.2',  cve:'CVE-2022-24785', severity:'high',   title:'Path Traversal in locale loading',  desc:'A path traversal vulnerability in moment.js locale loading allows an attacker to read arbitrary files via crafted locale names.', fixed:'2.29.2' },
    { name:'jsonwebtoken',        lt:'9.0.0',   cve:'CVE-2022-23529', severity:'high',   title:'Remote Code Execution via secretOrPublicKey',desc:'If secretOrPublicKey is not provided as a buffer, the library may be tricked into accepting forged tokens.', fixed:'9.0.0' },
    { name:'jsonwebtoken',        lt:'8.5.1',   cve:'CVE-2022-23540', severity:'high',   title:'JWT Algorithm Confusion (none alg)',desc:'jsonwebtoken does not always verify the algorithm parameter, allowing algorithm confusion attacks with the "none" algorithm.', fixed:'9.0.0' },
    { name:'minimist',            lt:'1.2.6',   cve:'CVE-2021-44906', severity:'critical',title:'Prototype Pollution via __proto__', desc:'minimist is vulnerable to prototype pollution when parsing specially crafted CLI arguments containing __proto__ keys.', fixed:'1.2.6' },
    { name:'tar',                 lt:'6.1.9',   cve:'CVE-2021-37712', severity:'high',   title:'Path Traversal on Windows',         desc:'The tar package allows arbitrary file creation via crafted entry paths with Windows-specific separators on Windows hosts.', fixed:'6.1.9' },
    { name:'vm2',                 lt:'3.9.19',  cve:'CVE-2023-29017', severity:'critical',title:'Sandbox Escape → Remote Code Execution',desc:'vm2 sandbox can be escaped via a specially crafted object that bypasses proxy handler validation, enabling arbitrary code execution.', fixed:'Unmaintained — migrate to isolated-vm or use a subprocess' },
    { name:'node-fetch',          lt:'2.6.7',   cve:'CVE-2022-0235',  severity:'high',   title:'Authorization Header Leak on Redirect',desc:'node-fetch forwards the Authorization header to third parties during HTTPS-to-HTTP redirects, leaking credentials.', fixed:'2.6.7 / 3.1.1' },
    { name:'express',             lt:'4.19.2',  cve:'CVE-2024-29041', severity:'medium', title:'Open Redirect via Unicode',         desc:'Express.js URL path sanitizer can be bypassed with specially crafted Unicode characters, enabling open redirect attacks.', fixed:'4.19.2' },
    { name:'serialize-javascript',lt:'3.1.0',   cve:'CVE-2020-7660',  severity:'high',   title:'XSS via serialize()',               desc:'serialize-javascript does not properly sanitize HTML in certain Unicode byte sequences, enabling XSS via serialized data.', fixed:'3.1.0' },
    { name:'marked',              lt:'4.0.10',  cve:'CVE-2022-21681', severity:'high',   title:'ReDoS via Backtick Parsing',        desc:'A ReDoS vulnerability in marked\'s inline code parsing allows denial of service via maliciously crafted markdown strings.', fixed:'4.0.10' },
    { name:'next',                lt:'14.1.1',  cve:'CVE-2024-34351', severity:'high',   title:'SSRF via Host Header in Server Actions',desc:'Next.js is vulnerable to SSRF via the Host header in server actions, allowing internal network requests.', fixed:'14.1.1' },
    { name:'next',                lt:'13.5.1',  cve:'CVE-2023-46298', severity:'high',   title:'DoS via Crafted Headers',           desc:'Certain HTTP requests with specifically crafted headers can cause Next.js server processes to crash.', fixed:'13.5.1' },
    { name:'webpack',             lt:'5.94.0',  cve:'CVE-2024-43788', severity:'medium', title:'DOM Clobbering → XSS',             desc:'webpack\'s auto public path feature is vulnerable to DOM clobbering, enabling cross-origin script injection in certain configurations.', fixed:'5.94.0' },
    { name:'dompurify',           lt:'3.1.3',   cve:'CVE-2024-45801', severity:'high',   title:'mXSS Bypass via Template+MathML',  desc:'DOMPurify can be bypassed via mutation XSS combining template elements with MathML namespace, allowing script execution.', fixed:'3.1.3' },
    { name:'semver',              lt:'7.5.2',   cve:'CVE-2022-25883', severity:'medium', title:'ReDoS via newRange()',              desc:'The newRange() function in semver is vulnerable to ReDoS via crafted version range strings.', fixed:'7.5.2 / 6.3.1 / 5.7.2' },
    { name:'socket.io',           lt:'4.6.2',   cve:'CVE-2023-32695', severity:'high',   title:'ReDoS in Room Name Parser',        desc:'socket.io server is vulnerable to ReDoS via specially crafted room name strings that trigger catastrophic backtracking.', fixed:'4.6.2' },
    { name:'tough-cookie',        lt:'4.1.3',   cve:'CVE-2023-26136', severity:'critical',title:'Prototype Pollution via Cookie',   desc:'tough-cookie is vulnerable to prototype pollution when parsing cookies with specific domain values.', fixed:'4.1.3' },
    { name:'word-wrap',           lt:'1.2.4',   cve:'CVE-2023-26115', severity:'high',   title:'ReDoS via wrap()',                 desc:'word-wrap is vulnerable to ReDoS via a specially crafted string passed to the wrap() function.', fixed:'1.2.4' },
    { name:'ip',                  lt:'2.0.1',   cve:'CVE-2023-42282', severity:'critical',title:'SSRF via Private IP Bypass',       desc:'The ip package does not correctly identify some private IP ranges, enabling SSRF by bypassing IP allowlist filters.', fixed:'2.0.1' },
    { name:'braces',              lt:'3.0.3',   cve:'CVE-2024-4068',  severity:'high',   title:'ReDoS via Untrusted Input',        desc:'braces is vulnerable to ReDoS via specially crafted input strings that trigger catastrophic backtracking.', fixed:'3.0.3' },
    { name:'@babel/traverse',     lt:'7.23.2',  cve:'CVE-2023-45133', severity:'critical',title:'RCE via Code Injection',          desc:'Babel traverse is vulnerable to arbitrary code execution when processing a maliciously crafted Babel plugin or preset.', fixed:'7.23.2' },
    { name:'vite',                lt:'5.2.6',   cve:'CVE-2024-31207', severity:'high',   title:'Arbitrary File Read via WebSocket',desc:'Vite development server allows arbitrary file reads via a specially crafted WebSocket message when the server binds to 0.0.0.0.', fixed:'5.2.6 / 4.5.3' },
    { name:'path-to-regexp',      lt:'0.1.10',  cve:'CVE-2024-45296', severity:'high',   title:'ReDoS via Backtracking Regex',     desc:'path-to-regexp generates regexes from route patterns that can be subject to ReDoS via crafted URL paths.', fixed:'0.1.10 / 1.9.0 / 3.3.0' },
    { name:'undici',              lt:'6.6.1',   cve:'CVE-2024-24758', severity:'medium', title:'Proxy-Authorization Header Leak',  desc:'undici forwards the Proxy-Authorization and Cookie headers to third-party hosts during cross-origin redirects.', fixed:'6.6.1' },
  ],

  go: [
    { name:'github.com/golang-jwt/jwt', lt:'4.5.0', cve:'CVE-2022-23540', severity:'high',   title:'JWT Algorithm Confusion',        desc:'golang-jwt/jwt is vulnerable to algorithm confusion attacks and the "none" algorithm in certain configurations.', fixed:'v4.5.0' },
    { name:'github.com/gin-gonic/gin',  lt:'1.9.1', cve:'CVE-2023-26125', severity:'medium', title:'Improper Input Validation',       desc:'The Gin web framework has improper handling of certain malformed HTTP requests that can cause unexpected behavior.', fixed:'v1.9.1' },
    { name:'golang.org/x/crypto',       lt:'0.17.0',cve:'CVE-2023-48795', severity:'medium', title:'Terrapin SSH Attack',             desc:'The Go x/crypto SSH implementation is vulnerable to the Terrapin attack via prefix truncation of SSH handshake messages.', fixed:'v0.17.0' },
    { name:'golang.org/x/net',          lt:'0.23.0',cve:'CVE-2023-44487', severity:'high',   title:'HTTP/2 Rapid Reset DoS',          desc:'The HTTP/2 Rapid Reset attack allows attackers to send many requests that are immediately cancelled, exhausting server resources.', fixed:'v0.23.0' },
    { name:'golang.org/x/net',          lt:'0.7.0', cve:'CVE-2023-24539', severity:'high',   title:'CSS Template Injection',          desc:'The html/template package in Go\'s x/net may allow injection through CSS template values containing backtick characters.', fixed:'v0.7.0 / Go 1.20.3' },
    { name:'github.com/go-jose/go-jose',lt:'3.0.1', cve:'CVE-2023-26483', severity:'high',   title:'Denial of Service via JWE',      desc:'go-jose is vulnerable to a DoS attack via specially crafted JWE tokens with overly large iteration counts.', fixed:'v3.0.1' },
    { name:'github.com/gorilla/websocket',lt:'1.5.1',cve:'CVE-2023-44487',severity:'high',   title:'HTTP/2 Rapid Reset Attack',      desc:'Applications using gorilla/websocket may be vulnerable to HTTP/2 Rapid Reset DoS attacks at the underlying HTTP/2 layer.', fixed:'v1.5.1' },
    { name:'github.com/hashicorp/consul',lt:'1.17.3',cve:'CVE-2024-23249',severity:'high',   title:'Bypass of Namespace Policy Enforcement',desc:'A crafted request can bypass namespace isolation, allowing ACL tokens to perform actions outside their authorized namespace.', fixed:'v1.17.3' },
  ],
};

/* ════════════════════════════════════════════════════════
   ████  DEPENDENCY FILE SAMPLE DATA  ████
   ════════════════════════════════════════════════════════ */
const DEP_SAMPLES = {
  python: `# requirements.txt — Sample project dependencies
django==3.2.20
requests==2.27.0
pillow==9.2.0
cryptography==38.0.0
jinja2==3.0.3
werkzeug==2.1.2
flask==2.1.3
pyyaml==5.4.1
paramiko==2.9.2
urllib3==1.26.4
sqlalchemy==1.4.0
aiohttp==3.8.4
certifi==2022.5.18
numpy==1.22.0
lxml==4.8.0`,

  npm: `{
  "name": "my-app",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "^4.17.15",
    "axios": "^0.21.0",
    "moment": "^2.29.1",
    "jsonwebtoken": "^8.5.0",
    "express": "^4.17.1",
    "node-fetch": "^2.6.1",
    "marked": "^4.0.1",
    "socket.io": "^4.5.0",
    "dompurify": "^2.3.6",
    "semver": "^7.3.5",
    "tough-cookie": "^4.1.2",
    "next": "^13.4.0",
    "webpack": "^5.75.0",
    "serialize-javascript": "^3.0.0",
    "vm2": "^3.9.5",
    "@babel/traverse": "^7.20.0"
  }
}`,

  go: `module github.com/example/myapp

go 1.21

require (
  github.com/golang-jwt/jwt v4.4.0
  github.com/gin-gonic/gin v1.8.0
  golang.org/x/crypto v0.14.0
  golang.org/x/net v0.15.0
  github.com/go-jose/go-jose v3.0.0
  github.com/gorilla/websocket v1.5.0
  github.com/hashicorp/consul v1.15.0
)`,
};

/* ════════════════════════════════════════════════════════
   ████  SECURE CODE FIXERS  ████
   Regex-based per-rule transformations
   ════════════════════════════════════════════════════════ */
const CODE_FIXERS = {
  python: {
    PY002: l => l.replace(/\beval\s*\(/, 'ast.literal_eval(') + (l.includes('eval(') ? '  # ✅ Fixed: eval → ast.literal_eval' : ''),
    PY003: l => `# ⚠️ TODO: Refactor exec() – see remediation\n` + l.replace(/\bexec\s*\(/, '# exec('),
    PY004: l => l.replace(/pickle\.(loads?)\s*\(/, 'json.$1(') + '  # ✅ Fixed: pickle → json',
    PY005: l => l.replace(/shell\s*=\s*True/, 'shell=False') + '  # ✅ Fixed: shell=False',
    PY006: l => l.replace(/hashlib\.(md5|sha1)\s*\(/, 'hashlib.sha256(') + '  # ✅ Fixed: weak hash → SHA-256',
    PY007: l => l.replace(/((?:password|passwd|api[_-]?key|secret|token)\s*=\s*)["'][^"']{3,}["']/i,
                  (_, g) => `${g}os.environ.get("${g.split('=')[0].trim().toUpperCase()}")`) + '  # ✅ Fixed: use env var',
    PY008: l => l.replace(/debug\s*=\s*True/, 'debug=False') + '  # ✅ Fixed: debug disabled',
    PY009: l => l.replace(/random\.(randint|randrange)\s*\(([^,)]+),\s*([^)]+)\)/,
                  (_, _fn, _a, b) => `secrets.randbelow(${b.trim()})`) + '  # ✅ Fixed: secrets module',
    PY010: l => '# ✅ Fixed: use subprocess.run with shell=False\nsubprocess.run(["cmd", "arg"], shell=False)',
    PY011: l => l.replace(/,?\s*verify\s*=\s*False/, '') + '  # ✅ Fixed: cert verification enabled',
    PY012: l => l.replace(/yaml\.load\s*\(/, 'yaml.safe_load(') + '  # ✅ Fixed: yaml.safe_load',
  },
  javascript: {
    JS001: l => l.replace(/\beval\s*\(([^)]+)\)/, 'JSON.parse($1)') + '  // ✅ Fixed: eval → JSON.parse',
    JS002: l => l.replace(/\.innerHTML\s*=/, '.textContent =') + '  // ✅ Fixed: innerHTML → textContent',
    JS003: l => '// ✅ Fixed: use DOM API instead\nconst el = document.createElement("p"); el.textContent = text; document.body.appendChild(el);',
    JS004: l => l.replace(/((?:apiKey|api_key|secret|token|password)\s*[:=]\s*)["'][^"']{5,}["']/i,
                  (_, g) => `${g}process.env.${g.split(/[:=]/)[0].trim().toUpperCase()}`) + '  // ✅ Fixed: use env var',
    JS006: l => '// ✅ Fixed: avoid new Function() — use static dispatch\n// ' + l,
    JS009: l => l.replace(/setTimeout\s*\(\s*["'`]([^"'`]+)["'`]/, 'setTimeout(() => { $1 }') + '  // ✅ Fixed: function ref',
    JS011: l => l.replace(/Math\.random\s*\(\s*\)/,
                  'crypto.getRandomValues(new Uint32Array(1))[0] / 0xFFFFFFFF') + '  // ✅ Fixed: crypto.getRandomValues',
  },
  java: {
    JV003: l => l.replace(/((?:String\s+)?(?:password|passwd|secret|apiKey)\s*=\s*)["'][^"']{4,}["']/i,
                  (_, g) => `${g}System.getenv("${g.split(/[=\s]+/)[1]?.trim().toUpperCase() || 'SECRET'}")`) + '  // ✅ Fixed: env var',
    JV005: l => l.replace(/getInstance\s*\(\s*["'](?:MD5|SHA-?1|SHA1)["']\s*\)/i, 'getInstance("SHA-256")') + '  // ✅ Fixed: SHA-256',
    JV006: l => l.replace(/\bnew\s+Random\s*\(\s*\)/, 'new SecureRandom()') + '  // ✅ Fixed: SecureRandom',
    JV007: l => l.replace(/\.printStackTrace\s*\(\s*\)/, '/* ✅ Fixed: */ ; logger.error("Error", e)'),
  },
  c: {
    C001: l => l.replace(/\bstrcpy\s*\((\w+),\s*(\w+)\)/, 'strncpy($1, $2, sizeof($1) - 1); $1[sizeof($1)-1] = \'\\0\'') + ' /* ✅ Fixed */',
    C002: l => l.replace(/\bgets\s*\((\w+)\)/, 'fgets($1, sizeof($1), stdin)') + ' /* ✅ Fixed */',
    C003: l => l.replace(/\bprintf\s*\((\w+)\)/, 'printf("%s", $1)') + ' /* ✅ Fixed: format string */',
    C004: l => l.replace(/\bstrcat\s*\((\w+),\s*(\w+)\)/, 'strncat($1, $2, sizeof($1) - strlen($1) - 1)') + ' /* ✅ Fixed */',
    C005: l => '/* ✅ Fixed: Use execv instead of system() */\nchar *args[] = {"cmd", "arg", NULL};\nexecv(args[0], args);',
    C008: l => l.replace(/\bsprintf\s*\(/, 'snprintf(/* buf_size, */') + ' /* ✅ Fixed: snprintf */',
  },
  php: {
    PHP002: l => l.replace(/echo\s+(\$_(?:GET|POST|REQUEST|COOKIE)\[[^\]]+\])/, 'echo htmlspecialchars($1, ENT_QUOTES | ENT_HTML5, "UTF-8")') + '  // ✅ Fixed',
    PHP005: l => l.replace(/\b(md5|sha1)\s*\((\$\w+)\)/, 'password_hash($2, PASSWORD_ARGON2ID)') + '  // ✅ Fixed: bcrypt/argon2',
    PHP007: l => l.replace(/ini_set\s*\(\s*["']display_errors["']\s*,\s*["']?1["']?\s*\)/, 'ini_set("display_errors", "0")') + '  // ✅ Fixed',
    PHP008: l => l.replace(/ini_set\s*\(\s*["']display_errors["']\s*,\s*["']?1["']?\s*\)/, 'ini_set("display_errors", "0")') + '  // ✅ Fixed',
  },
  go: {
    GO003: l => l.replace(/"crypto\/md5"/, '"crypto/sha256"').replace(/"crypto\/sha1"/, '"crypto/sha256"') + '  // ✅ Fixed',
    GO004: l => l.replace(/"math\/rand"/, '"crypto/rand"') + '  // ✅ Fixed: crypto/rand',
    GO005: l => l.replace(/InsecureSkipVerify\s*:\s*true/, 'InsecureSkipVerify: false /* ✅ Fixed */'),
    GO006: l => l.replace(/((?:password|secret|apiKey|token)\s*:?=\s*)["'][^"']{5,}["']/i,
                  (_, g) => `${g}os.Getenv("${g.split(/[:=]+/)[0].trim().toUpperCase()}")`) + '  // ✅ Fixed',
  },
};

/* ════════════════════════════════════════════════════════
   ████  COMMENT TOKENS PER LANGUAGE  ████
   ════════════════════════════════════════════════════════ */
const COMMENT_TOKEN = { python:'#', javascript:'//', java:'//', c:'/*', php:'//', go:'//' };

/* ════════════════════════════════════════════════════════
   ████  SEMVER COMPARISON  ████
   ════════════════════════════════════════════════════════ */
function parseVer(v) {
  return String(v).replace(/[^0-9.]/g,'').split('.').map(Number);
}
function versionLT(a, b) {
  const pa = parseVer(a), pb = parseVer(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const ai = pa[i]||0, bi = pb[i]||0;
    if (ai < bi) return true;
    if (ai > bi) return false;
  }
  return false;
}

/* ════════════════════════════════════════════════════════
   ████  DEPENDENCY FILE PARSERS  ████
   ════════════════════════════════════════════════════════ */
function parseRequirementsTxt(text) {
  const deps = [];
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith('-') || line.startsWith('git+')) continue;
    const m = line.match(/^([a-zA-Z0-9_.\-]+)\s*(?:==|>=|<=|~=|!=|===)\s*([0-9]+(?:\.[0-9]+)*(?:\.[0-9]+)*)/);
    if (m) deps.push({ name: m[1].toLowerCase().replace(/_/g,'-'), version: m[2] });
  }
  return deps;
}

function parsePackageJson(text) {
  try {
    const pkg = JSON.parse(text);
    const deps = [];
    const all = { ...(pkg.dependencies||{}), ...(pkg.devDependencies||{}) };
    for (const [name, ver] of Object.entries(all)) {
      const clean = String(ver).replace(/^[\^~>=<v]+/,'').split(' ')[0];
      if (/^\d/.test(clean)) deps.push({ name: name.toLowerCase(), version: clean });
    }
    return deps;
  } catch { return []; }
}

function parseGoMod(text) {
  const deps = [];
  for (const line of text.split('\n')) {
    const m = line.trim().match(/^([^\s]+)\s+v([0-9]+\.[0-9]+(?:\.[0-9]+)?)/);
    if (m) deps.push({ name: m[1].toLowerCase(), version: m[2] });
  }
  return deps;
}

/* ════════════════════════════════════════════════════════
   ████  DEP CVE SCANNER  ████
   ════════════════════════════════════════════════════════ */
let currentDepType = 'python';

function initDepScanner() {
  // File type tabs
  document.querySelectorAll('.dep-tab').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.dep-tab').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentDepType = btn.dataset.deptype;
      updateDepPlaceholder();
    });
  });

  document.getElementById('depScanBtn').addEventListener('click', runDepScan);
  document.getElementById('depSampleBtn').addEventListener('click', () => {
    document.getElementById('depInput').value = DEP_SAMPLES[currentDepType];
  });
  document.getElementById('depClearBtn').addEventListener('click', () => {
    document.getElementById('depInput').value = '';
    resetDepResults();
  });
}

function updateDepPlaceholder() {
  const hints = {
    python: 'Paste requirements.txt content here...',
    npm:    'Paste package.json content here...',
    go:     'Paste go.mod content here...',
  };
  document.getElementById('depInput').placeholder = hints[currentDepType] || '';
}

function resetDepResults() {
  document.getElementById('depPlaceholder').style.display = 'flex';
  document.getElementById('depStatsRow').style.display = 'none';
  document.getElementById('depCveList').innerHTML = '';
}

function runDepScan() {
  const text = document.getElementById('depInput').value.trim();
  if (!text) { shakeBtn('depScanBtn'); return; }

  const parsers = { python: parseRequirementsTxt, npm: parsePackageJson, go: parseGoMod };
  const deps = (parsers[currentDepType] || (() => []))(text);
  const cveDb = CVE_DATABASE[currentDepType] || [];

  const findings = [];
  const safePkgs = [];

  for (const dep of deps) {
    const matches = cveDb.filter(rule =>
      rule.name === dep.name && versionLT(dep.version, rule.lt)
    );
    if (matches.length > 0) {
      findings.push({ dep, cves: matches });
    } else {
      safePkgs.push(`${dep.name}@${dep.version}`);
    }
  }

  // Sort findings: critical first
  const sevOrder = { critical:0, high:1, medium:2, low:3 };
  findings.sort((a,b) => {
    const topA = Math.min(...a.cves.map(c => sevOrder[c.severity]||3));
    const topB = Math.min(...b.cves.map(c => sevOrder[c.severity]||3));
    return topA - topB;
  });

  renderDepResults(deps.length, findings, safePkgs);
}

function renderDepResults(totalPkgs, findings, safePkgs) {
  const placeholder = document.getElementById('depPlaceholder');
  const statsRow    = document.getElementById('depStatsRow');
  const cveList     = document.getElementById('depCveList');

  placeholder.style.display = 'none';
  statsRow.style.display = 'flex';

  const vulnCount = findings.length;
  const critCount = findings.filter(f => f.cves.some(c => c.severity === 'critical')).length;

  document.getElementById('depStatTotal').querySelector('.dep-stat-n').textContent = totalPkgs;
  document.getElementById('depStatVuln').querySelector('.dep-stat-n').textContent  = vulnCount;
  document.getElementById('depStatCrit').querySelector('.dep-stat-n').textContent  = critCount;
  document.getElementById('depStatSafe').querySelector('.dep-stat-n').textContent  = totalPkgs - vulnCount;

  if (findings.length === 0) {
    cveList.innerHTML = `
      <div style="text-align:center;padding:40px 20px;color:var(--green)">
        <div style="font-size:48px;margin-bottom:12px">✅</div>
        <div style="font-size:16px;font-weight:700;margin-bottom:6px">No Known CVEs Detected!</div>
        <div style="font-size:12px;color:var(--text-muted)">All ${totalPkgs} packages appear clean in our database.</div>
      </div>`;
    return;
  }

  cveList.innerHTML = findings.map(f => {
    const topSev = f.cves.reduce((acc, c) => (sevOrder_(c.severity) < sevOrder_(acc) ? c.severity : acc), f.cves[0].severity);
    return `
    <div class="dep-cve-card sev-${topSev}" style="animation-delay:${findings.indexOf(f)*60}ms">
      <div class="dep-cve-header" onclick="toggleCveCard(this)">
        <span class="dep-cve-sev" style="${sevStyle(topSev)}">${topSev.toUpperCase()}</span>
        <span class="dep-cve-pkg">${escHtml(f.dep.name)}</span>
        <span class="dep-cve-ver">v${escHtml(f.dep.version)}</span>
        <span class="dep-cve-title-text">${escHtml(f.cves[0].title)}</span>
        <span class="dep-cve-id">${f.cves.length > 1 ? f.cves.length + ' CVEs' : f.cves[0].cve}</span>
        <span style="color:var(--text-muted);margin-left:4px;font-size:12px">▼</span>
      </div>
      <div class="dep-cve-body" style="display:none">
        ${f.cves.map(c => `
          <div style="margin-bottom:12px;padding-bottom:12px;border-bottom:1px solid var(--border)">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
              <span class="dep-cve-sev" style="${sevStyle(c.severity)}">${c.severity.toUpperCase()}</span>
              <span style="font-weight:600;font-size:13px">${escHtml(c.title)}</span>
              <span class="dep-cve-id">${escHtml(c.cve)}</span>
            </div>
            <div class="dep-cve-desc">${escHtml(c.desc)}</div>
            <div class="dep-cve-fix">🔧 <strong>Fix:</strong> Upgrade to ${escHtml(c.fixed)}</div>
          </div>`).join('')}
      </div>
    </div>`;
  }).join('') +
  (safePkgs.length > 0 ? `
    <div class="dep-safe-list">
      <div class="dep-safe-title">✅ ${safePkgs.length} packages with no known CVEs</div>
      <div class="dep-safe-chips">${safePkgs.map(p => `<span class="dep-safe-chip">${escHtml(p)}</span>`).join('')}</div>
    </div>` : '');
}

function sevOrder_(s) { return ({critical:0,high:1,medium:2,low:3})[s]||3; }
function sevStyle(s) {
  const m = {
    critical:'background:rgba(255,45,85,0.15);color:#ff2d55;border:1px solid rgba(255,45,85,0.3)',
    high:'background:rgba(255,107,53,0.15);color:#ff6b35;border:1px solid rgba(255,107,53,0.3)',
    medium:'background:rgba(255,204,2,0.15);color:#ffcc02;border:1px solid rgba(255,204,2,0.3)',
    low:'background:rgba(0,212,255,0.15);color:#00d4ff;border:1px solid rgba(0,212,255,0.3)',
  };
  return m[s]||'';
}

window.toggleCveCard = (header) => {
  const body = header.nextElementSibling;
  const arrow = header.querySelector('span:last-child');
  const isOpen = body.style.display !== 'none';
  body.style.display = isOpen ? 'none' : 'block';
  arrow.textContent = isOpen ? '▼' : '▲';
};

/* ════════════════════════════════════════════════════════
   ████  🔥 VULNERABILITY HEATMAP ENGINE  ████
   ════════════════════════════════════════════════════════ */
let heatmapActive = false;

function initHeatmap() {
  document.getElementById('heatmapToggle').addEventListener('click', toggleHeatmap);
}

function toggleHeatmap() {
  heatmapActive = !heatmapActive;
  const btn = document.getElementById('heatmapToggle');
  btn.classList.toggle('active', heatmapActive);
  btn.textContent = heatmapActive ? '🔥 Heatmap ON' : '🔥 Heatmap';

  if (heatmapActive && typeof editor !== 'undefined' && lastFindings.length > 0) {
    applyHeatmap(lastFindings);
  } else {
    clearHeatmap();
  }
}

function applyHeatmap(findings) {
  if (!editor) return;
  clearHeatmap();

  // Add custom gutter
  try { editor.setOption('gutters', ['CodeMirror-linenumbers', 'heatmap-gutter']); } catch(e){}

  findings.forEach(f => {
    const idx = f.lineNumber - 1;
    if (idx < 0 || idx >= editor.lineCount()) return;

    // Background class
    editor.addLineClass(idx, 'background', `cm-heatmap-${f.severity}`);

    // Gutter marker
    const marker = document.createElement('div');
    marker.className = `cm-heatmap-gutter-${f.severity}`;
    marker.title = `[${f.severity.toUpperCase()}] ${f.name} — ${f.cwe}`;
    marker.style.cssText = 'width:5px;height:100%;border-radius:2px;margin:1px 3px;cursor:help';
    editor.setGutterMarker(idx, 'heatmap-gutter', marker);

    // Inline tooltip widget
    const widget = document.createElement('span');
    widget.className = 'heatmap-inline-badge';
    widget.textContent = ` ← ${f.severity.toUpperCase()}: ${f.name}`;
    widget.style.cssText = `
      font-size:10px;font-family:Inter,sans-serif;font-weight:600;
      padding:1px 6px;border-radius:4px;margin-left:6px;
      opacity:0.8;pointer-events:none;vertical-align:middle;
      ${sevStyleInline(f.severity)}`;
    editor.addWidget({ line: idx, ch: editor.getLine(idx).length }, widget, false);
  });

  // Scroll to first critical finding
  const first = findings.find(f => f.severity === 'critical') || findings[0];
  if (first) editor.scrollIntoView({ line: first.lineNumber - 1, ch: 0 }, 100);
}

function sevStyleInline(s) {
  const m = {
    critical:'background:rgba(255,45,85,0.2);color:#ff8099;border:1px solid rgba(255,45,85,0.4)',
    high:'background:rgba(255,107,53,0.15);color:#ff9060;border:1px solid rgba(255,107,53,0.3)',
    medium:'background:rgba(255,204,2,0.12);color:#ffcc60;border:1px solid rgba(255,204,2,0.3)',
    low:'background:rgba(0,212,255,0.08);color:#60d4ff;border:1px solid rgba(0,212,255,0.2)',
  };
  return m[s]||'';
}

function clearHeatmap() {
  if (!editor) return;
  for (let i = 0; i < editor.lineCount(); i++) {
    editor.removeLineClass(i, 'background', 'cm-heatmap-critical');
    editor.removeLineClass(i, 'background', 'cm-heatmap-high');
    editor.removeLineClass(i, 'background', 'cm-heatmap-medium');
    editor.removeLineClass(i, 'background', 'cm-heatmap-low');
    editor.setGutterMarker(i, 'heatmap-gutter', null);
  }
  // Remove inline widgets
  document.querySelectorAll('.heatmap-inline-badge').forEach(el => el.remove());
}

/* ════════════════════════════════════════════════════════
   ████  🤖 SECURE CODE GENERATOR  ████
   ════════════════════════════════════════════════════════ */
function initCodeFixer() {
  document.getElementById('fixBtn').addEventListener('click', openFixModal);
  document.getElementById('fixModalClose').addEventListener('click', closeFixModal);
  document.getElementById('fixModalOverlay').addEventListener('click', e => {
    if (e.target === e.currentTarget) closeFixModal();
  });
  document.getElementById('copyFixBtn').addEventListener('click', copyFixedCode);
  document.addEventListener('keydown', e => { if (e.key==='Escape') closeFixModal(); });
}

function generateSecureCode(originalCode, findings, language) {
  const lines = originalCode.split('\n');
  const changeLog = [];
  const autoFixed = new Set();
  const manualRequired = new Set();
  const fixers = CODE_FIXERS[language] || {};
  const cmtToken = COMMENT_TOKEN[language] || '//';

  // Group findings by line (one fix per line — most severe wins)
  const byLine = {};
  for (const f of findings) {
    if (!byLine[f.lineNumber] || sevOrder_(f.severity) < sevOrder_(byLine[f.lineNumber].severity)) {
      byLine[f.lineNumber] = f;
    }
  }

  for (const [lineNumStr, f] of Object.entries(byLine)) {
    const idx = parseInt(lineNumStr) - 1;
    if (idx < 0 || idx >= lines.length) continue;
    const original = lines[idx];
    const fixer = fixers[f.id];

    if (fixer) {
      try {
        const fixed = fixer(original);
        if (fixed !== original) {
          lines[idx] = fixed;
          autoFixed.add(idx);
          changeLog.push({ line: parseInt(lineNumStr), name: f.name, cwe: f.cwe, auto: true });
        }
      } catch(e) {
        // Fallback to manual
        const indent = original.match(/^\s*/)[0];
        lines[idx] = `${indent}${cmtToken} ⚠️ MANUAL FIX REQUIRED: ${f.name} (${f.cwe})\n${indent}${cmtToken} ${original.trim()}`;
        manualRequired.add(idx);
        changeLog.push({ line: parseInt(lineNumStr), name: f.name, cwe: f.cwe, auto: false });
      }
    } else {
      const indent = original.match(/^\s*/)[0];
      lines[idx] = `${indent}${cmtToken} ⚠️ MANUAL FIX REQUIRED: ${f.name} (${f.cwe})\n${indent}${cmtToken} ${original.trim()}`;
      manualRequired.add(idx);
      changeLog.push({ line: parseInt(lineNumStr), name: f.name, cwe: f.cwe, auto: false });
    }
  }

  return { fixedCode: lines.join('\n'), changeLog, autoFixed, manualRequired, originalLines: originalCode.split('\n') };
}

function openFixModal() {
  if (!lastFindings.length) return;
  const lang    = document.getElementById('languageSelect').value;
  const original = typeof editor !== 'undefined' ? editor.getValue() : '';
  const { fixedCode, changeLog, autoFixed, manualRequired, originalLines } = generateSecureCode(original, lastFindings, lang);

  // Stats bar
  document.getElementById('fixStatsBar').innerHTML = `
    <div class="fix-stat-chip fix-stat-total">📄 ${originalLines.length} lines total</div>
    <div class="fix-stat-chip fix-stat-auto">✅ ${autoFixed.size} auto-fixed</div>
    <div class="fix-stat-chip fix-stat-manual">⚠️ ${manualRequired.size} need manual review</div>`;

  // Render diff panels
  renderDiffPanel('fixOriginalCode', originalLines, autoFixed, manualRequired, 'bad');
  renderDiffPanel('fixSecureCode',   fixedCode.split('\n'), autoFixed, manualRequired, 'good');

  // Changelog
  document.getElementById('fixChangelog').innerHTML = changeLog.length > 0 ?
    changeLog.map(c => `
      <div class="fix-change-item">
        <span class="fix-change-tag ${c.auto ? 'fix-tag-auto' : 'fix-tag-manual'}">${c.auto ? '✅ AUTO' : '⚠️ MANUAL'}</span>
        <span class="fix-change-desc">${escHtml(c.name)}</span>
        <span class="fix-change-line">(${c.cwe} · Line ${c.line})</span>
      </div>`).join('') :
    '<span style="color:var(--text-muted);font-size:12px">No changes generated</span>';

  // Store for copy
  window._secureFixedCode = fixedCode;

  // Open modal
  document.getElementById('fixModalOverlay').classList.add('open');
  document.body.style.overflow = 'hidden';
}

function renderDiffPanel(containerId, lines, autoFixed, manualRequired, type) {
  const container = document.getElementById(containerId);
  const isFixed = type === 'good';

  container.innerHTML = lines.map((line, i) => {
    const isAuto   = autoFixed.has(i);
    const isManual = manualRequired.has(i);
    const cls = (isAuto || isManual) ? (isFixed ? 'changed-good' : 'changed-bad') : '';
    return `<div class="fix-line ${cls}">
      <span class="fix-line-num">${i+1}</span>
      <span class="fix-line-content">${escHtml(line)||'&nbsp;'}</span>
    </div>`;
  }).join('');
}

function closeFixModal() {
  document.getElementById('fixModalOverlay').classList.remove('open');
  document.body.style.overflow = '';
}

function copyFixedCode() {
  const code = window._secureFixedCode || '';
  navigator.clipboard.writeText(code).then(() => {
    const btn = document.getElementById('copyFixBtn');
    btn.textContent = '✅ Copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = '📋 Copy Fixed Code'; btn.classList.remove('copied'); }, 2200);
  }).catch(() => {
    // Fallback
    const ta = document.createElement('textarea');
    ta.value = code; document.body.appendChild(ta);
    ta.select(); document.execCommand('copy');
    document.body.removeChild(ta);
  });
}

/* ════════════════════════════════════════════════════════
   ████  HOOK INTO MAIN SCAN RESULTS  ████
   After main scan: enable buttons, apply heatmap if active
   ════════════════════════════════════════════════════════ */
function hookScanComplete(findings) {
  // Enable heatmap + fix buttons
  const heatmapBtn = document.getElementById('heatmapToggle');
  const fixBtn     = document.getElementById('fixBtn');
  const fixBadge   = document.getElementById('fixBadge');

  heatmapBtn.disabled = findings.length === 0;
  fixBtn.disabled     = findings.length === 0;

  if (findings.length > 0) {
    const lang = document.getElementById('languageSelect').value;
    const fixers = CODE_FIXERS[lang] || {};
    const autoFixable = findings.filter(f => fixers[f.id]).length;
    fixBadge.textContent = autoFixable > 0 ? `${autoFixable} auto` : '';

    // Auto-apply heatmap if it was active
    if (heatmapActive) applyHeatmap(findings);
    else clearHeatmap();
  } else {
    clearHeatmap();
    heatmapActive = false;
    heatmapBtn.classList.remove('active');
    heatmapBtn.textContent = '🔥 Heatmap';
  }
}

/* ════════════════════════════════════════════════════════
   ████  PATCH: intercept displayResults  ████
   ════════════════════════════════════════════════════════ */
(function patchDisplayResults() {
  const origDisplay = window.displayResults || (() => {});
  window.displayResults = function(findings, lang) {
    origDisplay(findings, lang);
    // Run our hook after original
    setTimeout(() => hookScanComplete(findings), 100);
  };
})();

/* ════════════════════════════════════════════════════════
   ████  UTILITIES  ████
   ════════════════════════════════════════════════════════ */
function escHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function shakeBtn(id) {
  const el = document.getElementById(id);
  if (!el) return;
  el.style.animation = 'none'; el.offsetHeight;
  el.style.animation = 'shake 0.4s ease';
  el.addEventListener('animationend', () => el.style.animation = '', { once: true });
}

/* ════════════════════════════════════════════════════════
   ████  BOOT  ████
   ════════════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', () => {
  initDepScanner();
  initHeatmap();
  initCodeFixer();
});
