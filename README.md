# 🛡️ SecureAudit Pro

Professional-grade static code security analyzer — detect vulnerabilities before they ship.

![status](https://img.shields.io/badge/status-active-success)
![license](https://img.shields.io/badge/license-MIT-blue)

## Overview
SecureAudit Pro scans source code for security vulnerabilities across 6 languages,
maps findings to OWASP Top 10 and CWE, and generates professional, exportable audit
reports — entirely client-side.

> Built during my Cybersecurity Internship at **CodeAlpha**.

## Features
- 55+ vulnerability detection rules across Python, JavaScript, Java, C/C++, PHP, Go
- OWASP Top 10 & CWE mapping
- AI-powered one-click auto-fix
- Dependency CVE scanner (requirements.txt / package.json / go.mod)
- Exportable professional audit reports (PDF)
- 100% client-side — no code is ever transmitted

## Demo
🔗 Live demo: <GitHub Pages link>
🎥 Video walkthrough: <link>

## Tech Stack
HTML5, CSS3, Vanilla JavaScript, CodeMirror 5

## Example: Auditing a vulnerable app
`examples/student_portal.py` is a deliberately vulnerable Flask app (12 intentional
flaws — SQL injection, RCE, insecure deserialization, hardcoded credentials, etc.)
used to validate detection accuracy. See `reports/security-audit-report.html` for
the full generated report.

⚠️ **Note:** All credentials in `student_portal.py` are fake placeholders created
for demonstration purposes only.

## Run locally
\`\`\`bash
git clone https://github.com/<your-username>/secureaudit-pro.git
cd secureaudit-pro/src
# just open SecureAudit_Pro.html in a browser — no build step required
\`\`\`

## License
MIT — see [LICENSE](LICENSE)

## Acknowledgements
Built as part of the **CodeAlpha** Cybersecurity Internship.
