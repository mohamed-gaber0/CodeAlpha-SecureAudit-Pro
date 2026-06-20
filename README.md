<div align="center">

# 🛡️ SecureAudit Pro

**Professional-grade static code security analyzer — detect vulnerabilities before they ship.**

[![Status](https://img.shields.io/badge/status-active-success?style=flat-square)](https://mohamed-gaber0.github.io/CodeAlpha-SecureAudit-Pro/)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=flat-square&logo=html5&logoColor=white)](#)
[![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=flat-square&logo=css3&logoColor=white)](#)
[![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=flat-square&logo=javascript&logoColor=black)](#)
[![CodeAlpha](https://img.shields.io/badge/CodeAlpha-Internship-7c3aed?style=flat-square)](#)

**[🔗 Live Demo](https://mohamed-gaber0.github.io/CodeAlpha-SecureAudit-Pro/)** • **[🎥 Video Walkthrough](https://drive.google.com/file/d/1iEsInAPiQqQrKXrI-FpvXkTq8ICesQZm/view?usp=sharing)** • **[📄 Sample Audit Report](reports/security-audit-report.html)**

</div>

---

## 📌 Overview

SecureAudit Pro scans source code for security vulnerabilities across **6 programming languages**, maps every finding to **OWASP Top 10** and **CWE**, and generates a professional, exportable audit report — entirely **client-side**, with zero data ever leaving the browser.

> Built during my Cybersecurity Internship at **[CodeAlpha](https://www.codealpha.tech/)**.

## 📑 Table of Contents

- [Features](#-features)
- [Live Demo](#-live-demo)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Example: Auditing a Vulnerable App](#-example-auditing-a-vulnerable-app)
- [Vulnerability Coverage](#-vulnerability-coverage)
- [Getting Started](#-getting-started)
- [License](#-license)
- [Acknowledgements](#-acknowledgements)

## ✨ Features

| | |
|---|---|
| 🌐 **Multi-language scanning** | Python, JavaScript, Java, C/C++, PHP, Go |
| 🔎 **55+ detection rules** | Mapped to OWASP Top 10 and CWE |
| 🤖 **AI-powered auto-fix** | Turns vulnerable code into secure code in one click |
| 📦 **Dependency CVE scanner** | Paste `requirements.txt`, `package.json`, or `go.mod` for an instant CVE report |
| 📄 **Professional audit reports** | Executive summary, security score, proof-of-concept per finding, prioritized remediation roadmap — exportable to PDF |
| 🔒 **100% client-side** | No code is ever transmitted or stored externally |

## 🎬 Live Demo

🔗 **[mohamed-gaber0.github.io/CodeAlpha-SecureAudit-Pro](https://mohamed-gaber0.github.io/CodeAlpha-SecureAudit-Pro/)**
🎥 **[Watch the video walkthrough](https://drive.google.com/file/d/1iEsInAPiQqQrKXrI-FpvXkTq8ICesQZm/view?usp=sharing)**

## 🛠 Tech Stack

HTML5 · CSS3 · Vanilla JavaScript · [CodeMirror 5](https://codemirror.net/5/)

No frameworks, no build step, no backend — the entire engine runs in the browser.

## 📂 Project Structure

```
CodeAlpha-SecureAudit-Pro/
├── README.md
├── LICENSE
├── .gitignore
├── assets/
│   └── logo.png
├── src/
│   ├── SecureAudit_Pro.html
│   ├── secure-review.css
│   ├── secure-review.js
│   ├── secure-review-features.js
│   ├── cyber-hud.css
│   └── cyber-hud.js
├── docs/
│   └── presentation.html
├── reports/
│   └── security-audit-report.html
└── examples/
    └── student_portal.py
```

## 🧪 Example: Auditing a Vulnerable App

`examples/student_portal.py` is a deliberately vulnerable Flask application — **12 intentional security flaws** — built specifically to validate detection accuracy. SecureAudit Pro identified every single one.

The full generated report is available at [`reports/security-audit-report.html`](reports/security-audit-report.html), including:
- Executive summary with an overall security score
- Proof-of-concept for each finding
- OWASP Top 10 coverage matrix
- A 3-phase prioritized remediation roadmap

> ⚠️ **Note:** All credentials, tokens, and secrets in `student_portal.py` are fake placeholders created purely for demonstration. They are not real and were never valid.

## 🎯 Vulnerability Coverage

| Category | CWE | Example |
|---|---|---|
| SQL Injection | CWE-89 | String-concatenated SQL queries |
| Remote Code Execution | CWE-95 | `eval()` / `exec()` on user input |
| Insecure Deserialization | CWE-502 | `pickle.loads()` on untrusted data |
| Hardcoded Credentials | CWE-798 | Secrets embedded in source code |
| Weak Cryptographic Hashing | CWE-327 | MD5 used for password storage |
| Insecure Randomness | CWE-330 | `random` used for session tokens |
| OS Command Injection | CWE-78 | Unsanitized input passed to shell commands |
| Insecure Deserialization (YAML) | CWE-502 | `yaml.load()` without a safe loader |
| Disabled Certificate Verification | CWE-295 | `verify=False` on outbound requests |
| Insecure Configuration | CWE-489 | Debug mode exposed on a public host |

## 🚀 Getting Started

```bash
git clone https://github.com/mohamed-gaber0/CodeAlpha-SecureAudit-Pro.git
cd CodeAlpha-SecureAudit-Pro/src
# open SecureAudit_Pro.html in any browser — no build step required
```

## 📄 License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for details.

## 🙏 Acknowledgements

Built as part of the **[CodeAlpha](https://www.codealpha.tech/)** Cybersecurity Internship.

---

<div align="center">

If this project was useful or interesting, consider leaving a ⭐ — it helps a lot.

</div>
