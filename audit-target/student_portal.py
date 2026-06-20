# =============================================================================
#  StudentPortal v1.2.0 — Student Management Web Application
#  Framework: Python 3.11 / Flask 2.1.3 / SQLite3
#  Purpose:   Academic student records, grade management, report generation
#  WARNING:   This file is the AUDIT TARGET for SecureAudit Pro Task 3
# =============================================================================

import sqlite3
import hashlib
import random
import pickle
import subprocess
import os
import yaml
import requests
from flask import Flask, request, render_template_string, session, redirect, jsonify

app = Flask(__name__)
app.secret_key = "mysecretkey123"          # [VULN-07] Hardcoded Flask secret key

# ── Database & Service Credentials (hardcoded) ────────────────────────────────
DB_HOST       = "db.university.local"
DB_PASSWORD   = "Univ3rs!ty@2024"          # [VULN-07] Hardcoded DB password
ADMIN_TOKEN   = "Bearer sk-live-abc123xyz" # [VULN-07] Hardcoded API token
SMTP_PASSWORD = "MailPass#Prod99"          # [VULN-07] Hardcoded SMTP password

# ── Database Setup ─────────────────────────────────────────────────────────────
def get_db():
    return sqlite3.connect('students.db')


# =============================================================================
#  ENDPOINT: /login  (POST)
#  Authenticates students via username + password
# =============================================================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        conn = get_db()
        cursor = conn.cursor()

        # [VULN-01] SQL Injection — string concatenation in query
        query = "SELECT * FROM users WHERE username='" + username + \
                "' AND password='" + password + "'"
        cursor.execute(query)
        user = cursor.fetchone()

        # [VULN-06] Weak hashing — MD5 for password storage
        hashed_pw = hashlib.md5(password.encode()).hexdigest()

        if user:
            # [VULN-08] Insecure PRNG — random.randint for session token
            token = random.randint(100000, 999999)
            session['token'] = token
            session['user']  = username
            return redirect('/dashboard')

        return render_template_string('<h3>Invalid credentials</h3><a href="/login">Back</a>')

    return render_template_string('''
        <form method="post">
          <input name="username" placeholder="Username"><br>
          <input name="password" type="password" placeholder="Password"><br>
          <button type="submit">Login</button>
        </form>
    ''')


# =============================================================================
#  ENDPOINT: /calculate  (POST)
#  Evaluates mathematical expressions submitted by students
# =============================================================================
@app.route('/calculate', methods=['POST'])
def calculate():
    expression = request.form.get('expression', '')

    # [VULN-02] Code Injection — eval() with unsanitised user input
    result = eval(expression)
    return jsonify({'result': str(result)})


# =============================================================================
#  ENDPOINT: /run-script  (POST)
#  Runs custom Python scripts submitted by admin users
# =============================================================================
@app.route('/run-script', methods=['POST'])
def run_script():
    script = request.form.get('script', '')

    # [VULN-03] Code Injection — exec() with unsanitised user input
    exec(script)
    return jsonify({'status': 'executed'})


# =============================================================================
#  ENDPOINT: /upload-profile  (POST)
#  Restores a student profile from a previously exported file
# =============================================================================
@app.route('/upload-profile', methods=['POST'])
def upload_profile():
    raw_data = request.get_data()

    # [VULN-04] Insecure Deserialization — pickle.loads() on untrusted input
    profile = pickle.loads(raw_data)
    return jsonify({'name': str(profile.get('name', ''))})


# =============================================================================
#  ENDPOINT: /generate-report  (POST)
#  Generates a PDF report for a given student ID
# =============================================================================
@app.route('/generate-report', methods=['POST'])
def generate_report():
    student_id  = request.form.get('student_id', '')
    report_type = request.form.get('format', 'pdf')

    # [VULN-05a] Command Injection — subprocess with shell=True + user input
    cmd = f"python tools/report_gen.py --id {student_id} --format {report_type}"
    output = subprocess.check_output(cmd, shell=True)
    return output


# =============================================================================
#  ENDPOINT: /ping  (POST)
#  Admin tool: checks connectivity to an internal server by hostname
# =============================================================================
@app.route('/ping', methods=['POST'])
def ping_host():
    host = request.form.get('host', '')

    # [VULN-05b] OS Command Injection — os.system() with user-controlled host
    os.system(f"ping -c 4 {host}")
    return jsonify({'status': 'sent'})


# =============================================================================
#  ENDPOINT: /import-config  (POST)
#  Imports application configuration from a YAML payload
# =============================================================================
@app.route('/import-config', methods=['POST'])
def import_config():
    yaml_payload = request.get_data(as_text=True)

    # [VULN-09] Insecure YAML deserialization — yaml.load() without safe Loader
    config = yaml.load(yaml_payload)
    return jsonify({'loaded_keys': list(config.keys()) if isinstance(config, dict) else []})


# =============================================================================
#  ENDPOINT: /proxy  (POST)
#  Fetches external resource on behalf of the student (proxy feature)
# =============================================================================
@app.route('/proxy', methods=['POST'])
def proxy_fetch():
    target_url = request.form.get('url', '')

    # [VULN-10] TLS Certificate Verification Disabled — verify=False
    response = requests.get(target_url, verify=False, timeout=10)
    return response.text


# =============================================================================
#  ENDPOINT: /dashboard  (GET)
#  Student dashboard — shows grades, attendance, schedule
# =============================================================================
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/login')
    return render_template_string(f'<h1>Welcome {session["user"]}</h1>')


# =============================================================================
#  Application entry point
# =============================================================================
if __name__ == '__main__':
    # [VULN-11] Debug Mode + Exposed Host — debug=True on 0.0.0.0
    app.run(debug=True, host='0.0.0.0', port=5000)
