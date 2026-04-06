from flask import Flask, request, render_template, redirect, session, jsonify, send_file
import sqlite3, threading, json, os
from werkzeug.security import generate_password_hash, check_password_hash

# SCANNERS
from scanner.sql_injection import scan_sql
from scanner.xss import scan_xss
from scanner.headers import scan_headers
from scanner.open_redirect import scan_redirect

# UTILS
from utils.severity import calculate_severity
from ai import explain
from report import generate_report

app = Flask(__name__)

# 🔐 SECURE SECRET KEY (NO HARDCODE)
app.secret_key = os.environ.get("SECRET_KEY", "fallback_dev_key")

DB_PATH = os.environ.get("DB_PATH", "database.db")
scan_status = {}

# ================= DATABASE =================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT,
        password TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT,
        result TEXT,
        user_id INTEGER
    )
    """)

    conn.commit()
    conn.close()

init_db()

# ================= HOME =================
@app.route('/')
def home():
    return redirect('/login')

# ================= REGISTER =================
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        u = request.form['username']
        e = request.form['email']
        p = request.form['password']

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()

        try:
            cur.execute(
                "INSERT INTO users (username,email,password) VALUES (?,?,?)",
                (u, e, generate_password_hash(p))
            )
            conn.commit()
        except:
            return "User already exists"

        conn.close()
        return redirect('/login')

    return render_template("register.html")

# ================= LOGIN =================
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        u = request.form['username']
        p = request.form['password']

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT id,password FROM users WHERE username=?", (u,))
        user = cur.fetchone()
        conn.close()

        if user and check_password_hash(user[1], p):
            session['user_id'] = user[0]
            return redirect('/scanner')

        return "Invalid login"

    return render_template("login.html")

# ================= LOGOUT =================
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

# ================= SCAN FUNCTION =================
def run_scan(url, user_id):
    scan_status[user_id] = "Scanning..."

    result = {}

    try:
        result['SQL'] = scan_sql(url)
        scan_status[user_id] = "Scanning XSS..."

        result['XSS'] = scan_xss(url)
        scan_status[user_id] = "Checking Headers..."

        result['Headers'] = scan_headers(url)
        scan_status[user_id] = "Checking Redirect..."

        result['Redirect'] = scan_redirect(url)

        scan_status[user_id] = "Calculating severity..."

        result['Severity'] = calculate_severity(result)

        scan_status[user_id] = "Generating AI..."

        result['AI'] = explain(result)

    except Exception as e:
        result['Error'] = str(e)

    # Save result
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO scans (url,result,user_id) VALUES (?,?,?)",
        (url, json.dumps(result), user_id)
    )
    conn.commit()
    conn.close()

    # Generate PDF
    generate_report(url, result)

    scan_status[user_id] = "Completed ✅"

# ================= SCANNER =================
@app.route('/scanner', methods=['GET','POST'])
def scanner():
    if 'user_id' not in session:
        return redirect('/login')

    if request.method == 'POST':
        url = request.form['url']

        if not url.startswith("http"):
            url = "http://" + url

        threading.Thread(
            target=run_scan,
            args=(url, session['user_id'])
        ).start()

    return render_template("index.html")

# ================= STATUS =================
@app.route('/status')
def status():
    return jsonify({
        "status": scan_status.get(session.get('user_id'), "Idle")
    })

# ================= LATEST =================
@app.route('/latest')
def latest():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute(
        "SELECT url, result FROM scans WHERE user_id=? ORDER BY id DESC LIMIT 1",
        (session.get('user_id'),)
    )

    data = cur.fetchone()
    conn.close()

    if data:
        return jsonify({
            "url": data[0],
            "result": json.loads(data[1])
        })

    return jsonify({})

# ================= DOWNLOAD REPORT =================
@app.route('/report')
def download_report():
    if os.path.exists("report.pdf"):
        return send_file("report.pdf", as_attachment=True)
    return "Report not found"

# ================= RUN =================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)