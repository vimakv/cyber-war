from flask import Flask, request, render_template, redirect, session, jsonify
import sqlite3, os, requests, re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_key")

DB_PATH = "database.db"

scan_logs = {}
scan_status = {}
scan_history = {}

# ================= DATABASE =================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )
    """)
    conn.commit()
    conn.close()

init_db()

# ================= UTIL =================
def check_sql_payload(url):
    payloads = ["' OR '1'='1", "'--", "\" OR \"1\"=\"1"]
    for p in payloads:
        try:
            r = requests.get(url + p, timeout=5)
            if "sql" in r.text.lower() or "syntax" in r.text.lower():
                return True
        except:
            pass
    return False

def detect_login_form(html):
    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")

    for f in forms:
        inputs = f.find_all("input")
        names = [i.get("name","").lower() for i in inputs]
        if "password" in names:
            return True
    return False

def check_phishing(url):
    issues = []
    domain = urlparse(url).netloc

    if "@" in url:
        issues.append("❌ URL contains @ (phishing)")

    if re.match(r"^\d+\.\d+\.\d+\.\d+", domain):
        issues.append("❌ IP address used")

    if len(domain) > 25:
        issues.append("⚠ Long domain name")

    return issues

def calculate_verdict(logs):
    score = 0
    for l in logs:
        if "❌" in l:
            score += 3
        elif "⚠" in l:
            score += 1

    if score >= 6:
        return "🔴 Dangerous"
    elif score >= 3:
        return "🟡 Medium"
    return "🟢 Safe"

# ================= ROUTES =================
@app.route('/')
def home():
    return redirect('/login')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        u = request.form['username']
        p = generate_password_hash(request.form['password'])
        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("INSERT INTO users VALUES(NULL,?,?)",(u,p))
            conn.commit()
            conn.close()
            return redirect('/login')
        except:
            return "User exists"
    return render_template("register.html")

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

    return render_template("login.html")

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

# ================= SCANNER =================
@app.route('/scanner', methods=['GET','POST'])
def scanner():
    if 'user_id' not in session:
        return redirect('/login')

    uid = session['user_id']

    if request.method == 'POST':
        url = request.form.get('url')

        if not url.startswith("http"):
            url = "http://" + url

        scan_logs[uid] = []
        scan_status[uid] = "Scanning..."

        try:
            res = requests.get(url, timeout=5)
            html = res.text

            scan_logs[uid].append("🌐 Site reachable")

            # SQL
            scan_logs[uid].append("🧪 Testing SQL payloads...")
            if check_sql_payload(url):
                scan_logs[uid].append("❌ SQL Injection detected")
            else:
                scan_logs[uid].append("✅ SQL safe")

            # Login form
            scan_logs[uid].append("🕵️ Checking login forms...")
            if detect_login_form(html):
                scan_logs[uid].append("⚠ Login form detected")
            else:
                scan_logs[uid].append("✅ No login form")

            # Headers
            if "X-Frame-Options" not in res.headers:
                scan_logs[uid].append("⚠ Missing security headers")

            # Phishing
            scan_logs[uid].extend(check_phishing(url))

            verdict = calculate_verdict(scan_logs[uid])
            scan_logs[uid].append(f"📊 Verdict: {verdict}")

            scan_history.setdefault(uid, []).append({
                "url": url,
                "verdict": verdict
            })

            scan_status[uid] = "Completed ✅"

        except Exception as e:
            scan_logs[uid].append(str(e))
            scan_status[uid] = "Error ❌"

        return render_template("index.html")

    return render_template("index.html")

# ================= STATUS =================
@app.route('/status')
def status():
    uid = session.get('user_id')
    return jsonify({
        "status": scan_status.get(uid,"Idle"),
        "logs": scan_logs.get(uid,[])
    })

# ================= HISTORY =================
@app.route('/history')
def history():
    uid = session.get('user_id')
    return render_template("history.html", data=scan_history.get(uid,[]))

# ================= RUN =================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))