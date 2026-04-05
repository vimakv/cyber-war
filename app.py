from flask import Flask, request, render_template, redirect, session, send_file
import sqlite3, os, re, random, time
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse

# EMAIL
from flask_mail import Mail, Message

# SCANNERS
from scanner.sql_injection import scan_sql
from scanner.xss import scan_xss
from scanner.headers import scan_headers
from scanner.open_redirect import scan_redirect
from scanner.port_scanner import scan_ports
from scanner.subdomain import scan_subdomains
from scanner.bruteforce import simulate_bruteforce

from report import generate_report

app = Flask(__name__)
app.secret_key = "secret123"

DB_PATH = "database.db"

# ================= EMAIL CONFIG =================
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "cyberwarrs@gmail.com"
app.config['MAIL_PASSWORD'] = "ulyhjsrnxnikozsn"
app.config['MAIL_DEFAULT_SENDER'] = app.config['MAIL_USERNAME']

mail = Mail(app)

# ================= DATABASE =================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT,
        result TEXT,
        user_id TEXT
    )
    """)

    conn.commit()
    conn.close()

init_db()

# ================= VALIDATION =================
def valid_password(p):
    return (
        6 <= len(p) <= 12 and
        any(c.isupper() for c in p) and
        any(c.islower() for c in p) and
        any(c in "!@#$%^&*" for c in p)
    )

# ================= HOME =================
@app.route('/')
def home():
    if 'user' in session:
        return redirect('/dashboard')
    return redirect('/login')

# ================= REGISTER =================
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        u = request.form.get('username')
        e = request.form.get('email')
        p = request.form.get('password')
        cp = request.form.get('confirm_password')

        if not u or not e or not p or not cp:
            return render_template("register.html", error="All fields required")

        if not re.match(r"[^@]+@[^@]+\.[^@]+", e):
            return render_template("register.html", error="Invalid email")

        if p != cp:
            return render_template("register.html", error="Passwords mismatch")

        if not valid_password(p):
            return render_template("register.html", error="Weak password")

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()

        cur.execute("SELECT * FROM users WHERE email=?", (e,))
        if cur.fetchone():
            conn.close()
            return render_template("register.html", error="Email exists")

        conn.close()

        otp = str(random.randint(100000,999999))

        session['temp_user'] = (u,e,p)
        session['otp'] = otp
        session['otp_time'] = time.time()

        try:
            msg = Message(
                subject="Cyber War OTP Verification",
                recipients=[e]
            )
            msg.body = f"Your OTP is: {otp}"
            mail.send(msg)
            print("✅ Email sent")
        except Exception as err:
            print("❌ Email error:", err)
            print("🔥 OTP:", otp)

        return redirect('/verify')

    return render_template("register.html")

# ================= VERIFY =================
@app.route('/verify', methods=['GET','POST'])
def verify():
    if request.method == 'POST':

        if time.time() - session.get('otp_time',0) > 300:
            return "❌ OTP expired"

        if request.form.get('otp') == session.get('otp'):

            u,e,p = session.get('temp_user',(None,None,None))
            hashed = generate_password_hash(p)

            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()

            cur.execute(
                "INSERT INTO users (username,email,password) VALUES (?,?,?)",
                (u,e,hashed)
            )

            conn.commit()
            conn.close()

            session.clear()
            return redirect('/login')

        return "❌ Invalid OTP"

    return render_template("verify.html")

# ================= LOGIN =================
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        u = request.form.get('username')
        p = request.form.get('password')

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username=?", (u,))
        user = cur.fetchone()
        conn.close()

        if user and check_password_hash(user[3], p):
            session['user'] = u
            return redirect('/dashboard')

        return render_template("login.html", error="Invalid login")

    return render_template("login.html")

# ================= DASHBOARD =================
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/login')

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT * FROM scans WHERE user_id=?", (session['user'],))
    scans = cur.fetchall()
    conn.close()

    return render_template("dashboard.html", scans=scans)

# ================= SCANNER =================
@app.route('/scanner', methods=['GET','POST'])
def scanner():
    if 'user' not in session:
        return redirect('/login')

    result = {}

    if request.method == 'POST':
        url = request.form.get('url')

        if "?" not in url:
            url += "?id=1"

        parsed = urlparse(url)
        host = parsed.netloc or parsed.path

        sql = scan_sql(url)
        xss = scan_xss(url)
        headers = scan_headers(url)
        redirect_vuln = scan_redirect(url)
        ports = scan_ports(host)
        subs = scan_subdomains(host)
        brute = simulate_bruteforce()

        result['SQL Injection'] = sql
        result['XSS'] = xss
        result['Security Headers'] = headers
        result['Open Redirect'] = redirect_vuln
        result['Port Scan'] = ports
        result['Subdomains'] = subs
        result['Brute Force'] = brute

        # 🔥 SEVERITY
        if any("Vulnerable" in str(v) for v in result.values()):
            result['Severity'] = "High"
        elif "Open Ports" in result['Port Scan']:
            result['Severity'] = "Medium"
        else:
            result['Severity'] = "Low"

        # REPORT
        generate_report(url, result)

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO scans (url,result,user_id) VALUES (?,?,?)",
            (url, str(result), session['user'])
        )
        conn.commit()
        conn.close()

    return render_template("index.html", result=result)

# ================= DOWNLOAD =================
@app.route('/download')
def download():
    if os.path.exists("scan_report.pdf"):
        return send_file("scan_report.pdf", as_attachment=True)
    return "No report"

@app.route('/download_html')
def download_html():
    if os.path.exists("scan_report.html"):
        return send_file("scan_report.html", as_attachment=True)
    return "No report"

# ================= PROFILE =================
@app.route('/profile')
def profile():
    if 'user' not in session:
        return redirect('/login')

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT username,email FROM users WHERE username=?", (session['user'],))
    user = cur.fetchone()
    conn.close()

    return render_template("profile.html", user=user)

# ================= LOGOUT =================
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

# ================= RUN =================
if __name__ == "__main__":
    app.run(debug=True)