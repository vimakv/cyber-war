from flask import Flask, request, render_template, redirect, session, jsonify, send_file
import sqlite3, threading, json, os, random, time
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message

# SCANNERS
from scanner.sql_injection import scan_sql
from scanner.xss import scan_xss
from scanner.headers import scan_headers
from scanner.open_redirect import scan_redirect
from scanner.crawler import crawl

# UTILS
from utils.severity import calculate_severity
from ai import explain
from report import generate_report

app = Flask(__name__)

# 🔐 SECRET KEY
app.secret_key = os.environ.get("SECRET_KEY", "dev_key")

# 📧 MAIL CONFIG
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get("EMAIL_USER")
app.config['MAIL_PASSWORD'] = os.environ.get("EMAIL_PASS")

mail = Mail(app)

verification_codes = {}
scan_status = {}
DB_PATH = "database.db"

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
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        code = str(random.randint(100000, 999999))

        verification_codes[email] = {
            "code": code,
            "username": username,
            "password": generate_password_hash(password),
            "time": time.time()
        }

        try:
            msg = Message(
                "Verify your account",
                sender=app.config['MAIL_USERNAME'],
                recipients=[email]
            )
            msg.body = f"Your OTP is: {code} (valid 5 minutes)"
            mail.send(msg)
        except Exception as e:
            print("MAIL ERROR:", e)

        return f"""
        <h2>OTP Generated</h2>
        <p>Your OTP: <b>{code}</b></p>
        <a href='/verify_page?email={email}'>Verify</a>
        """

    return render_template("register.html")

# ================= VERIFY PAGE =================
@app.route('/verify_page')
def verify_page():
    email = request.args.get('email')
    return render_template("verify.html", email=email)

# ================= VERIFY =================
@app.route('/verify', methods=['POST'])
def verify():
    email = request.form['email']
    code = request.form['code']

    data = verification_codes.get(email)

    if not data:
        return "Session expired"

    if time.time() - data["time"] > 300:
        verification_codes.pop(email)
        return "OTP expired"

    if data["code"] == code:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()

        try:
            cur.execute(
                "INSERT INTO users (username,email,password) VALUES (?,?,?)",
                (data["username"], email, data["password"])
            )
            conn.commit()
        except:
            return "User exists"

        conn.close()
        verification_codes.pop(email)

        return redirect('/login')

    return "Invalid OTP"

# ================= LOGIN =================
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT id,password FROM users WHERE username=?", (username,))
        user = cur.fetchone()
        conn.close()

        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            return redirect('/scanner')

        return "Invalid login"

    return render_template("login.html")

# ================= LOGOUT (FINAL FIX) =================
@app.route('/logout')
def logout():
    session.pop('user_id', None)   # 🔥 remove only user
    return redirect('/login')

# ================= SCAN =================
def run_scan(url, user_id):
    result = {}

    try:
        pages = crawl(url)
        result["Pages"] = len(pages)

        result['SQL'] = scan_sql(url)
        result['XSS'] = scan_xss(url)
        result['Headers'] = scan_headers(url)
        result['Redirect'] = scan_redirect(url)

        result['Severity'] = calculate_severity(result)
        result['AI'] = explain(result)

    except Exception as e:
        result['Error'] = str(e)

    generate_report(url, result)

# ================= SCANNER (PROTECTED) =================
@app.route('/scanner', methods=['GET','POST'])
def scanner():
    if 'user_id' not in session:
        return redirect('/login')   # 🔥 PROTECTION

    if request.method == 'POST':
        url = request.form['url']
        threading.Thread(target=run_scan, args=(url, session['user_id'])).start()

    return render_template("index.html")

# ================= REPORT =================
@app.route('/report')
def report():
    if os.path.exists("report.pdf"):
        return send_file("report.pdf", as_attachment=True)
    return "No report"

# ================= RUN =================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))