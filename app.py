from flask import Flask, request, render_template, redirect, jsonify, make_response
import sqlite3, threading, json, os, random, time, jwt
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

SECRET_KEY = os.environ.get("SECRET_KEY", "dev_key")

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

    conn.commit()
    conn.close()

init_db()

# ================= JWT HELPER =================
def create_token(user_id, remember=False):
    exp_time = time.time() + (86400 if remember else 900)  # 1 day or 15 min

    token = jwt.encode({
        "user_id": user_id,
        "exp": exp_time
    }, SECRET_KEY, algorithm="HS256")

    return token

def verify_token(token):
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return data["user_id"]
    except:
        return None

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

        msg = Message("Verify Account",
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[email])
        msg.body = f"OTP: {code} (valid 5 min)"

        mail.send(msg)

        return render_template("verify.html", email=email)

    return render_template("register.html")

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

        cur.execute(
            "INSERT INTO users (username,email,password) VALUES (?,?,?)",
            (data["username"], email, data["password"])
        )

        conn.commit()
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
        remember = request.form.get('remember')

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT id,password FROM users WHERE username=?", (username,))
        user = cur.fetchone()
        conn.close()

        if user and check_password_hash(user[1], password):
            token = create_token(user[0], remember)

            resp = make_response(redirect('/scanner'))
            resp.set_cookie("token", token, max_age=86400 if remember else None)

            return resp

        return "Invalid login"

    return render_template("login.html")

# ================= AUTH CHECK =================
def get_user():
    token = request.cookies.get("token")
    if not token:
        return None
    return verify_token(token)

# ================= LOGOUT =================
@app.route('/logout')
def logout():
    resp = make_response(redirect('/login'))
    resp.set_cookie("token", "", expires=0)
    return resp

# ================= SCAN =================
def run_scan(url, user_id):
    result = {}

    try:
        pages = crawl(url)
        result["Pages Scanned"] = len(pages)

        result['SQL'] = scan_sql(url)
        result['XSS'] = scan_xss(url)
        result['Headers'] = scan_headers(url)
        result['Redirect'] = scan_redirect(url)

        result['Severity'] = calculate_severity(result)
        result['AI'] = explain(result)

    except Exception as e:
        result['Error'] = str(e)

    generate_report(url, result)

# ================= SCANNER =================
@app.route('/scanner', methods=['GET','POST'])
def scanner():
    user_id = get_user()

    if not user_id:
        return redirect('/login')

    if request.method == 'POST':
        url = request.form['url']
        threading.Thread(target=run_scan, args=(url, user_id)).start()

    return render_template("index.html")

# ================= RUN =================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))