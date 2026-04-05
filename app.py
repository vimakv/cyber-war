from flask import Flask, request, render_template, redirect, session
import sqlite3, re, random, time
from werkzeug.security import generate_password_hash, check_password_hash

# EMAIL
from flask_mail import Mail, Message

# SCANNER
from scanner.sql_injection import scan_sql
from scanner.xss import scan_xss

app = Flask(__name__)
app.secret_key = "secret123"

DB_PATH = "database.db"

# ================= EMAIL CONFIG =================
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "cyberwarrs@gmail.com"   # 👈 YOUR EMAIL
app.config['MAIL_PASSWORD'] = "ulyhjsrnxnikozsn"          # 👈 APP PASSWORD (NO SPACES)
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

        # 🔥 SEND EMAIL
        try:
            msg = Message(
                subject="Cyber War OTP Verification",
                recipients=[e]
            )
            msg.body = f"Your OTP is: {otp}"
            mail.send(msg)
            print("✅ Email sent")

        except Exception as err:
            print("❌ Email failed:", err)
            print("🔥 OTP (fallback):", otp)

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

        sql = scan_sql(url)
        xss = scan_xss(url)

        result['SQL Injection'] = sql
        result['XSS'] = xss

        if "Vulnerable" in sql or "Vulnerable" in xss:
            result['Severity'] = "High"
        else:
            result['Severity'] = "Low"

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO scans (url,result,user_id) VALUES (?,?,?)",
            (url, str(result), session['user'])
        )
        conn.commit()
        conn.close()

    return render_template("index.html", result=result)

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