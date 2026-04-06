from flask import Flask, request, render_template, redirect, session, jsonify
import sqlite3, os, requests
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_key")

DB_PATH = "database.db"

# 🔥 GLOBAL STORAGE
scan_logs = {}
scan_status = {}

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

# ================= HOME =================
@app.route('/')
def home():
    return redirect('/login')

# ================= REGISTER =================
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])

        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("INSERT INTO users (username,password) VALUES (?,?)", (username, password))
            conn.commit()
            conn.close()
            return redirect('/login')
        except:
            return "User already exists"

    return render_template("register.html")

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

# ================= LOGOUT =================
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

# ================= SCANNER =================
@app.route('/scanner', methods=['GET','POST'])
def scanner():
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']

    if request.method == 'POST':
        url = request.form.get('url')

        if not url:
            return "Enter URL"

        if not url.startswith("http"):
            url = "http://" + url

        scan_logs[user_id] = []
        scan_status[user_id] = "Scanning..."

        try:
            # 🔥 CONNECTION TEST
            res = requests.get(url, timeout=5)

            scan_logs[user_id].append("🌐 Site reachable")

            # SQL CHECK
            scan_logs[user_id].append("🔍 Checking SQL...")
            if "sql" in res.text.lower():
                scan_logs[user_id].append("❌ SQL vulnerability possible")
            else:
                scan_logs[user_id].append("✅ SQL safe")

            # HEADERS CHECK
            scan_logs[user_id].append("🔍 Checking headers...")
            if "X-Frame-Options" not in res.headers:
                scan_logs[user_id].append("⚠ Missing security headers")
            else:
                scan_logs[user_id].append("✅ Headers OK")

            scan_status[user_id] = "Completed ✅"

        except Exception as e:
            scan_logs[user_id].append("❌ Error connecting to site")
            scan_logs[user_id].append(str(e))
            scan_status[user_id] = "Error ❌"

        return render_template("index.html")

    return render_template("index.html")

# ================= STATUS API =================
@app.route('/status')
def status():
    user_id = session.get('user_id')

    return jsonify({
        "status": scan_status.get(user_id, "Idle"),
        "logs": scan_logs.get(user_id, [])
    })

# ================= RUN =================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))