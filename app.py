from flask import Flask, request, render_template, redirect, session, send_file
import sqlite3, os
from werkzeug.security import generate_password_hash, check_password_hash

from scanner.sql_injection import scan_sql
from scanner.xss import scan_xss
from report import generate_report

app = Flask(__name__)
app.secret_key = "cyberwar_secret"

history = []

# -------- DATABASE --------
def init_db():
    conn = sqlite3.connect("database.db")
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

# -------- REGISTER --------
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        u = request.form['username']
        p = generate_password_hash(request.form['password'])

        try:
            conn = sqlite3.connect("database.db")
            cur = conn.cursor()
            cur.execute("INSERT INTO users (username,password) VALUES (?,?)",(u,p))
            conn.commit()
            conn.close()
        except:
            return "⚠️ User exists"

        return redirect('/login')

    return render_template("register.html")

# -------- LOGIN --------
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        u = request.form['username']
        p = request.form['password']

        conn = sqlite3.connect("database.db")
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username=?",(u,))
        user = cur.fetchone()
        conn.close()

        if user and check_password_hash(user[2],p):
            session['user']=u
            return redirect('/dashboard')
        return "❌ Invalid Login"

    return render_template("login.html")

# -------- LOGOUT --------
@app.route('/logout')
def logout():
    session.pop('user',None)
    return redirect('/login')

# -------- DASHBOARD --------
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/login')
    return render_template("dashboard.html", scans=len(history))

# -------- SCANNER --------
@app.route('/', methods=['GET','POST'])
def index():
    if 'user' not in session:
        return redirect('/login')

    result={}
    if request.method=='POST':
        url=request.form['url']

        result['SQL Injection']=scan_sql(url)
        result['XSS']=scan_xss(url)

        generate_report(url,result)

        history.append({"url":url,"result":result})

    return render_template("index.html",result=result)

# -------- DOWNLOAD PDF --------
@app.route('/download')
def download():
    path="scan_report.pdf"
    if os.path.exists(path):
        return send_file(path,as_attachment=True)
    return "No report"

# -------- DOWNLOAD HTML --------
@app.route('/download_html')
def download_html():
    path="scan_report.html"
    if os.path.exists(path):
        return send_file(path,as_attachment=True)
    return "No report"

# -------- ADMIN --------
@app.route('/admin')
def admin():
    conn=sqlite3.connect("database.db")
    cur=conn.cursor()
    cur.execute("SELECT id,username FROM users")
    users=cur.fetchall()
    conn.close()
    return render_template("admin.html",users=users)

if __name__=="__main__":
    app.run(debug=True)