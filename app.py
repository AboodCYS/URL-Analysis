from flask import Flask, request, render_template, session, redirect
import sqlite3
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os
import json
import requests
import time

app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.secret_key = "super-secret-key"
Session(app)

load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

DB_FILE = "url_database.db"


def execute_query(query, parameter=None, fetch=False):
    db = sqlite3.connect(DB_FILE)
    db.row_factory = sqlite3.Row
    cursor = db.cursor()

    if parameter or []:
        cursor.execute(query, parameter)
    else:
        cursor.execute(query)

    result = None
    if fetch:
        result = cursor.fetchall()

    db.commit()
    db.close()
    return result


def initialization_database():
    db = sqlite3.connect(DB_FILE)
    cursor = db.cursor()
    cursor.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER UNIQUE PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password TEXT NOT NULL)")
    cursor.execute("CREATE TABLE IF NOT EXISTS url (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT, user_id INTEGER, timestamp DATETIME, scan_results TEXT, FOREIGN KEY(user_id) REFERENCES users(id))")

    db.commit()
    db.close()


initialization_database()


def virus_total_scan(target_url):
    url = "https://www.virustotal.com/api/v3/urls"
    data = {"url": target_url}
    headers = {"x-apikey": VT_API_KEY}
    response = requests.post(url, headers=headers, data=data)

    if response.status_code != 200:
        return {"error": "Failed to scan with VirusTotal", "details": response.text}

    scan_id = response.json()["data"]["id"]

    result_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"

    for _ in range(10):
        result = requests.get(result_url, headers=headers)
        if result.status_code == 200:
            data = result.json()
            status = data.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                return data
        time.sleep(2)

    return {"error": "Analysis not ready. Try again later."}


@app.route('/')
def index():
    if 'username' in session:
        return render_template('index.html', username=session['username'])
    return redirect('/register')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirmation = request.form.get('confirmation')

        if not username or not password or not confirmation:
            return render_template('register.html', error='All fields must be completed.')

        if password != confirmation:
            return render_template('register.html', error='Passwords do not match')

        hash_password = generate_password_hash(password)
        try:
            execute_query("INSERT INTO users(username, password) VALUES(?, ?)",
                          (username, hash_password))
            return redirect('/login')
        except sqlite3.IntegrityError:
            return render_template('register.html', error='User already exists.')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    session.clear()
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            return render_template('login.html', error='All fields must be completed.')

        user_data = execute_query("SELECT * FROM users WHERE username = ?", (username,), fetch=True)
        if not user_data:
            return render_template('login.html', error='Username not found')
        user = user_data[0]

        if not check_password_hash(user['password'], password):
            return render_template('login.html', error='Password is error')
        session['username'] = user['username']
        session['user_id'] = user['id']
        return redirect('/')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return render_template('login.html')


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if request.method == 'POST':
        current = request.form.get('current')
        new = request.form.get('new')
        confirm = request.form.get('confirmation')

        if not current or not new or not confirm:
            return render_template('change_password.html', error='All fields must be completed.')

        if new != confirm:
            return render_template('change_password.html', error='New Password do not match confirm')

        user = session['username']
        stored_hash = execute_query(
            "SELECT password FROM users WHERE username = ?", (user,), fetch=True)
        if not stored_hash or not check_password_hash(stored_hash[0]['password'], current):
            return render_template('change_password.html', error='Current password is incorrect.')

        hash_password = generate_password_hash(new)
        execute_query("UPDATE users SET password = ? WHERE username = ?",
                      (hash_password, user,), fetch=True)
        return redirect('/login')

    return render_template('change_password.html')


@app.route("/scan", methods=["POST"])
def scan():
    target_url = request.form.get("target")

    if not target_url:
        return redirect("/")

    vt_result = virus_total_scan(target_url)

    execute_query("INSERT INTO url (url, scan_results, timestamp, user_id) VALUES (?, ?, datetime('now'), ?)",
                  (target_url, json.dumps(vt_result), session["user_id"]))

    return render_template("index.html", username=session.get("username"), scan_result=vt_result)


@app.route("/dashboard")
def dashboard():
    scans = execute_query(
        "SELECT * FROM url WHERE user_id = ? ORDER BY timestamp DESC", (session["user_id"],), fetch=True)

    parsed_scans = []
    for scan in scans:
        try:
            results = json.loads(scan["scan_results"])
            stats = results.get("data", {}).get("attributes", {}).get("stats", {})
            malicious = stats.get("malicious", 0)
            harmless = stats.get("harmless", 0)
            suspicious = stats.get("suspicious", 0)
        except:
            malicious, harmless, suspicious = 0, 0, 0

        parsed_scans.append({
            "id": scan["id"],
            "url": scan["url"],
            "timestamp": scan["timestamp"],
            "malicious": malicious,
            "harmless": harmless,
            "suspicious": suspicious,
        })

    return render_template("dashboard.html", username=session.get("username"), scans=parsed_scans, last_scan=parsed_scans[0] if parsed_scans else None)


if __name__ == '__main__':
    app.run(debug=True)
