from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3

app = Flask(__name__)
app.secret_key = "segredo_super_secreto"

DB_NAME = "database.db"

def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                pin TEXT NOT NULL,
                qr_code TEXT NOT NULL
            )
        """)
        conn.commit()

@app.route("/")
def index():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    pin = request.form.get("pin")
    with sqlite3.connect(DB_NAME) as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, username, qr_code FROM users WHERE pin = ?", (pin,))
        user = cur.fetchone()
        if user:
            session["user_id"] = user[0]
            session["qr_code"] = user[2]
            return redirect(url_for("show_qr"))
    return "Login falhou. PIN incorreto."

@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    if request.method == "POST":
        username = request.form.get("username")
        pin = request.form.get("pin")
        qr_code = request.form.get("qr_code")
        with sqlite3.connect(DB_NAME) as conn:
            cur = conn.cursor()
            try:
                cur.execute("INSERT INTO users (username, pin, qr_code) VALUES (?, ?, ?)",
                            (username, pin, qr_code))
                conn.commit()
                return redirect(url_for("index"))
            except sqlite3.IntegrityError:
                return "Usuário já existe."
    return render_template("cadastro.html")

@app.route("/qr")
def show_qr():
    if "qr_code" not in session:
        return redirect(url_for("index"))
    qr_code = session["qr_code"]
    return render_template("qr.html", qr_code=qr_code)

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
