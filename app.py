from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import sqlite3, qrcode, io, base64, os
from flask_session import Session
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
import base64, json

app = Flask(__name__)
app.secret_key = "chave-secreta"
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# cria o banco se não existir
def init_db():
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    pin TEXT,
                    credential_id TEXT,
                    public_key TEXT
                )''')
    conn.commit()
    conn.close()

@app.route("/")
def home():
    return render_template("login.html")

@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    if request.method == "POST":
        username = request.form["username"]
        pin = request.form["pin"]
        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, pin) VALUES (?, ?)", (username, pin))
            conn.commit()
        except sqlite3.IntegrityError:
            return "Usuário já existe!"
        conn.close()
        return render_template("cadastro.html", username=username, biometria=True)
    return render_template("cadastro.html", biometria=False)

@app.route("/webauthn/register", methods=["POST"])
def webauthn_register():
    data = request.json
    username = data["username"]
    credential_id = data["credential"]["id"]
    public_key = data["credential"]["publicKey"]

    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("UPDATE users SET credential_id=?, public_key=? WHERE username=?",
              (credential_id, public_key, username))
    conn.commit()
    conn.close()

    return jsonify({"status": "ok"})

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    pin = request.form["pin"]

    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username=? AND pin=?", (username, pin))
    user = c.fetchone()
    conn.close()

    if user:
        session["user_id"] = user[0]
        return redirect(url_for("qr"))
    return "Login inválido!"

@app.route("/login-bio/<username>")
def login_bio(username):
    challenge = os.urandom(32)
    session["challenge"] = base64.urlsafe_b64encode(challenge).decode("utf-8")

    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("SELECT credential_id FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()

    if not row or not row[0]:
        return jsonify({"error": "Usuário sem credencial biométrica"}), 400

    return jsonify({
        "challenge": session["challenge"],
        "credential_id": row[0]
    })

@app.route("/verify-bio", methods=["POST"])
def verify_bio():
    data = request.json
    username = data["username"]
    signature = base64.urlsafe_b64decode(data["signature"])
    challenge = base64.urlsafe_b64decode(session["challenge"])

    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("SELECT id, public_key FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "Usuário não encontrado"}), 400

    user_id, public_key_pem = row

    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    try:
        public_key.verify(signature, challenge, ec.ECDSA(hashes.SHA256()))
        session["user_id"] = user_id
        return jsonify({"status": "ok"})
    except Exception:
        return jsonify({"error": "Falha na verificação biométrica"}), 400

@app.route("/qr")
def qr():
    if "user_id" not in session:
        return redirect(url_for("home"))

    user_id = session["user_id"]
    data = f"user:{user_id}"
    img = qrcode.make(data)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    return render_template("qr.html", qr_code=qr_b64)

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
