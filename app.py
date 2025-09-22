import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
from flask_session import Session
from werkzeug.utils import secure_filename
import qrcode
import base64
import io

app = Flask(__name__)
app.secret_key = "segredo123"

# Configuração da sessão
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Pasta para salvar imagens
UPLOAD_FOLDER = "static/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Banco de dados
DB_NAME = "database.db"


def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                pin TEXT,
                webauthn_key TEXT,
                foto TEXT
            )
        """)
        conn.commit()


init_db()


@app.route("/")
def home():
    return render_template("login.html")


@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    if request.method == "POST":
        username = request.form["username"]
        pin = request.form["pin"]
        file = request.files.get("foto")

        foto_filename = None
        if file and file.filename != "":
            foto_filename = secure_filename(file.filename)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], foto_filename))

        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            try:
                c.execute(
                    "INSERT INTO users (username, pin, foto) VALUES (?, ?, ?)",
                    (username, pin, foto_filename),
                )
                conn.commit()
            except sqlite3.IntegrityError:
                return "Usuário já existe!"

        return redirect(url_for("home"))

    return render_template("cadastro.html")


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    pin = request.form["pin"]

    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("SELECT id, foto FROM users WHERE username=? AND pin=?", (username, pin))
        user = c.fetchone()

    if user:
        foto = user[1]
        qr_img = qrcode.make(f"Usuário: {username}")
        buffer = io.BytesIO()
        qr_img.save(buffer, format="PNG")
        qr_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")

        return render_template("qr.html", qr_code=qr_base64, foto=foto)
    else:
        return "Login inválido!"


# Rotas futuras para WebAuthn
@app.route("/register_webauthn", methods=["POST"])
def register_webauthn():
    # Aqui vamos salvar a chave pública do usuário
    return {"status": "ok"}


@app.route("/login_webauthn", methods=["POST"])
def login_webauthn():
    # Aqui vamos validar a biometria
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(debug=True)

