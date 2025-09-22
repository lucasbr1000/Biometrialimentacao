import os
import sqlite3
import json
import base64
import pathlib
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_from_directory
from flask_session import Session
from werkzeug.utils import secure_filename
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity, AttestedCredentialData
from fido2.webauthn import AuthenticatorData

# Configs
BASE = pathlib.Path(__file__).parent
DB = BASE / "database.db"
UPLOAD_DIR = BASE / "static" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

RP_ID = os.environ.get("RP_ID", "localhost")
ORIGIN = os.environ.get("ORIGIN", "http://localhost:5000")

rp = PublicKeyCredentialRpEntity(
    id=RP_ID,
    name="Biometria QR App"
)
server = Fido2Server(rp)


app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["SESSION_TYPE"] = "filesystem"
app.secret_key = os.environ.get("FLASK_SECRET", "troque_essa_chave")
Session(app)

# --- DB helpers ---
def init_db():
    with sqlite3.connect(DB) as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS pessoas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pin TEXT UNIQUE NOT NULL,
                credential_id TEXT,
                public_key BLOB,
                sign_count INTEGER DEFAULT 0,
                imagem TEXT NOT NULL
            )
        """)
        conn.commit()

def db_getone(query, args=()):
    with sqlite3.connect(DB) as conn:
        cur = conn.cursor()
        cur.execute(query, args)
        return cur.fetchone()

def db_execute(query, args=()):
    with sqlite3.connect(DB) as conn:
        cur = conn.cursor()
        cur.execute(query, args)
        conn.commit()
        return cur.lastrowid

init_db()

# ------------- Front pages -------------
@app.route("/")
def index():
    # Tela inicial com teclado fixo
    return render_template("login.html")

@app.route("/cadastro")
def cadastro_page():
    return render_template("cadastro.html")

# Serve uploaded images (static/uploads)
@app.route("/uploads/<path:fn>")
def uploaded(fn):
    return send_from_directory(str(UPLOAD_DIR), fn)

# ------------- API endpoints -------------
# Cadastro (recebe multipart/form-data)
@app.route("/api/cadastro", methods=["POST"])
def api_cadastro():
    pin = request.form.get("pin")
    # pin required
    if not pin:
        return jsonify({"ok": False, "error": "PIN obrigatório"}), 400
    # check unique pin
    existing = db_getone("SELECT id FROM pessoas WHERE pin=?", (pin,))
    if existing:
        return jsonify({"ok": False, "error": "PIN já cadastrado"}), 400

    # imagem obrigatória
    if "imagem" not in request.files:
        return jsonify({"ok": False, "error": "Imagem obrigatória"}), 400
    f = request.files["imagem"]
    if f.filename == "":
        return jsonify({"ok": False, "error": "Imagem obrigatória"}), 400
    filename = secure_filename(f.filename)
    # avoid collisions
    filename = f"{pin}_{filename}"
    path = UPLOAD_DIR / filename
    f.save(path)

    # insert row with pin and image (we'll add credential after biometric registration)
    rowid = db_execute("INSERT INTO pessoas (pin, imagem) VALUES (?, ?)", (pin, filename))
    return jsonify({"ok": True, "id": rowid, "pin": pin})

# Login via PIN
@app.route("/api/login_pin", methods=["POST"])
def api_login_pin():
    data = request.get_json()
    pin = data.get("pin")
    if not pin:
        return jsonify({"ok": False, "error": "PIN obrigatório"}), 400
    row = db_getone("SELECT id, imagem FROM pessoas WHERE pin=?", (pin,))
    if not row:
        return jsonify({"ok": False, "error": "PIN inválido"}), 404
    _, imagem = row
    image_url = url_for("uploaded", fn=imagem)
    return jsonify({"ok": True, "imageUrl": image_url})

# WebAuthn: register options (client asks to register credential for a given user id)
@app.route("/webauthn/register/options", methods=["POST"])
def web_register_options():
    body = request.get_json()
    user_id = body.get("id")  # integer id returned after cadastro
    if not user_id:
        return jsonify({"error": "id obrigatório"}), 400

    # create user entity
    user_entity = PublicKeyCredentialUserEntity(id=str(user_id).encode("utf-8"), name=str(user_id), display_name=str(user_id))
    # gather existing credentials for this user (none usually)
    creds = []
    registration_data, state = server.register_begin(user_entity, creds, user_verification="discouraged")
    # store state to temp file
    state_file = BASE / f".webauthn_reg_state_{user_id}.json"
    state_file.write_text(json.dumps(state))
    # return publicKey options (challenge base64url, etc)
    publicKey = registration_data["publicKey"]
    # convert bytes to base64url strings
    publicKey["challenge"] = base64.urlsafe_b64encode(publicKey["challenge"]).decode("utf-8")
    # also convert user.id to base64url
    publicKey["user"]["id"] = base64.urlsafe_b64encode(publicKey["user"]["id"]).decode("utf-8")
    return jsonify({"publicKey": publicKey})

# WebAuthn: register finish
@app.route("/webauthn/register/finish", methods=["POST"])
def web_register_finish():
    body = request.get_json()
    user_id = body.get("id")
    attestation = body.get("att")
    if not user_id or not attestation:
        return jsonify({"error": "params missing"}), 400

    state_file = BASE / f".webauthn_reg_state_{user_id}.json"
    if not state_file.exists():
        return jsonify({"error": "state not found"}), 400
    state = json.loads(state_file.read_text())

    rawId = base64.urlsafe_b64decode(attestation["rawId"].encode("utf-8"))
    attObj = base64.urlsafe_b64decode(attestation["response"]["attestationObject"].encode("utf-8"))
    clientData = base64.urlsafe_b64decode(attestation["response"]["clientDataJSON"].encode("utf-8"))

    auth_data = server.register_complete(state, clientData, attObj)
    # auth_data.credential_data is AttestedCredentialData
    cred_id_b64 = base64.urlsafe_b64encode(auth_data.credential_data.credential_id).decode("utf-8")
    pubkey = auth_data.credential_data.public_key  # COSEKey / bytes-like from library
    sign_count = auth_data.sign_count or 0

    # store credential and public key in DB for this user id
    db_execute("UPDATE pessoas SET credential_id=?, public_key=?, sign_count=? WHERE id=?",
               (cred_id_b64, pubkey, sign_count, user_id))

    try:
        state_file.unlink()
    except:
        pass
    return jsonify({"ok": True})

# WebAuthn: auth/options -> return allowCredentials = all registered creds (so client can authenticate without providing user)
@app.route("/webauthn/auth/options", methods=["GET"])
def web_auth_options():
    # fetch all credential ids
    with sqlite3.connect(DB) as conn:
        cur = conn.cursor()
        cur.execute("SELECT credential_id FROM pessoas WHERE credential_id IS NOT NULL")
        rows = cur.fetchall()
    allow = []
    for (cred_b64,) in rows:
        try:
            cred = base64.urlsafe_b64decode(cred_b64.encode("utf-8"))
            allow.append(base64.urlsafe_b64encode(cred).decode("utf-8"))  # will convert to buffer client-side
        except:
            pass
    # prepare challenge and state
    credentials = [base64.urlsafe_b64decode(x.encode("utf-8")) for x in []]  # not used locally
    auth_data, state = server.authenticate_begin([base64.urlsafe_b64decode(x.encode("utf-8")) for x in []], user_verification="discouraged")
    state_file = BASE / f".webauthn_auth_state.json"
    state_file.write_text(json.dumps(state))
    # build allowCredentials payload for client (base64 strings)
    allow_payload = []
    for (cred_b64,) in rows:
        try:
            # cred_b64 is base64 stored
            allow_payload.append({"id": cred_b64, "type": "public-key"})
        except:
            pass
    return jsonify({
        "publicKey": {
            "challenge": base64.urlsafe_b64encode(auth_data["publicKey"]["challenge"]).decode("utf-8"),
            "allowCredentials": allow_payload,
            "timeout": auth_data["publicKey"].get("timeout", 60000)
        }
    })

# WebAuthn: auth finish -> verify and find which user matched the cred
@app.route("/webauthn/auth/finish", methods=["POST"])
def web_auth_finish():
    body = request.get_json()
    assertion = body.get("assertion")
    if not assertion:
        return jsonify({"error": "assertion missing"}), 400
    state_file = BASE / f".webauthn_auth_state.json"
    if not state_file.exists():
        return jsonify({"error": "state missing"}), 400
    state = json.loads(state_file.read_text())

    rawId = base64.urlsafe_b64decode(assertion["rawId"].encode("utf-8"))
    clientData = base64.urlsafe_b64decode(assertion["response"]["clientDataJSON"].encode("utf-8"))
    authData = base64.urlsafe_b64decode(assertion["response"]["authenticatorData"].encode("utf-8"))
    signature = base64.urlsafe_b64decode(assertion["response"]["signature"].encode("utf-8"))

    # find user by credential id
    cred_b64 = base64.urlsafe_b64encode(rawId).decode("utf-8")
    row = db_getone("SELECT id, public_key, sign_count, imagem FROM pessoas WHERE credential_id=?", (cred_b64,))
    if not row:
        return jsonify({"ok": False, "error": "credential not found"}), 404
    user_id, public_key_blob, sign_count, imagem = row

    # build AttestedCredentialData object expected by server.authenticate_complete
    # persistent storage: public_key_blob (we stored object bytes from registration)
    try:
        credential = AttestedCredentialData(public_key_blob, rawId, b"")
    except Exception:
        # fallback: try to pass raw public_key as bytes to AttestedCredentialData
        try:
            credential = AttestedCredentialData(public_key_blob, rawId, b"")
        except Exception as e:
            return jsonify({"ok": False, "error": f"cred build error: {e}"}), 500

    try:
        auth_result = server.authenticate_complete(state, [credential], rawId, clientData, authData, signature)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    # update counter
    db_execute("UPDATE pessoas SET sign_count=? WHERE id=?", (auth_result.new_sign_count, user_id))

    image_url = url_for("uploaded", fn=imagem)
    try:
        state_file.unlink()
    except:
        pass
    return jsonify({"ok": True, "imageUrl": image_url})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
