# WebAuthn: register options (client asks to register credential for a given user id)
@app.route("/webauthn/register/options", methods=["POST"])
def web_register_options():
    body = request.get_json()
    user_id = body.get("id")  # integer id retornado após cadastro
    if not user_id:
        return jsonify({"error": "id obrigatório"}), 400

    # cria user entity
    user_entity = PublicKeyCredentialUserEntity(
        id=str(user_id).encode("utf-8"),
        name=str(user_id),
        display_name=str(user_id)
    )

    # pega credenciais existentes (normalmente vazio no primeiro cadastro)
    creds = []

    # gera opções de registro (objeto PublicKeyCredentialCreationOptions)
    options, state = server.register_begin(
        user=user_entity,
        credentials=creds,
        user_verification="discouraged"
    )

    # salvar estado em arquivo temporário
    state_file = BASE / f".webauthn_reg_state_{user_id}.json"
    state_file.write_text(json.dumps(state))

    # converter bytes -> base64url (para mandar em JSON)
    publicKey = options
    publicKey["challenge"] = base64.urlsafe_b64encode(publicKey["challenge"]).decode("utf-8")
    publicKey["user"]["id"] = base64.urlsafe_b64encode(publicKey["user"]["id"]).decode("utf-8")

    return jsonify({"publicKey": publicKey})
