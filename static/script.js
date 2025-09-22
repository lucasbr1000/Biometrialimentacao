async function cadastrarBiometria() {
    if (!("credentials" in navigator)) {
        alert("Seu navegador não suporta WebAuthn!");
        return;
    }

    try {
        let cred = await navigator.credentials.create({
            publicKey: {
                challenge: new Uint8Array([ // mock challenge
                    0x8C, 0xFA, 0xDD, 0x01
                ]),
                rp: { name: "Biometria QR App" },
                user: {
                    id: new Uint8Array([1, 2, 3, 4]),
                    name: "usuario@teste.com",
                    displayName: "Usuário"
                },
                pubKeyCredParams: [{ type: "public-key", alg: -7 }],
                authenticatorSelection: { authenticatorAttachment: "platform" },
                timeout: 60000,
                attestation: "direct"
            }
        });

        console.log("Credenciais geradas:", cred);

        // Aqui deveria enviar pro backend
        await fetch("/register_webauthn", {
            method: "POST",
            body: JSON.stringify({ id: cred.id }),
            headers: { "Content-Type": "application/json" }
        });

        alert("Biometria cadastrada com sucesso!");
    } catch (err) {
        console.error(err);
        alert("Erro ao cadastrar biometria");
    }
}

