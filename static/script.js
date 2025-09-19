// ---------- CADASTRO ----------
async function registrarBiometria(username) {
  const publicKey = {
    challenge: new Uint8Array(32),
    rp: { name: "Projeto Biometria QR" },
    user: {
      id: new Uint8Array(16),
      name: username,
      displayName: username
    },
    pubKeyCredParams: [{ alg: -7, type: "public-key" }],
    authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required" },
    timeout: 60000,
    attestation: "none"
  };

  const credential = await navigator.credentials.create({ publicKey });

  const publicKeyPem = await exportPublicKey(credential.response.getPublicKey());
  const credentialId = btoa(String.fromCharCode(...new Uint8Array(credential.rawId)));

  await fetch("/webauthn/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: username,
      credential: {
        id: credentialId,
        publicKey: publicKeyPem
      }
    })
  });

  alert("Biometria cadastrada com sucesso!");
  window.location.href = "/";
}

// ---------- LOGIN ----------
async function loginBiometria() {
  const username = document.getElementById("username").value;
  if (!username) {
    alert("Digite o usuário para login biométrico");
    return;
  }

  const resp = await fetch(`/login-bio/${username}`);
  const options = await resp.json();
  if (options.error) {
    alert(options.error);
    return;
  }

  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: Uint8Array.from(atob(options.challenge), c => c.charCodeAt(0)),
      allowCredentials: [{
        id: Uint8Array.from(atob(options.credential_id), c => c.charCodeAt(0)),
        type: "public-key"
      }],
      userVerification: "required"
    }
  });

  const signature = btoa(String.fromCharCode(...new Uint8Array(assertion.response.signature)));

  const verify = await fetch("/verify-bio", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: username, signature: signature })
  });

  const result = await verify.json();
  if (result.status === "ok") {
    window.location.href = "/qr";
  } else {
    alert("Falha no login biométrico");
  }
}

// ---------- UTILS ----------
async function exportPublicKey(key) {
  const spki = await window.crypto.subtle.exportKey("spki", key);
  const pem = `-----BEGIN PUBLIC KEY-----\n${btoa(String.fromCharCode(...new Uint8Array(spki)))}\n-----END PUBLIC KEY-----`;
  return pem;
}

// ---------- QR AUTO-REDIRECT ----------
window.onload = function() {
  if (document.getElementById("qr")) {
    setTimeout(() => {
      window.location.href = "/";
    }, 4000);
  }
}
