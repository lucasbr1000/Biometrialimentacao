// Helper buffer/base64
function b64ToBuf(s){ return Uint8Array.from(atob(s), c=>c.charCodeAt(0)).buffer; }
function bufToB64(buf){ return btoa(String.fromCharCode(...new Uint8Array(buf))); }

// ---------- Keypad & PIN logic ----------
const display = document.getElementById("display");
const keyboard = document.getElementById("keyboard");
const msg = document.getElementById("msg");

// Render keypad
if(keyboard){
  for(let i=1;i<=9;i++){
    const b = document.createElement("button");
    b.className = "kbtn";
    b.textContent = i;
    b.onclick = ()=>appendDigit(i);
    keyboard.appendChild(b);
  }
  const zero = document.createElement("button");
  zero.className = "kbtn";
  zero.textContent = 0;
  zero.onclick = ()=>appendDigit(0);
  keyboard.appendChild(document.createElement("div"));
  keyboard.appendChild(zero);
  keyboard.appendChild(document.createElement("div"));
}

function appendDigit(d){
  const current = (display.textContent||"").trim();
  if(current.length >= 6) return; // limit
  display.textContent = current + d.toString();
}

document.addEventListener("DOMContentLoaded", ()=> {
  const btnClear = document.getElementById("btnClear");
  const btnEnter = document.getElementById("btnEnter");
  const btnBio = document.getElementById("btnBio");
  if(btnClear) btnClear.onclick = ()=>{ display.textContent = ""; msg.textContent = ""; };
  if(btnEnter) btnEnter.onclick = doPinLogin;
  if(btnBio) btnBio.onclick = doBiometricLogin;

  // cadastro page handlers
  const form = document.getElementById("formCadastro");
  if(form){
    form.onsubmit = async (e) => {
      e.preventDefault();
      const formData = new FormData(form);
      const res = await fetch("/api/cadastro", { method: "POST", body: formData });
      const j = await res.json();
      const cadMsg = document.getElementById("cadMsg");
      if(j.ok){
        cadMsg.style.color = "green";
        cadMsg.textContent = "Cadastrado! ID: " + j.id + ". Agora clique em 'Ativar Biometria'.";
        // enable activate button and attach data-id
        const act = document.getElementById("activateBio");
        act.disabled = false;
        act.dataset.userid = j.id;
        act.onclick = ()=>activateBiometry(j.id);
      } else {
        cadMsg.style.color = "red";
        cadMsg.textContent = j.error || "Erro no cadastro";
      }
    }
  }
});

// PIN login
async function doPinLogin(){
  msg.textContent = "";
  const pin = (display.textContent||"").trim();
  if(!pin){ msg.textContent = "Digite o PIN"; return; }
  try{
    const res = await fetch("/api/login_pin", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ pin }) });
    const j = await res.json();
    if(j.ok){
      showImage(j.imageUrl);
    } else {
      msg.textContent = j.error || "PIN inválido";
      display.textContent = "";
    }
  }catch(e){
    msg.textContent = "Erro no servidor";
  }
}

// Show image for 4s
function showImage(url){
  // simple flow: open qr.html replacement by injecting in page
  const wrapper = document.querySelector(".wrapper");
  wrapper.innerHTML = `<div class="card"><h2>Identificado</h2><img src="${url}" style="max-width:320px"></div>`;
  setTimeout(()=>{ window.location.href = "/"; }, 4000);
}

// ------------- WebAuthn flows -------------
// Activate biometric after cadastro
async function activateBiometry(userId){
  // 1) get options
  try{
    const ro = await fetch("/webauthn/register/options", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id: userId }) });
    const opts = await ro.json();
    const pub = opts.publicKey;

    // convert base64 fields to ArrayBuffers
    pub.challenge = b64ToBuf(pub.challenge);
    pub.user.id = b64ToBuf(pub.user.id);
    // pub.pubKeyCredParams is array and ok

    // create credential
    const cred = await navigator.credentials.create({ publicKey: pub });
    // compose attestation to send
    const att = {
      id: cred.id,
      rawId: bufToB64(cred.rawId),
      response: {
        clientDataJSON: bufToB64(cred.response.clientDataJSON),
        attestationObject: bufToB64(cred.response.attestationObject)
      }
    };
    const finish = await fetch("/webauthn/register/finish", { method: "POST", headers: { "Content-Type":"application/json" }, body: JSON.stringify({ id: userId, att })});
    const j = await finish.json();
    if(j.ok){
      alert("Biometria ativada com sucesso!");
    } else {
      alert("Erro ao ativar biometria: " + (j.error || JSON.stringify(j)));
    }
  }catch(e){
    alert("Erro WebAuthn (registro): " + e);
  }
}

// Biometric login (no user input)
async function doBiometricLogin(){
  try{
    const res = await fetch("/webauthn/auth/options");
    const opts = await res.json();
    const pub = opts.publicKey;
    pub.challenge = b64ToBuf(pub.challenge);
    pub.allowCredentials = (pub.allowCredentials||[]).map(c => ({ id: b64ToBuf(c.id), type: c.type }));

    const assertion = await navigator.credentials.get({ publicKey: pub });
    const auth = {
      id: assertion.id,
      rawId: bufToB64(assertion.rawId),
      response: {
        clientDataJSON: bufToB64(assertion.response.clientDataJSON),
        authenticatorData: bufToB64(assertion.response.authenticatorData),
        signature: bufToB64(assertion.response.signature)
      }
    };
    const fin = await fetch("/webauthn/auth/finish", { method: "POST", headers: { "Content-Type":"application/json" }, body: JSON.stringify({ assertion: auth }) });
    const j = await fin.json();
    if(j.ok){
      showImage(j.imageUrl);
    } else {
      alert("Falha na autenticação: " + (j.error || JSON.stringify(j)));
    }
  }catch(e){
    alert("Erro WebAuthn (auth): " + e);
  }
}
