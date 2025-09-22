let pinAtual = "";

// Mostra os dígitos digitados
function addDigit(digit) {
  if (pinAtual.length < 8) {
    pinAtual += digit;
    document.getElementById("pin-display").innerText = "*".repeat(pinAtual.length);
  }
}

function clearPin() {
  pinAtual = "";
  document.getElementById("pin-display").innerText = "";
}

// Login com PIN
function loginPin() {
  if (!pinAtual) {
    alert("Digite o PIN");
    return;
  }

  let usuarios = JSON.parse(localStorage.getItem("usuarios") || "[]");
  let user = usuarios.find(u => u.pin === pinAtual);

  if (user) {
    mostrarImagem(user.imagem);
  } else {
    alert("PIN inválido!");
  }
  clearPin();
}

// Login com biometria
async function loginBiometria() {
  try {
    const cred = await navigator.credentials.get({ publicKey: { challenge: new Uint8Array([1,2,3,4]) } });
    let usuarios = JSON.parse(localStorage.getItem("usuarios") || "[]");
    if (usuarios.length > 0) {
      mostrarImagem(usuarios[0].imagem); // simplificado: pega o primeiro
    } else {
      alert("Nenhum usuário cadastrado!");
    }
  } catch (err) {
    alert("Erro Biometria: " + err);
  }
}

// Exibir imagem por 4 segundos
function mostrarImagem(base64Img) {
  let img = document.createElement("img");
  img.src = base64Img;
  img.style.maxWidth = "300px";
  img.style.display = "block";
  img.style.margin = "20px auto";
  
  document.body.innerHTML = "";
  document.body.appendChild(img);

  setTimeout(() => {
    window.location.href = "/";
  }, 4000);
}

// Cadastro
function salvarCadastro(e) {
  e.preventDefault();

  let pin = document.getElementById("pin").value;
  let imgFile = document.getElementById("imagem").files[0];

  if (!pin || !imgFile) {
    alert("Preencha todos os campos!");
    return;
  }

  let usuarios = JSON.parse(localStorage.getItem("usuarios") || "[]");
  if (usuarios.find(u => u.pin === pin)) {
    alert("PIN já cadastrado!");
    return;
  }

  let reader = new FileReader();
  reader.onload = function(event) {
    usuarios.push({ pin: pin, imagem: event.target.result });
    localStorage.setItem("usuarios", JSON.stringify(usuarios));
    alert("Usuário cadastrado com sucesso!");
    window.location.href = "/";
  };
  reader.readAsDataURL(imgFile);
}

// Cadastrar biometria
async function cadastrarBiometria() {
  try {
    await navigator.credentials.create({ publicKey: { challenge: new Uint8Array([1,2,3,4]) } });
    alert("Biometria cadastrada (simulada)");
  } catch (err) {
    alert("Erro ao cadastrar biometria: " + err);
  }
}
