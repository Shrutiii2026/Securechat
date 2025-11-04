document.addEventListener('DOMContentLoaded', () => {
  const loginBtn = document.getElementById('login-btn');
  const registerBtn = document.getElementById('register-btn');

  if (registerBtn) {
    registerBtn.onclick = async () => {
      const username = document.getElementById('register-username').value.trim();
      const password = document.getElementById('register-password').value;
      const err = document.getElementById('register-error');
      const ok = document.getElementById('register-success');
      err.textContent = ''; ok.textContent = '';
      if (username.length < 3 || password.length < 6) { err.textContent = 'Use a valid username and a password with 6+ characters.'; return; }
      const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey','deriveBits']);
      const raw = await crypto.subtle.exportKey('raw', pair.publicKey);
      const pubB64 = btoa(String.fromCharCode(...new Uint8Array(raw)));
      const res = await fetch('/api/register', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ username, password, publicKey: pubB64 }) });
      const data = await res.json();
      if (data.error) err.textContent = data.error; else ok.textContent = 'Registration successful. Please login.';
    };
  }

  if (loginBtn) {
    loginBtn.onclick = async () => {
      const username = document.getElementById('login-username').value.trim();
      const password = document.getElementById('login-password').value;
      const err = document.getElementById('login-error');
      err.textContent = '';
      const res = await fetch('/api/login', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ username, password }) });
      const data = await res.json();
      if (data.error) { err.textContent = 'Invalid credentials.'; return; }
      sessionStorage.setItem('username', data.username);
      window.location.href = 'chat.html';
    };
  }
});
