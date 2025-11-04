function createAvatar(username) {
  const initials = username.slice(0, 2).toUpperCase();
  const avatar = document.createElement('div');
  avatar.className = 'user-avatar';
  avatar.textContent = initials;
  return avatar;
}

function formatTimestamp(ts) {
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

// Persist a per-device identity ECDH keypair in localStorage so history can decrypt after logout/login
async function loadOrCreateIdentity() {
  const stored = localStorage.getItem('securechat_ecdh_jwk');
  if (stored) {
    const { pubJwk, privJwk } = JSON.parse(stored);
    const publicKey = await crypto.subtle.importKey('jwk', pubJwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
    const privateKey = await crypto.subtle.importKey('jwk', privJwk, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey','deriveBits']);
    return { publicKey, privateKey };
  }
  const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey','deriveBits']);
  const pubJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const privJwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  localStorage.setItem('securechat_ecdh_jwk', JSON.stringify({ pubJwk, privJwk }));
  return pair;
}

document.addEventListener('DOMContentLoaded', () => {
  const socket = io();
  const currentUser = sessionStorage.getItem('username');
  if (!currentUser) return window.location.replace('index.html');

  const userList = document.getElementById('user-list');
  const userSearch = document.getElementById('user-search');
  const chatHeader = document.getElementById('chat-header');
  const messageForm = document.getElementById('message-form');
  const messageInput = document.getElementById('message-input');
  const logoutBtn = document.getElementById('logout-btn');
  const messageList = document.getElementById('message-list');

  logoutBtn.onclick = () => {
    socket.emit('logout', currentUser);
    // DO NOT clear localStorage here, only sessionStorage
    sessionStorage.clear();
    window.location.href = 'index.html';
  };

  let usersCache = [];
  let userPubKeys = {};
  let selectedUser = null;

  let identity;             // persistent identity ECDH pair
  let mySessionPubB64 = ''; // base64 raw public key for this device/session

  const aesOutCache = new Map(); // per-peer AES for outgoing messages

  (async () => {
    identity = await loadOrCreateIdentity();

    // Publish our public key (id key persisted across sessions)
    const raw = await crypto.subtle.exportKey('raw', identity.publicKey);
    mySessionPubB64 = btoa(String.fromCharCode(...new Uint8Array(raw)));
    await fetch('/api/updatePublicKey', {
      method: 'POST',
      headers: { 'Content-Type':'application/json' },
      body: JSON.stringify({ username: currentUser, publicKey: mySessionPubB64 })
    });

    socket.emit('login', currentUser);
    socket.emit('who-online');

    await loadUsers();
  })().catch(console.error);

  async function loadUsers() {
    const res = await fetch('/api/users');
    const all = await res.json();
    usersCache = (all || []).filter(u => u.username !== currentUser);
    userPubKeys = {};
    usersCache.forEach(u => userPubKeys[u.username] = u.publicKey || '');
    renderUsers(usersCache);
  }

  function renderUsers(users) {
    userList.innerHTML = '';
    users.forEach(u => {
      const li = document.createElement('li');
      li.className = 'user-item';
      li.dataset.username = u.username;

      li.appendChild(createAvatar(u.username));
      const dot = document.createElement('span');
      dot.className = 'status-dot offline';
      li.appendChild(dot);

      const nameSpan = document.createElement('span');
      nameSpan.className = 'username';
      nameSpan.textContent = u.username;
      li.appendChild(nameSpan);

      li.onclick = () => selectUser(u.username);
      userList.appendChild(li);
    });
  }

  userSearch.oninput = () => {
    const q = userSearch.value.toLowerCase();
    renderUsers(usersCache.filter(u => u.username.toLowerCase().includes(q)));
  };

  function setUserStatus(username, status) {
    document.querySelectorAll('.user-item').forEach(li => {
      if ((li.dataset.username || '').toLowerCase() === (username || '').toLowerCase()) {
        const dot = li.querySelector('.status-dot');
        if (dot) dot.className = 'status-dot ' + status;
      }
    });
  }

  socket.on('user-status', ({ username, status }) => setUserStatus(username, status));
  socket.on('online-list', (arr) => (arr || []).forEach(u => setUserStatus(u, 'online')));

  // Crypto helpers
  async function importECDHPub(b64) {
    const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    return crypto.subtle.importKey('raw', bytes.buffer, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
  }

  async function deriveWithPub(peerPubB64) {
    if (!peerPubB64 || peerPubB64.length < 80) throw new Error('Invalid peer public key');
    const otherPub = await importECDHPub(peerPubB64);
    return crypto.subtle.deriveKey(
      { name: 'ECDH', public: otherPub },
      identity.privateKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt','decrypt']
    );
  }

  async function encryptAES(key, text) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder().encode(text);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc);
    const ctBytes = new Uint8Array(ct);
    const out = new Uint8Array(iv.length + ctBytes.length);
    out.set(iv, 0); out.set(ctBytes, iv.length);
    return btoa(String.fromCharCode(...out));
  }

  async function decryptAES(key, b64) {
    const all = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const iv = all.slice(0, 12);
    const ct = all.slice(12);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return new TextDecoder().decode(pt);
  }

  async function selectUser(username) {
    selectedUser = username;

    chatHeader.innerHTML = '';
    const bar = document.createElement('div');
    bar.className = 'chat-title-bar';
    bar.appendChild(createAvatar(username));
    const nm = document.createElement('span');
    nm.className = 'chat-header-username';
    nm.textContent = username;
    bar.appendChild(nm);
    chatHeader.appendChild(bar);

    aesOutCache.delete(username);
    try {
      const latest = await fetch(`/api/publicKey/${encodeURIComponent(username)}`).then(r => r.json());
      const aes = await deriveWithPub(latest.publicKey);
      aesOutCache.set(username, aes);
      await loadChatHistory(username);
    } catch (e) {
      console.error('Select/derive error:', e);
      alert('Could not establish secure session. Ensure both users are on the chat screen.');
    }
  }

  async function loadChatHistory(username) {
    const res = await fetch(`/api/messages?user1=${encodeURIComponent(currentUser)}&user2=${encodeURIComponent(username)}`);
    const messages = await res.json();
    messageList.innerHTML = '';
    for (const m of messages) {
      let txt = '[Decryption Error]';
      try {
        const otherPubForMsg = (m.sender === currentUser) ? m.receiverPub : m.senderPub;
        const aes = await deriveWithPub(otherPubForMsg);
        txt = await decryptAES(aes, m.content);
      } catch {}
      addBubble(m.sender === currentUser ? 'sent' : 'received', txt, m.timestamp, false);
    }
  }

  function addBubble(type, text, ts, read) {
    const row = document.createElement('div');
    row.className = 'msg-row ' + type;
    const bubble = document.createElement('div');
    bubble.className = 'msg-bubble';
    bubble.textContent = text;
    const meta = document.createElement('div');
    meta.className = 'bubble-meta';
    meta.textContent = formatTimestamp(ts || Date.now());
    if (type === 'sent') {
      const rcpt = document.createElement('span');
      rcpt.className = 'read-receipt';
      rcpt.textContent = read ? '✓✓' : '✓';
      meta.appendChild(rcpt);
    }
    bubble.appendChild(meta);
    row.appendChild(bubble);
    messageList.appendChild(row);
    messageList.scrollTop = messageList.scrollHeight;
  }

  messageForm.onsubmit = async (e) => {
    e.preventDefault();
    const msg = messageInput.value.trim();
    if (!msg || !selectedUser) return;

    try {
      let aes = aesOutCache.get(selectedUser);
      if (!aes) {
        const latest = await fetch(`/api/publicKey/${encodeURIComponent(selectedUser)}`).then(r => r.json());
        aes = await deriveWithPub(latest.publicKey);
        aesOutCache.set(selectedUser, aes);
      }

      const peer = await fetch(`/api/publicKey/${encodeURIComponent(selectedUser)}`).then(r => r.json());
      const receiverPubB64 = peer.publicKey;

      const enc = await encryptAES(aes, msg);
      const timestamp = Date.now();

      socket.emit('send-message', {
        sender: currentUser,
        receiver: selectedUser,
        content: enc,
        senderPub: mySessionPubB64,
        receiverPub: receiverPubB64,
        timestamp
      });

      addBubble('sent', msg, timestamp, false);
      messageInput.value = '';
    } catch (e) {
      console.error('Send failed:', e);
      alert('Key not established. Ask the other user to open Chat, then reselect the conversation.');
    }
  };

  socket.on('receive-message', async (m) => {
    let txt = '[Decryption Error]';
    try {
      const otherPubForMsg = (m.sender === currentUser) ? m.receiverPub : m.senderPub;
      const aes = await deriveWithPub(otherPubForMsg);
      txt = await decryptAES(aes, m.content);
    } catch {}
    if (selectedUser === m.sender || selectedUser === m.receiver) {
      addBubble(m.sender === currentUser ? 'sent' : 'received', txt, m.timestamp, false);
    }
  });
});
