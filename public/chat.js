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
  const messageList = document.getElementById('message-list');
  const logoutBtn = document.getElementById('logout-btn');
  // Hamburger menu and dash dropdown
const topBar = document.querySelector('.top-bar');
const menuBtn = document.getElementById('menu-btn'); // reuse right-side button

  const menuDropdown = document.createElement('div');
  menuDropdown.id = 'menu-dropdown';
  menuDropdown.className = 'menu-dropdown hidden';
  menuDropdown.innerHTML = `
    <ul>
      <li id="help-item">Help</li>
      <li id="contact-item">Contact</li>
      <li id="settings-item">Settings</li>
    </ul>`;
  document.body.appendChild(menuDropdown);

  function positionMenu() {
  const rect = menuBtn.getBoundingClientRect();
  const vw = document.documentElement.clientWidth;
  const dd = menuDropdown;

  dd.style.position = 'absolute';
  dd.style.top = `${rect.bottom + window.scrollY}px`;

  // Preferred: align dropdown's right edge with button's right edge
  let left = rect.left + window.scrollX - dd.offsetWidth;

  // Clamp to viewport with 8px side padding
  const minLeft = window.scrollX + 8;
  const maxLeft = window.scrollX + vw - dd.offsetWidth - 8;
  if (left < minLeft) left = minLeft;
  if (left > maxLeft) left = maxLeft;

  dd.style.left = `${left}px`;
  dd.style.zIndex = 1000;
}

window.addEventListener('resize', positionMenu);
window.addEventListener('scroll', positionMenu);

  positionMenu();

  menuBtn.onclick = () => {
    menuDropdown.classList.toggle('hidden');
  };

  window.addEventListener('click', (e) => {
    if (!menuDropdown.contains(e.target) && e.target !== menuBtn) {
      menuDropdown.classList.add('hidden');
    }
  });

 document.addEventListener('click', (e) => {
  if (!menuDropdown) return;
  const id = e.target && e.target.id;
  if (id === 'help-item') {
    alert('Help: This is a secure chat app. Contact support for assistance.');
    menuDropdown.classList.add('hidden');
  }
  if (id === 'contact-item') {
    alert('Contact: support@securechat.com');
    menuDropdown.classList.add('hidden');
  }
  if (id === 'settings-item') {
    menuDropdown.classList.add('hidden');
    window.location.href = 'settings.html';
  }
});
  // Message encryption, decryption, presence, and UI

  logoutBtn.onclick = () => {
    socket.emit('logout', currentUser);
    sessionStorage.clear();
    window.location.href = 'index.html';
  };

  let usersCache = [];
  let userPubKeys = {};
  let selectedUser = null;

  let identity;
  let mySessionPubB64 = '';

  const aesOutCache = new Map();
  const receiptSpans = new Map();
  const pendingReadIds = new Set();

  const unreadCounts = new Map(); // username -> number

  (async () => {
    identity = await loadOrCreateIdentity();

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
  usersCache.forEach(u => {
    userPubKeys[u.username] = u.publicKey || '';
    if (!unreadCounts.has(u.username)) unreadCounts.set(u.username, 0);
  });
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

    const name = document.createElement('span');
    name.className = 'username';
    name.textContent = u.username;
    li.appendChild(name);

    // unread badge
    const badge = document.createElement('span');
    badge.className = 'unread-badge';
    const cnt = unreadCounts.get(u.username) || 0;
    badge.textContent = cnt;
    if (cnt > 0) badge.classList.add('show');
    li.appendChild(badge);

    li.onclick = () => selectUser(u.username);
    userList.appendChild(li);
  });
}

function updateUnreadBadge(username) {
  const li = [...document.querySelectorAll('.user-item')]
    .find(el => (el.dataset.username || '').toLowerCase() === (username || '').toLowerCase());
  if (!li) return;
  const badge = li.querySelector('.unread-badge');
  if (!badge) return;
  const cnt = unreadCounts.get(username) || 0;
  badge.textContent = cnt;
  if (cnt > 0) badge.classList.add('show');
  else badge.classList.remove('show');
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

  async function importECDHPub(b64) {
    const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    return crypto.subtle.importKey('raw', bytes.buffer, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
  }
  async function deriveWithPub(peerPubB64) {
    if (!peerPubB64 || peerPubB64.length < 80) throw new Error('Invalid peer pub');
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
    tryMarkRead();
  } catch (e) {
    console.error('Select/derive error:', e);
    alert('Could not establish secure session. Ensure both users are on the chat screen.');
  }

  // ADD THESE TWO LINES:
  unreadCounts.set(username, 0);
  updateUnreadBadge(username);
}
  function addBubble(type, text, ts, read, id) {
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
      rcpt.style.marginLeft = '6px';
      rcpt.textContent = '✓✓';
      rcpt.style.color = read ? '#ffffff' : '#8e8e8e';
      meta.appendChild(rcpt);
      if (id) receiptSpans.set(id, rcpt);
    }
    bubble.appendChild(meta);
    row.appendChild(bubble);
    messageList.appendChild(row);
    messageList.scrollTop = messageList.scrollHeight;
  }
  function isAtBottom() {
    return (messageList.scrollHeight - messageList.scrollTop - messageList.clientHeight) < 30;
  }
  function tryMarkRead() {
    if (document.visibilityState !== 'visible') return;
    if (!isAtBottom()) return;
    if (!pendingReadIds.size) return;
    pendingReadIds.forEach(id => {
      socket.emit('message-read', { messageId: id, reader: currentUser });
    });
    pendingReadIds.clear();
  }
  messageList.addEventListener('scroll', tryMarkRead);
  window.addEventListener('visibilitychange', tryMarkRead);

  async function loadChatHistory(username) {
    const res = await fetch(`/api/messages?user1=${encodeURIComponent(currentUser)}&user2=${encodeURIComponent(username)}`);
    const messages = await res.json();
    messageList.innerHTML = '';
    pendingReadIds.clear();
    for (const m of messages) {
      let txt = '[Decryption Error]';
      try {
        const otherPubForMsg = (m.sender === currentUser) ? m.receiverPub : m.senderPub;
        const aes = await deriveWithPub(otherPubForMsg);
        txt = await decryptAES(aes, m.content);
      } catch {}
      const isSent = m.sender === currentUser;
      addBubble(isSent ? 'sent' : 'received', txt, m.timestamp, !!m.read, m.id);
      if (!isSent && m.read === 0) {
        pendingReadIds.add(m.id);
      }
    }
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
      addBubble('sent', msg, timestamp, false, null);
      messageInput.value = '';
    } catch (e2) {
      console.error('Send failed:', e2);
      alert('Key not established. Ask the other user to open Chat, then reselect the conversation.');
    }
  };

  socket.on('sent-stored', ({ id }) => {
    const last = messageList.querySelector('.msg-row.sent:last-child .read-receipt');
    if (last) receiptSpans.set(id, last);
  });

  socket.on('receive-message', async (m) => {
    let txt = '[Decryption Error]';
    try {
      const otherPubForMsg = (m.sender === currentUser) ? m.receiverPub : m.senderPub;
      const aes = await deriveWithPub(otherPubForMsg);
      txt = await decryptAES(aes, m.content);
    } catch {}
    if (selectedUser === m.sender || selectedUser === m.receiver) {
      addBubble(m.sender === currentUser ? 'sent' : 'received', txt, m.timestamp, false, m.id);
    } 


    if (m.receiver === currentUser && selectedUser !== m.sender) {
    const prev = unreadCounts.get(m.sender) || 0;
    unreadCounts.set(m.sender, prev + 1);
    updateUnreadBadge(m.sender);
  } 

    if (m.receiver === currentUser && selectedUser === m.sender) {
      pendingReadIds.add(m.id);
      tryMarkRead();
    }
  });

  socket.on('read-receipt', ({ messageId }) => {
    const el = receiptSpans.get(messageId);
    if (el) {
      el.textContent = '✓✓';
      el.style.color = '#ffffff';
    }
  });
});