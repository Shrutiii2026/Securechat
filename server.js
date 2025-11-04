const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// SQLite
const db = new sqlite3.Database(path.join(__dirname, 'securechat.db'));
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    publicKey TEXT
  )`);
  // IMPORTANT: includes senderPub and receiverPub for per-message derivation
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT,
    receiver TEXT,
    content TEXT,
    senderPub TEXT,
    receiverPub TEXT,
    timestamp INTEGER
  )`);
});

// Register
app.post('/api/register', (req, res) => {
  const { username, password, publicKey } = req.body;
  if (!username || !password || !publicKey) return res.status(400).json({ error: 'Missing fields' });
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    const stmt = db.prepare(`INSERT INTO users (username, password, publicKey) VALUES (?, ?, ?)`);
    stmt.run(username, hash, publicKey, function (e) {
      if (e) return res.status(400).json({ error: 'Username already exists' });
      return res.json({ success: true });
    });
    stmt.finalize();
  });
});

// Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
    if (err || !user) return res.status(400).json({ error: 'Invalid credentials' });
    bcrypt.compare(password, user.password, (e, ok) => {
      if (e || !ok) return res.status(400).json({ error: 'Invalid credentials' });
      return res.json({ success: true, username: user.username });
    });
  });
});

// Update session public key (chat page load)
app.post('/api/updatePublicKey', (req, res) => {
  const { username, publicKey } = req.body;
  if (!username || !publicKey) return res.status(400).json({ error: 'Missing fields' });
  db.run(`UPDATE users SET publicKey = ? WHERE username = ?`, [publicKey, username], function (err) {
    if (err) return res.status(500).json({ error: 'Could not update public key' });
    return res.json({ success: true });
  });
});

// Users list
app.get('/api/users', (req, res) => {
  db.all(`SELECT username, publicKey FROM users`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    return res.json(rows || []);
  });
});

// Latest public key for a user (for outgoing sends)
app.get('/api/publicKey/:username', (req, res) => {
  const { username } = req.params;
  db.get(`SELECT publicKey FROM users WHERE username = ?`, [username], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!row) return res.status(404).json({ error: 'User not found' });
    return res.json({ publicKey: row.publicKey || '' });
  });
});

// Encrypted history (returns saved per-message pubs)
app.get('/api/messages', (req, res) => {
  const { user1, user2 } = req.query;
  if (!user1 || !user2) return res.status(400).json({ error: 'Missing query params' });
  db.all(
    `SELECT * FROM messages
     WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
     ORDER BY timestamp ASC`,
    [user1, user2, user2, user1],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      return res.json(rows || []);
    }
  );
});

// Presence + realtime relay
const onlineUsers = new Map();

io.on('connection', (socket) => {
  socket.on('login', (username) => {
    if (!username) return;
    onlineUsers.set(username, socket.id);
    io.emit('user-status', { username, status: 'online' });
  });

  socket.on('who-online', () => {
    socket.emit('online-list', Array.from(onlineUsers.keys()));
  });

  socket.on('logout', (username) => {
    if (!username) return;
    onlineUsers.delete(username);
    io.emit('user-status', { username, status: 'offline' });
  });

  // Relay with per-message pubs
  socket.on('send-message', (data) => {
    const { sender, receiver, content, senderPub, receiverPub, timestamp } = data;
    const ts = typeof timestamp === 'number' ? timestamp : Date.now();
    db.run(
      `INSERT INTO messages (sender, receiver, content, senderPub, receiverPub, timestamp)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [sender, receiver, content, senderPub, receiverPub, ts],
      function (err) {
        if (err) return;
        const receiverSocketId = onlineUsers.get(receiver);
        if (receiverSocketId) {
          io.to(receiverSocketId).emit('receive-message', {
            id: this.lastID, sender, receiver, content, senderPub, receiverPub, timestamp: ts
          });
        }
      }
    );
  });

  socket.on('disconnect', () => {
    for (const [user, id] of onlineUsers.entries()) {
      if (id === socket.id) {
        onlineUsers.delete(user);
        io.emit('user-status', { username: user, status: 'offline' });
        break;
      }
    }
  });
});

const PORT = process.env.PORT || 4000;
server.listen(PORT, () => console.log(`SecureChat server running on http://localhost:${PORT}`));
