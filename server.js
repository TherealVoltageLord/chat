require('dotenv').config();
const express = require('express');
const WebSocket = require('ws');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const path = require('path');

// Database initialization
const db = new sqlite3.Database(process.env.DB_PATH || './voltura.db', (err) => {
  if (err) {
    console.error('Database connection error:', err);
    process.exit(1);
  }
  console.log('Connected to SQLite database');
});

// Database schema setup
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    online BOOLEAN DEFAULT 0,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    recipient_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    status TEXT DEFAULT 'sent' CHECK(status IN ('sent', 'delivered', 'read')),
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(sender_id) REFERENCES users(id),
    FOREIGN KEY(recipient_id) REFERENCES users(id)
  )`);

  db.run('CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id)');
});

const app = express();
app.use(helmet());
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

// Authentication middleware
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1] || '';
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
};

app.use(express.static(__dirname));

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/chat', authenticate, (req, res) => {
  res.sendFile(path.join(__dirname, 'chat.html'));
});

app.post('/register', [
  body('username').isLength({ min: 3, max: 20 }).trim().escape(),
  body('password').isLength({ min: 8 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const { username, password } = req.body;
    const existingUser = await new Promise((resolve, reject) => {
      db.get('SELECT username FROM users WHERE username = ?', [username], (err, row) => {
        return err ? reject(err) : resolve(row);
      });
    });

    if (existingUser) return res.status(409).json({ error: 'Username exists' });

    const hashedPassword = await bcrypt.hash(password, 12);
    await new Promise((resolve, reject) => {
      db.run('INSERT INTO users (username, password) VALUES (?, ?)', 
        [username, hashedPassword], 
        function(err) {
          return err ? reject(err) : resolve(this.lastID);
        }
      );
    });

    res.status(201).json({ message: 'Registration successful' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/login', [
  body('username').trim().escape(),
  body('password').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const { username, password } = req.body;
    const user = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
        return err ? reject(err) : resolve(row);
      });
    });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    db.run('UPDATE users SET online = 1 WHERE id = ?', user.id);
    res.json({ token, username: user.username, userId: user.id });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/users', authenticate, (req, res) => {
  db.all(
    `SELECT id, username, online, 
     strftime('%Y-%m-%d %H:%M:%S', last_seen) as last_seen 
     FROM users WHERE id != ? ORDER BY username`,
    [req.user.id],
    (err, users) => {
      if (err) {
        console.error('Users fetch error:', err);
        return res.status(500).json({ error: 'Failed to fetch users' });
      }
      res.json(users);
    }
  );
});

app.get('/messages', authenticate, (req, res) => {
  const { contact } = req.query;
  if (!contact) return res.status(400).json({ error: 'Missing contact parameter' });

  db.all(
    `SELECT m.*, u.username as sender_name 
     FROM messages m
     JOIN users u ON m.sender_id = u.id
     WHERE (m.sender_id = ? AND m.recipient_id = ?)
     OR (m.sender_id = ? AND m.recipient_id = ?)
     ORDER BY m.timestamp DESC LIMIT 100`,
    [req.user.id, contact, contact, req.user.id],
    (err, messages) => {
      if (err) {
        console.error('Messages fetch error:', err);
        return res.status(500).json({ error: 'Failed to fetch messages' });
      }
      res.json(messages);
    }
  );
});

// WebSocket Server
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
  console.log(`HTTP server running on port ${PORT}`);
});

const wss = new WebSocket.Server({ server });
const activeClients = new Map();

wss.on('connection', (ws, req) => {
  const token = new URL(req.url, `http://${req.headers.host}`).searchParams.get('token');
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return ws.close();

    activeClients.set(user.id, ws);
    db.run('UPDATE users SET online = 1 WHERE id = ?', user.id);
    broadcastPresence(user.id, true);

    ws.on('message', (data) => {
      try {
        const message = JSON.parse(data);
        handleMessage(user, message);
      } catch (err) {
        console.error('WS message error:', err);
      }
    });

    ws.on('close', () => {
      activeClients.delete(user.id);
      db.run('UPDATE users SET online = 0 WHERE id = ?', user.id);
      broadcastPresence(user.id, false);
    });
  });
});

function handleMessage(sender, message) {
  switch (message.type) {
    case 'message':
      db.run(
        `INSERT INTO messages (sender_id, recipient_id, content) 
         VALUES (?, ?, ?)`,
        [sender.id, message.recipient, message.content],
        function(err) {
          if (err) return console.error('Message save error:', err);

          const newMessage = {
            id: this.lastID,
            sender: sender.id,
            recipient: message.recipient,
            content: message.content,
            status: activeClients.has(message.recipient) ? 'delivered' : 'sent',
            timestamp: new Date().toISOString()
          };

          activeClients.get(message.recipient)?.send(JSON.stringify({
            type: 'message',
            data: newMessage
          }));

          db.run('UPDATE messages SET status = ? WHERE id = ?', [newMessage.status, newMessage.id]);
        }
      );
      break;

    case 'typing':
      activeClients.get(message.recipient)?.send(JSON.stringify({
        type: 'typing',
        sender: sender.id
      }));
      break;

    case 'read':
      db.run('UPDATE messages SET status = ? WHERE id = ?', ['read', message.messageId]);
      break;
  }
}

function broadcastPresence(userId, isOnline) {
  activeClients.forEach((ws, id) => {
    if (id !== userId && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({
        type: 'presence',
        userId,
        isOnline
      }));
    }
  });
}

// Error handling
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Cleanup job
setInterval(() => {
  db.run("DELETE FROM messages WHERE timestamp < datetime('now', '-30 days')");
}, 86400000);

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('Shutting down server...');
  db.close();
  server.close();
  process.exit();
});

process.on('SIGTERM', () => {
  console.log('Terminating server...');
  db.close();
  server.close();
  process.exit();
});
