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

// Create tables
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
});

// Express setup
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

// Routes
app.post('/register', [
  body('username').isLength({ min: 3, max: 20 }).trim().escape(),
  body('password').isLength({ min: 8 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, password } = req.body;

  try {
    // Check if user exists
    const existingUser = await new Promise((resolve, reject) => {
      db.get('SELECT username FROM users WHERE username = ?', [username], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });

    if (existingUser) {
      return res.status(409).json({ error: 'Username already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create new user
    await new Promise((resolve, reject) => {
      db.run('INSERT INTO users (username, password) VALUES (?, ?)', 
        [username, hashedPassword],
        function(err) {
          if (err) reject(err);
          else resolve(this.lastID);
        }
      );
    });

    res.status(201).json({ message: 'User created successfully' });
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
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, password } = req.body;

  try {
    // Find user
    const user = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT
    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Update user status
    db.run('UPDATE users SET online = 1 WHERE id = ?', user.id);

    res.json({ 
      token,
      username: user.username,
      userId: user.id 
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/users', authenticate, (req, res) => {
  db.all(
    `SELECT id, username, online, 
     strftime('%Y-%m-%d %H:%M:%S', last_seen) as last_seen 
     FROM users WHERE id != ? 
     ORDER BY username`,
    [req.user.id],
    (err, rows) => {
      if (err) {
        console.error('Users fetch error:', err);
        return res.status(500).json({ error: 'Failed to fetch users' });
      }
      res.json(rows);
    }
  );
});

app.get('/messages', authenticate, (req, res) => {
  const { contact } = req.query;
  if (!contact) {
    return res.status(400).json({ error: 'Missing contact parameter' });
  }

  db.all(
    `SELECT m.*, u.username as sender_name 
     FROM messages m
     JOIN users u ON m.sender_id = u.id
     WHERE (m.sender_id = ? AND m.recipient_id = ?)
     OR (m.sender_id = ? AND m.recipient_id = ?)
     ORDER BY m.timestamp DESC
     LIMIT 100`,
    [req.user.id, contact, contact, req.user.id],
    (err, rows) => {
      if (err) {
        console.error('Messages fetch error:', err);
        return res.status(500).json({ error: 'Failed to fetch messages' });
      }
      res.json(rows);
    }
  );
});

// WebSocket Server
const server = app.listen(process.env.PORT || 3000);
const wss = new WebSocket.Server({ server });
const activeClients = new Map();

wss.on('connection', (ws, req) => {
  const token = new URL(req.url, `http://${req.headers.host}`).searchParams.get('token');

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      ws.close();
      return;
    }

    // Store connection
    activeClients.set(user.id, ws);
    broadcastPresence(user.id, true);

    // Message handler
    ws.on('message', async (data) => {
      try {
        const message = JSON.parse(data);
        
        if (message.type === 'message') {
          // Save message to database
          db.run(
            `INSERT INTO messages 
             (sender_id, recipient_id, content) 
             VALUES (?, ?, ?)`,
            [user.id, message.recipient, message.content],
            function(err) {
              if (err) throw err;

              const newMessage = {
                id: this.lastID,
                sender: user.id,
                recipient: message.recipient,
                content: message.content,
                status: 'sent',
                timestamp: new Date().toISOString()
              };

              // Update status to delivered if recipient is online
              if (activeClients.has(message.recipient)) {
                newMessage.status = 'delivered';
                db.run('UPDATE messages SET status = ? WHERE id = ?', ['delivered', newMessage.id]);
              }

              // Send to recipient
              const recipientWs = activeClients.get(message.recipient);
              if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
                recipientWs.send(JSON.stringify({
                  type: 'message',
                  data: newMessage
                }));
              }

              // Send confirmation to sender
              ws.send(JSON.stringify({
                type: 'message-confirm',
                data: newMessage
              }));
            }
          );
        }
        else if (message.type === 'typing') {
          const recipientWs = activeClients.get(message.recipient);
          if (recipientWs) {
            recipientWs.send(JSON.stringify({
              type: 'typing',
              sender: user.id
            }));
          }
        }
        else if (message.type === 'read') {
          db.run('UPDATE messages SET status = ? WHERE id = ?', ['read', message.messageId]);
        }
      } catch (err) {
        console.error('WebSocket message error:', err);
      }
    });

    // Connection close handler
    ws.on('close', () => {
      activeClients.delete(user.id);
      db.run('UPDATE users SET online = 0 WHERE id = ?', user.id);
      broadcastPresence(user.id, false);
    });
  });
});

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

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Cleanup job
setInterval(() => {
  db.run("DELETE FROM messages WHERE timestamp < datetime('now', '-30 days')");
}, 86400000); // Run daily

// Server start
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  db.close();
  server.close();
  process.exit();
});
