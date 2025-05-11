// --- Dependencies ---
console.log("Dependencies loaded");
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');

// --- Constants ---
const PORT = 3001;
const JWT_SECRET = 'supersecretkey';
const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = 'admin123';
console.log("Constants defined");

// --- App Setup ---
const app = express();
app.use(cors());
app.use(bodyParser.json());
console.log("Express app configured");

// --- SQLite DB Setup ---
const db = new sqlite3.Database('./newsapp.db');
console.log("Database connection established");

db.serialize(() => {
    console.log("Setting up database tables");
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
    console.log("Users table created or verified");

    // Articles table
    db.run(`CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    url TEXT NOT NULL,
    published_at DATETIME
  )`);
    console.log("Articles table created or verified");

    // Saved articles table
    db.run(`CREATE TABLE IF NOT EXISTS saved_articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    article_id INTEGER NOT NULL,
    saved_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(article_id) REFERENCES articles(id)
  )`);
    console.log("Saved articles table created or verified");

    // Seed admin user if not exists
    db.get('SELECT * FROM users WHERE username = ?', [ADMIN_USERNAME], (err, row) => {
        if (err) console.log("Error checking for admin user:", err);
        if (!row) {
            const hash = bcrypt.hashSync(ADMIN_PASSWORD, 10);
            db.run('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)', [ADMIN_USERNAME, hash, 'admin']);
            console.log('Seeded admin user:', ADMIN_USERNAME, ADMIN_PASSWORD);
        } else {
            console.log("Admin user already exists");
        }
    });
});

// --- JWT Middleware ---
const authenticateJWT = (req, res, next) => {
    console.log("Authenticating JWT for request to:", req.path);
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        console.log("No authorization header found");
        return res.sendStatus(401);
    }
    const token = authHeader.split(' ')[1];
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.log("JWT verification failed:", err.message);
            return res.sendStatus(403);
        }
        console.log("JWT authenticated for user:", user.username);
        req.user = user;
        next();
    });
};

// --- Role Middleware ---
const requireAdmin = (req, res, next) => {
    console.log("Checking admin role for user:", req.user.username);
    if (req.user.role !== 'admin') {
        console.log("Access denied: user is not admin");
        return res.sendStatus(403);
    }
    console.log("Admin access granted");
    next();
};

// --- Auth Endpoints ---
app.post('/api/auth/signup', (req, res) => {
    console.log("Signup attempt for username:", req.body.username);
    const { username, password } = req.body;
    if (!username || !password) {
        console.log("Signup failed: missing fields");
        return res.status(400).json({ error: 'Missing fields' });
    }
    const hash = bcrypt.hashSync(password, 10);
    db.run('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, hash], function (err) {
        if (err) {
            console.log("Signup failed: username taken");
            return res.status(400).json({ error: 'Username taken' });
        }
        const user = { userId: this.lastID, username, role: 'user' };
        const token = jwt.sign(user, JWT_SECRET, { expiresIn: '1h' });
        console.log("User created successfully:", username);
        res.json({ token, ...user });
    });
});

app.post('/api/auth/login', (req, res) => {
    console.log("Login attempt for username:", req.body.username);
    const { username, password } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (!user) {
            console.log("Login failed: user not found");
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        if (!bcrypt.compareSync(password, user.password_hash)) {
            console.log("Login failed: incorrect password");
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const payload = { userId: user.id, username: user.username, role: user.role };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
        console.log("Login successful for:", username);
        res.json({ token, ...payload });
    });
});

// --- Articles Endpoints ---
app.get('/api/articles', (req, res) => {
    console.log("Fetching all articles");
    db.all('SELECT * FROM articles', [], (err, rows) => {
        if (err) {
            console.log("Error fetching articles:", err);
            return res.status(500).json({ error: 'DB error' });
        }
        console.log(`Retrieved ${rows.length} articles`);
        res.json(rows);
    });
});

app.post('/api/articles/save', authenticateJWT, (req, res) => {
    console.log("Saving article for user:", req.user.username);
    const { article } = req.body;
    if (!article || !article.title || !article.url) {
        console.log("Save failed: missing article fields");
        return res.status(400).json({ error: 'Missing article fields' });
    }
    // Insert article if not exists
    db.get('SELECT * FROM articles WHERE url = ?', [article.url], (err, row) => {
        if (err) console.log("Error checking for existing article:", err);
        if (row) {
            console.log("Article already exists, saving reference");
            // Already exists, just save
            db.run('INSERT INTO saved_articles (user_id, article_id) VALUES (?, ?)', [req.user.userId, row.id], function (err2) {
                if (err2) {
                    console.log("Error saving article reference:", err2);
                    return res.status(400).json({ error: 'Already saved' });
                }
                console.log("Article reference saved successfully");
                res.json({ success: true });
            });
        } else {
            console.log("Creating new article:", article.title);
            db.run('INSERT INTO articles (title, content, url, published_at) VALUES (?, ?, ?, ?)', [article.title, article.content || '', article.url, article.published_at || null], function (err2) {
                if (err2) {
                    console.log("Error creating article:", err2);
                    return res.status(500).json({ error: 'DB error' });
                }
                console.log("Article created with ID:", this.lastID);
                db.run('INSERT INTO saved_articles (user_id, article_id) VALUES (?, ?)', [req.user.userId, this.lastID], function (err3) {
                    if (err3) {
                        console.log("Error saving article reference:", err3);
                        return res.status(500).json({ error: 'DB error' });
                    }
                    console.log("Article saved successfully");
                    res.json({ success: true });
                });
            });
        }
    });
});

app.get('/api/articles/saved', authenticateJWT, (req, res) => {
    console.log("Fetching saved articles for user:", req.user.username);
    db.all(`SELECT a.* FROM articles a JOIN saved_articles s ON a.id = s.article_id WHERE s.user_id = ?`, [req.user.userId], (err, rows) => {
        if (err) {
            console.log("Error fetching saved articles:", err);
            return res.status(500).json({ error: 'DB error' });
        }
        console.log(`Retrieved ${rows.length} saved articles`);
        res.json(rows);
    });
});

app.delete('/api/articles/saved/:id', authenticateJWT, (req, res) => {
    console.log(`Removing saved article ${req.params.id} for user:`, req.user.username);
    db.run('DELETE FROM saved_articles WHERE user_id = ? AND article_id = ?', [req.user.userId, req.params.id], function (err) {
        if (err) {
            console.log("Error removing saved article:", err);
            return res.status(500).json({ error: 'DB error' });
        }
        console.log(`Removed article with ${this.changes} changes`);
        res.json({ success: true });
    });
});

// --- Admin Endpoints ---
app.get('/api/admin/users', authenticateJWT, requireAdmin, (req, res) => {
    console.log("Admin request: fetching all users");
    db.all('SELECT id, username, role, created_at FROM users', [], (err, rows) => {
        if (err) {
            console.log("Error fetching users:", err);
            return res.status(500).json({ error: 'DB error' });
        }
        console.log(`Retrieved ${rows.length} users`);
        res.json(rows);
    });
});

app.post('/api/admin/promote', authenticateJWT, requireAdmin, (req, res) => {
    console.log(`Admin request: promoting user ${req.body.username} to admin`);
    const { username } = req.body;
    if (!username) {
        console.log("Promotion failed: missing username");
        return res.status(400).json({ error: 'Missing username' });
    }
    db.run('UPDATE users SET role = ? WHERE username = ?', ['admin', username], function (err) {
        if (err) {
            console.log("Error promoting user:", err);
            return res.status(500).json({ error: 'DB error' });
        }
        if (this.changes === 0) {
            console.log("Promotion failed: user not found");
            return res.status(404).json({ error: 'User not found' });
        }
        console.log(`User ${username} promoted to admin successfully`);
        res.json({ success: true });
    });
});

// --- Start Server ---
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
}); 
