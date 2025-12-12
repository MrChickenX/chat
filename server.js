// server.js
const express = require('express');
const argon2 = require('argon2');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

const app = express();
const USERS_FILE = path.join(__dirname, 'users.json');

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Hilfsfunktionen
async function loadUsersFile() {
    try {
        const raw = await fs.readFile(USERS_FILE, 'utf8');
        return JSON.parse(raw);
    } catch (err) {
        if (err.code === 'ENOENT') {
            const initial = { users: {} };
            await fs.writeFile(USERS_FILE, JSON.stringify(initial, null, 2));
            return initial;
        }
        throw err;
    }
}

async function saveUsersFile(obj) {
    // Einfacher atomic-ish write: überschreiben (für Demo ausreichend)
    await fs.writeFile(USERS_FILE, JSON.stringify(obj, null, 2));
}

function now() {
    return Date.now();
}

function findUserByUsername(usersObj, username) {
    const entries = Object.entries(usersObj || {});
    for (const [id, u] of entries) {
        if (u.username && u.username.toLowerCase() === String(username).toLowerCase()) return { id, user: u };
    }
    return null;
}

// Register
app.post('/register', async (req, res) => {
    try {
        console.log('[register] payload:', req.body);
        const { username, password, nickname } = req.body || {};

        if (!username || !password) return res.status(400).json({ error: 'Benutzernamen & Passwort benötigt' });

        const db = await loadUsersFile();

        if (findUserByUsername(db.users, username)) {
            return res.status(409).json({ error: 'Benutzer exitiert bereits' });
        }

        const id = crypto.randomUUID();
        const salt = crypto.randomBytes(16); // Buffer
        // argon2.hash accepts a salt Buffer; encoded hash contains params+salt
        const passHash = await argon2.hash(password, { salt });

        const userObj = {
            id,
            username,
            nickname: nickname || username,
            passHash,               // argon2 encoded hash (includes salt/params)
            salt: salt.toString('hex'), // zusätzliches Feld mit hex-salt
            created: now(),
            publicKey: '',
            verified: 'no',
            contacts: []
        };

        db.users[id] = userObj;
        await saveUsersFile(db);

        console.log('[register] new user saved:', { id, username });
        return res.json({ ok: true, id, username });
    } catch (err) {
        console.error('[register] error', err);
        return res.status(500).json({ error: 'Server error' });
    }
});

// Login
app.post('/login', async (req, res) => {
    try {
        console.log('[login] payload:', req.body);
        const { username, password } = req.body || {};

        if (!username || !password) return res.status(400).json({ error: 'Benutzernamen & Passwort benötigt' });

        const db = await loadUsersFile();
        const found = findUserByUsername(db.users, username);
        if (!found) return res.status(401).json({ error: 'Ungültige Anmeldeinformationen' });

        const { user } = found;
        // verify password against stored argon2 hash
        const ok = await argon2.verify(user.passHash, password).catch(() => false);
        if (!ok) return res.status(401).json({ error: 'Ungültige Anmeldeinformationen' });

        // Für Demo: keine Sessions, nur Erfolgsmeldung
        console.log('[login] success for user:', user.username);
        return res.json({ ok: true, id: user.id, username: user.username });
    } catch (err) {
        console.error('[login] error', err);
        return res.status(500).json({ error: 'Server error' });
    }
});

// Optional: debug route, nicht nötig, entferne in prod
app.get('/_debug/users', async (req, res) => {
    const db = await loadUsersFile();
    // gib keine Hashes in public API in prod; hier nur zu debug-Zwecken
    res.json({ ok: true, users: Object.keys(db.users).length });
});


const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
