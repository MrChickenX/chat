const express = require('express');
const argon2 = require('argon2');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const { Server: IOServer } = require('socket.io');

const app = express();
const USERS_FILE = path.join(__dirname, 'users.json');
const MESSAGES_FILE = path.join(__dirname, 'messages.json');

app.use(express.json({ limit: '100mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// atomic save: write to temp then rename
const writeQueues = Object.create(null);

async function saveJSON(filePath, obj) {
    const data = JSON.stringify(obj, null, 2);
    const tmp = `${filePath}.tmp.${Date.now()}`;

    // operation that actually writes the file (attempt rename, fallback to direct write)
    const doWrite = async () => {
        // 1) write tmp file
        await fs.writeFile(tmp, data);
        // 2) try atomic rename
        try {
            await fs.rename(tmp, filePath);
            return;
        } catch (err) {
            console.warn(`[saveJSON] rename failed for ${tmp} -> ${filePath}:`, err && err.code ? err.code : err);
            // fallback: try direct overwrite of destination (less atomic but works on Windows if rename blocked)
            try {
                await fs.writeFile(filePath, data);
                // remove tmp file if still present
                await fs.unlink(tmp).catch(() => { /* ignore */ });
                return;
            } catch (err2) {
                // final failure: try to cleanup tmp and rethrow
                try { await fs.unlink(tmp).catch(() => { }); } catch (e) {/*ignore*/ }
                console.error('[saveJSON] fallback write failed:', err2);
                throw err2;
            }
        }
    };

    // serialize per-file writes to avoid racing renames/writes
    const last = writeQueues[filePath] || Promise.resolve();
    const next = last.then(() => doWrite(), () => doWrite());
    // store the promise so next calls wait
    writeQueues[filePath] = next.finally(() => {
        // clear queue entry if it's settled to avoid memory growth
        if (writeQueues[filePath] === next) delete writeQueues[filePath];
    });
    return next;
}

// robust loader: on parse error rename corrupt file and return default
async function loadJSON(filePath, defaultObj) {
    try {
        const raw = await fs.readFile(filePath, 'utf8');
        return JSON.parse(raw);
    } catch (err) {
        if (err && err.code === 'ENOENT') {
            await fs.writeFile(filePath, JSON.stringify(defaultObj, null, 2));
            return defaultObj;
        }
        if (err instanceof SyntaxError) {
            console.error(`[loadJSON] JSON parse error for ${filePath}:`, err.message);
            // move bad file aside
            try {
                const bak = `${filePath}.corrupt.${Date.now()}`;
                await fs.rename(filePath, bak);
                console.warn(`[loadJSON] moved corrupt file to ${bak} and created fresh file`);
            } catch (e) {
                console.error('[loadJSON] failed to move corrupt file', e);
            }
            await fs.writeFile(filePath, JSON.stringify(defaultObj, null, 2));
            return defaultObj;
        }
        throw err;
    }
}

// convenience wrappers
async function loadUsersFile() { return loadJSON(USERS_FILE, { users: {} }); }
async function loadMessagesFile() { return loadJSON(MESSAGES_FILE, { conversations: {} }); }
async function saveUsersFile(obj) { return saveJSON(USERS_FILE, obj); }
async function saveMessagesFile(obj) { return saveJSON(MESSAGES_FILE, obj); }

function now() { return Date.now(); }

function findUserByUsername(usersObj, username) {
    if (!usersObj) return null;
    const entries = Object.entries(usersObj);
    for (const [id, u] of entries) {
        if (u.username && u.username.toLowerCase() === String(username).toLowerCase()) return { id, user: u };
    }
    return null;
}

/* -----------------------
   REGISTER
   ----------------------- */
app.post('/register', async (req, res) => {
    try {
        const { username, password, nickname, publicKey } = req.body || {};
        if (!username || !password) return res.status(400).json({ error: 'Benutzernamen & Passwort benötigt' });

        const db = await loadUsersFile();
        if (findUserByUsername(db.users, username)) return res.status(409).json({ error: 'Benutzer existiert bereits' });

        const id = crypto.randomUUID();
        const passHash = await argon2.hash(password);

        const sessionToken = crypto.randomUUID();

        const userObj = {
            id,
            username,
            nickname: nickname || username,
            passHash,
            created: now(),
            publicKey: publicKey || '',
            verified: 'no',
            contacts: [],
            sessionToken
        };

        db.users[id] = userObj;
        await saveUsersFile(db);

        console.log(`[register] user created: ${username} (${id})  publicKey? ${!!publicKey}`);
        return res.json({ ok: true, id, username, nickname: userObj.nickname, sessionToken });
    } catch (err) {
        console.error('[register] error', err);
        return res.status(500).json({ error: 'Server error' });
    }
});

/* -----------------------
   LOGIN (jetzt optional publicKey speichern)
   ----------------------- */
app.post('/login', async (req, res) => {
    try {
        const { username, password, publicKey } = req.body || {};
        if (!username || !password) return res.status(400).json({ error: 'Benutzernamen & Passwort benötigt' });

        const db = await loadUsersFile();
        const found = findUserByUsername(db.users, username);
        if (!found) return res.status(401).json({ error: 'Ungültige Anmeldeinformationen' });

        const { user } = found;
        const ok = await argon2.verify(user.passHash, password).catch(() => false);
        if (!ok) return res.status(401).json({ error: 'Ungültige Anmeldeinformationen' });

        if (!user.sessionToken) user.sessionToken = crypto.randomUUID();
        await saveUsersFile(db);

        if (publicKey) {
            user.publicKey = publicKey;
            await saveUsersFile(db);
            console.log(`[login] gespeicherter publicKey für ${user.username} (${user.id})`);
        } else {
            console.log(`[login] no publicKey provided for ${user.username} (${user.id}). current? ${!!user.publicKey}`);
        }

        return res.json({
            ok: true,
            id: user.id,
            username: user.username,
            nickname: user.nickname || user.username,
            publicKey: user.publicKey || '',
            sessionToken: user.sessionToken
        });
    } catch (err) {
        console.error('[login] error', err);
        return res.status(500).json({ error: 'Server error' });
    }
});

/* -----------------------
   Set public key (falls client es separat senden will)
   ----------------------- */
app.post('/user/:id/publicKey', async (req, res) => {
    try {
        const id = req.params.id;
        const { publicKey } = req.body || {};
        if (!publicKey) return res.status(400).json({ error: 'publicKey required' });

        const db = await loadUsersFile();
        const u = db.users[id];
        if (!u) return res.status(404).json({ error: 'user not found' });

        u.publicKey = publicKey;
        await saveUsersFile(db);
        console.log(`[publicKey] saved for ${u.username} (${id})`);
        return res.json({ ok: true });
    } catch (err) {
        console.error('/user/:id/publicKey error', err);
        return res.status(500).json({ error: 'server error' });
    }
});

/* -----------------------
   Small debug: read public key quickly
   ----------------------- */
app.get('/publicKey/:id', async (req, res) => {
    try {
        const db = await loadUsersFile();
        const u = db.users[req.params.id];
        if (!u) return res.status(404).json({ error: 'not found' });
        return res.json({ ok: true, publicKey: u.publicKey || '' });
    } catch (err) {
        console.error('/publicKey error', err);
        return res.status(500).json({ error: 'server error' });
    }
});

/* -----------------------
   Kontakte hinzufügen (by username)
   ----------------------- */
app.post('/user/:id/contacts', async (req, res) => {
    try {
        const id = req.params.id;
        const { contactUsername } = req.body || {};
        if (!contactUsername) return res.status(400).json({ error: 'contactUsername required' });

        const db = await loadUsersFile();
        const me = db.users[id];
        if (!me) return res.status(404).json({ error: 'user not found' });

        const found = findUserByUsername(db.users, contactUsername);
        if (!found) return res.status(404).json({ error: 'contact not found' });

        const contactId = found.id;
        me.contacts = me.contacts || [];
        if (!me.contacts.includes(contactId)) me.contacts.push(contactId);

        // add reverse contact for convenience
        const other = db.users[contactId];
        other.contacts = other.contacts || [];
        if (!other.contacts.includes(id)) other.contacts.push(id);

        await saveUsersFile(db);
        console.log(`[contacts] ${me.username} added ${other.username}`);
        return res.json({ ok: true, contactId });
    } catch (err) {
        console.error('/user/:id/contacts error', err);
        return res.status(500).json({ error: 'server error' });
    }
});

/* -----------------------
   GET user safe info
   ----------------------- */
app.get('/user/:id', async (req, res) => {
    try {
        const db = await loadUsersFile();
        const u = db.users[req.params.id];
        if (!u) return res.status(404).json({ error: 'not found' });
        const safe = {
            id: u.id,
            username: u.username,
            nickname: u.nickname,
            created: u.created,
            publicKey: u.publicKey || '',
            verified: u.verified || 'no',
            contacts: u.contacts || []
        };
        return res.json({ ok: true, user: safe });
    } catch (err) {
        console.error('/user/:id error', err);
        return res.status(500).json({ error: 'server error' });
    }
});

/* -----------------------
   Conversations & messages
   ----------------------- */
app.get('/conversations', async (req, res) => {
    try {
        const userId = req.query.userId;
        if (!userId) return res.status(400).json({ error: 'userId required' });

        const [msgs, usersDb] = await Promise.all([loadMessagesFile(), loadUsersFile()]);
        const convs = Object.values(msgs.conversations || {}).filter(c => (c.members || []).includes(userId));
        const result = convs.map(c => {
            const lastMsg = c.messages && c.messages.length ? c.messages[c.messages.length - 1] : null;
            const unread = (c.messages || []).reduce((acc, m) => acc + ((m.senderId !== userId && !(m.readBy || []).includes(userId)) ? 1 : 0), 0);
            const others = (c.members || []).filter(id => id !== userId).map(id => {
                const u = usersDb.users[id];
                return u ? { id: u.id, username: u.username, nickname: u.nickname } : { id };
            });
            return {
                id: c.id,
                members: c.members,
                lastMessage: lastMsg ? { id: lastMsg.id, ts: lastMsg.ts, senderId: lastMsg.senderId, textEncrypted: lastMsg.textEncrypted, iv: lastMsg.iv } : null,
                unread,
                others
            };
        });
        return res.json({ ok: true, conversations: result });
    } catch (err) {
        console.error('/conversations error', err);
        return res.status(500).json({ error: 'server error' });
    }
});

app.get('/conversation/:id', async (req, res) => {
    try {
        const convId = req.params.id;
        const msgs = await loadMessagesFile();
        const conv = msgs.conversations[convId];
        if (!conv) return res.status(404).json({ error: 'conversation not found' });
        return res.json({ ok: true, conversation: conv });
    } catch (err) {
        console.error('/conversation/:id error', err);
        return res.status(500).json({ error: 'server error' });
    }
});

app.post('/conversation', async (req, res) => {
    try {
        const members = Array.isArray(req.body.members) ? req.body.members.map(String) : null;
        if (!members || members.length < 2) return res.status(400).json({ error: 'members array required (min 2)' });

        const msgs = await loadMessagesFile();
        const memberKey = members.slice().sort().join(',');
        let found = Object.values(msgs.conversations || {}).find(c => c._memberKey === memberKey);
        if (found) return res.json({ ok: true, conversation: found });

        const id = crypto.randomUUID();
        const conv = { id, members, messages: [], created: now(), _memberKey: memberKey };
        msgs.conversations[id] = conv;
        await saveMessagesFile(msgs);
        return res.json({ ok: true, conversation: conv });
    } catch (err) {
        console.error('/conversation POST error', err);
        return res.status(500).json({ error: 'server error' });
    }
});

// message (speichert auch iv & attachments)
app.post('/message', async (req, res) => {
    try {
        const { conversationId, from, textEncrypted, iv, to, attachments } = req.body || {};
        if (!from) return res.status(400).json({ error: 'from required' });

        const msgs = await loadMessagesFile();
        let conv = conversationId ? msgs.conversations[conversationId] : null;
        if (!conv) {
            if (!to) return res.status(400).json({ error: 'conversationId or to required' });
            const members = [String(from), String(to)];
            const memberKey = members.slice().sort().join(',');
            conv = Object.values(msgs.conversations).find(c => c._memberKey === memberKey);
            if (!conv) {
                const id = crypto.randomUUID();
                conv = { id, members, messages: [], created: now(), _memberKey: memberKey };
                msgs.conversations[id] = conv;
            }
        }

        const message = {
            id: crypto.randomUUID(),
            senderId: String(from),
            textEncrypted: textEncrypted || '',
            iv: iv || '',
            attachments: Array.isArray(attachments) ? attachments : [],
            ts: now(),
            readBy: [String(from)]
        };

        conv.messages.push(message);
        await saveMessagesFile(msgs);

        // emit to all members (notify each user's personal room)
        // notify by conversation also (clients can join conv rooms)
        for (const mid of conv.members || []) {
            io.to(`user:${mid}`).emit('message', { conversationId: conv.id, message });
        }
        io.to(`conv:${conv.id}`).emit('conversation_update', { conversationId: conv.id, lastMessage: message });

        // auto-add contacts to users file (convenience)
        try {
            const usersDb = await loadUsersFile();
            conv.members.forEach(mid => {
                usersDb.users[mid] = usersDb.users[mid] || { id: mid, username: mid, contacts: [] };
            });
            conv.members.forEach(mid => {
                const others = conv.members.filter(x => x !== mid);
                others.forEach(o => {
                    if (!usersDb.users[mid].contacts) usersDb.users[mid].contacts = [];
                    if (!usersDb.users[mid].contacts.includes(o)) usersDb.users[mid].contacts.push(o);
                });
            });
            await saveUsersFile(usersDb);
        } catch (e) { /* ignore */ }

        console.log(`[message] conv=${conv.id} from=${from} to=${to || 'N/A'} text? ${!!textEncrypted} attachments=${(attachments || []).length}`);
        return res.json({ ok: true, conversationId: conv.id, message });
    } catch (err) {
        console.error('/message error', err);
        return res.status(500).json({ error: 'server error' });
    }
});

app.patch('/conversation/:id/read', async (req, res) => {
    try {
        const convId = req.params.id;
        const { userId } = req.body || {};
        if (!userId) return res.status(400).json({ error: 'userId required' });

        const msgs = await loadMessagesFile();
        const conv = msgs.conversations[convId];
        if (!conv) return res.status(404).json({ error: 'conversation not found' });

        (conv.messages || []).forEach(m => {
            if (!m.readBy) m.readBy = [];
            if (!m.readBy.includes(userId)) m.readBy.push(userId);
        });

        await saveMessagesFile(msgs);
        return res.json({ ok: true });
    } catch (err) {
        console.error('/conversation/:id/read error', err);
        return res.status(500).json({ error: 'server error' });
    }
});

app.get('/contacts', async (req, res) => {
    try {
        const userId = req.query.userId;
        if (!userId) return res.status(400).json({ error: 'userId required' });

        const [usersDb, msgs] = await Promise.all([loadUsersFile(), loadMessagesFile()]);
        const user = usersDb.users[userId];
        if (!user) return res.status(404).json({ error: 'user not found' });

        const contacts = (user.contacts || []).map(cid => {
            const cu = usersDb.users[cid];
            return cu ? { id: cu.id, username: cu.username, nickname: cu.nickname, verified: cu.verified || 'no' } : { id: cid };
        });

        const result = [];
        for (const c of contacts) {
            const key = [userId, c.id].slice().sort().join(',');
            const conv = Object.values(msgs.conversations || {}).find(cv => cv._memberKey === key);
            const last = conv && conv.messages.length ? conv.messages[conv.messages.length - 1] : null;
            const unread = conv ? (conv.messages || []).reduce((acc, m) => acc + ((m.senderId !== userId && !(m.readBy || []).includes(userId)) ? 1 : 0), 0) : 0;
            result.push({
                id: c.id,
                username: c.username,
                nickname: c.nickname,
                verified: c.verified || 'no',
                conversationId: conv ? conv.id : null,
                lastMessageMeta: last ? { id: last.id, ts: last.ts, senderId: last.senderId, textEncrypted: last.textEncrypted, iv: last.iv } : null,
                unread
            });
        }

        return res.json({ ok: true, contacts: result });
    } catch (err) {
        console.error('/contacts error', err);
        return res.status(500).json({ error: 'server error' });
    }
});

async function cleanupOldMessages() {
    const filePath = 'messages.json';
    try {
        const emptyStructure = {
            conversations: {}
        };

        await fs.writeFile(
            filePath,
            JSON.stringify(emptyStructure, null, 2),
            'utf8'
        );

        console.log(`Inhalt von ${filePath} wurde korrekt geleert.`);
    } catch (err) {
        console.error('Fehler beim Leeren der Datei:', err.message);
    }
}

/* -----------------------
   Debug route
   ----------------------- */
app.get('/_debug/users', async (req, res) => {
    const db = await loadUsersFile();
    res.json({ ok: true, users: Object.keys(db.users).length });
});

const PORT = 3000;
const server = http.createServer(app);
const io = new IOServer(server, {
    // optional: cors falls nötig
    // cors: { origin: '*' }
});

io.use(async (socket, next) => {
    try {
        const sessionToken = socket.handshake.auth?.sessionToken;

        if (!sessionToken) {
            return next(new Error('AUTH_NO_TOKEN'));
        }

        const usersDb = await loadUsersFile();
        const user = Object.values(usersDb.users || {}).find(
            u => u.sessionToken === sessionToken
        );

        if (!user) {
            return next(new Error('AUTH_INVALID_TOKEN'));
        }

        // User am Socket speichern (für später)
        socket.data.userId = user.id;
        socket.data.username = user.username;

        next(); // ✅ Auth OK
    } catch (err) {
        console.error('[socket auth] error', err);
        next(new Error('AUTH_INTERNAL_ERROR'));
    }
});

// socket auth & rooms
io.on('connection', (socket) => {
    try {
        // socket.data.userId wird von io.use (Auth-Middleware) gesetzt
        const userId = socket.data && socket.data.userId;
        const username = socket.data && socket.data.username;

        if (!userId) {
            console.warn('[socket] connected socket without userId, disconnecting', socket.id);
            socket.disconnect(true);
            return;
        }

        const userRoom = `user:${userId}`;
        socket.join(userRoom);

        console.log(`[socket] user connected ${userId} (socket=${socket.id}, username=${username || 'n/a'})`);

        // optional: client kann conv-rooms joinen, damit server gezielt an conv:ID senden kann
        socket.on('join_conv', (convId) => {
            if (!convId) return;
            socket.join(`conv:${convId}`);
            console.log(`[socket] ${userId} joined conv:${convId}`);
        });

        socket.on('leave_conv', (convId) => {
            if (!convId) return;
            socket.leave(`conv:${convId}`);
            console.log(`[socket] ${userId} left conv:${convId}`);
        });

        socket.on('disconnect', (reason) => {
            console.log(`[socket] ${userId} disconnected:`, reason);
        });
    } catch (e) {
        console.error('[socket] connection handler error', e);
        try { socket.disconnect(true); } catch (_) { /* ignore */ }
    }
});

cleanupOldMessages();
server.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
setInterval(() => {
    cleanupOldMessages();
}, 60 * 60 * 24 * 7 * 1000); // jede Woche
