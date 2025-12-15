(() => {
    const API_BASE = window.__API_BASE__ || 'https://rhythm-flu-portal-vehicle.trycloudflare.com';
    const SOCKET_URL = window.__SOCKET_URL__ || 'https://rhythm-flu-portal-vehicle.trycloudflare.com';
    const SOCKET_IO_CDN = 'https://cdn.socket.io/4.7.1/socket.io.min.js';

    function loadSocketIoClient() {
        return new Promise((resolve, reject) => {
            if (typeof io !== 'undefined') return resolve();
            const s = document.createElement('script');
            s.src = SOCKET_IO_CDN;
            s.onload = () => resolve();
            s.onerror = () => reject(new Error('socket.io client load failed'));
            document.head.appendChild(s);
        });
    }

    // ------------------------------------------------------------------
    // API Fetch: robuste Fehlerbehandlung, gibt immer ein Objekt zurück
    // { ok: boolean, status: number, body: any, error?: string }
    // ------------------------------------------------------------------
    async function apiFetch(path, opts = {}) {
        const url = API_BASE ? `${API_BASE}${path}` : path;
        try {
            const res = await fetch(url, {
                ...opts,
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    ...(opts.headers || {})
                }
            });
            const text = await res.text().catch(() => '');
            let parsed = text;
            const ct = res.headers.get('content-type') || '';
            if (ct.includes('application/json')) {
                try { parsed = JSON.parse(text); } catch (e) { parsed = text; }
            }
            if (!res.ok) {
                return { ok: false, status: res.status, body: parsed, error: typeof parsed === 'string' ? parsed : (parsed && parsed.error) || 'HTTP error' };
            }
            return { ok: true, status: res.status, body: parsed };
        } catch (err) {
            return { ok: false, status: 0, body: null, error: err && err.message ? err.message : 'Network error' };
        }
    }

    const api = {
        getContacts: (userId) => apiFetch(`/contacts?userId=${encodeURIComponent(userId)}`),
        getConversation: (convId) => apiFetch(`/conversation/${encodeURIComponent(convId)}`),
        getConversationsForUser: (userId) => apiFetch(`/conversations?userId=${encodeURIComponent(userId)}`),
        createConversation: (members) => apiFetch('/conversation', { method: 'POST', body: JSON.stringify({ members }) }),
        postMessage: (payload) => apiFetch('/message', { method: 'POST', body: JSON.stringify(payload) }),
        markRead: (convId, userId) => apiFetch(`/conversation/${encodeURIComponent(convId)}/read`, { method: 'PATCH', body: JSON.stringify({ userId }) }),
        getUser: (id) => apiFetch(`/user/${encodeURIComponent(id)}`),
        setPublicKey: (id, publicKeyBase64) => apiFetch(`/user/${encodeURIComponent(id)}/publicKey`, { method: 'POST', body: JSON.stringify({ publicKey: publicKeyBase64 }) }),
        addContact: (id, contactUsername) => apiFetch(`/user/${encodeURIComponent(id)}/contacts`, { method: 'POST', body: JSON.stringify({ contactUsername }) })
    };

    // base64 helpers
    function arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        const chunkSize = 0x8000;
        let binary = '';
        for (let i = 0; i < bytes.length; i += chunkSize) {
            const sub = bytes.subarray(i, i + chunkSize);
            binary += String.fromCharCode.apply(null, Array.from(sub));
        }
        return btoa(binary);
    }
    function base64ToArrayBuffer(b64) {
        const binary = atob(b64);
        const len = binary.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
        return bytes.buffer;
    }

    function el(tag, cls) { const e = document.createElement(tag); if (cls) e.className = cls; return e; }
    function formatTime(ts) {
        if (!ts) return '';
        const d = new Date(ts);
        const now = new Date();
        if (d.toDateString() === now.toDateString()) return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        return d.toLocaleDateString();
    }

    // E2EE helpers (unchanged logic)
    const E2EE = {
        async ensureKeypair(userId) {
            const storedPriv = localStorage.getItem('ecdh_jwk_' + userId);
            const storedPub = localStorage.getItem('ecdh_pub_' + userId);
            if (storedPriv && storedPub) {
                const jwk = JSON.parse(storedPriv);
                const priv = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
                return { privateKey: priv, publicBase64: storedPub };
            }
            const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
            const pubRaw = await crypto.subtle.exportKey('raw', kp.publicKey);
            const pubB64 = arrayBufferToBase64(pubRaw);
            const privJwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
            localStorage.setItem('ecdh_pub_' + userId, pubB64);
            localStorage.setItem('ecdh_jwk_' + userId, JSON.stringify(privJwk));
            try { await api.setPublicKey(userId, pubB64); } catch (e) { console.warn('setPublicKey failed', e); }
            const priv = await crypto.subtle.importKey('jwk', privJwk, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
            return { privateKey: priv, publicBase64: pubB64 };
        },
        async importPeerPublicKey(base64) {
            const raw = base64ToArrayBuffer(base64);
            return crypto.subtle.importKey('raw', raw, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
        },
        async deriveAESKey(myPrivKey, theirPubKey) {
            const bits = await crypto.subtle.deriveBits({ name: 'ECDH', public: theirPubKey }, myPrivKey, 256);
            return crypto.subtle.importKey('raw', bits, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
        },
        async encryptWithKey(aesKey, plaintext) {
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const enc = new TextEncoder().encode(plaintext);
            const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, enc);
            return { cipherB64: arrayBufferToBase64(cipher), ivB64: arrayBufferToBase64(iv) };
        },
        async decryptWithKey(aesKey, cipherB64, ivB64) {
            try {
                const cipher = base64ToArrayBuffer(cipherB64);
                const iv = new Uint8Array(base64ToArrayBuffer(ivB64));
                const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, cipher);
                return new TextDecoder().decode(plain);
            } catch (e) {
                console.warn('decrypt error', e);
                return null;
            }
        },
        async encryptBuffer(aesKey, buffer) {
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, buffer);
            return { cipherB64: arrayBufferToBase64(cipher), ivB64: arrayBufferToBase64(iv) };
        },
        async decryptBuffer(aesKey, cipherB64, ivB64) {
            try {
                const cipher = base64ToArrayBuffer(cipherB64);
                const iv = new Uint8Array(base64ToArrayBuffer(ivB64));
                const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, cipher);
                return plain;
            } catch (e) {
                console.warn('decryptBuffer error', e);
                return null;
            }
        }
    };

    document.addEventListener('DOMContentLoaded', async () => {
        const contactsContainer = document.querySelector('.contacts');
        const messagesContainer = document.querySelector('main.chat-messages') || document.querySelector('.chat-messages');
        const headerName = document.querySelector('.current-contact-name');
        const headerStatus = document.querySelector('.current-contact-status');
        const messageInput = document.getElementById('message-input');
        const sendBtn = document.getElementById('send-btn');
        const addBtn = document.getElementById('add-btn');
        const attachBtn = document.getElementById('attach-btn');
        const emojiBtn = document.getElementById('emoji-btn');

        let contacts = [];
        let currentConversationId = null;
        let currentContact = null;
        let attachedFile = null;

        // crypto cache: peerId => { theirPubB64, aesKey (CryptoKey) }
        const cryptoCache = new Map();

        // send dedupe map
        const ongoingSends = new Map();
        const sendLock = new Set();
        let sendCooldown = false;
        function makeSendKey(convId, text, file) {
            const t = String(text || '').trim();
            const fname = file && file.name ? file.name : '';
            return `${convId || 'nocv'}|${t}|${fname}`;
        }

        // load user
        const raw = localStorage.getItem('user');
        const user = raw ? JSON.parse(raw) : null;
        if (!user || !user.id) {
            window.location.href = '/chat/login/login.html';
            return;
        }
        const userId = user.id;
        await E2EE.ensureKeypair(userId);


        const sessionToken = (user && user.sessionToken) ? user.sessionToken : (localStorage.getItem('user') ? JSON.parse(localStorage.getItem('user')).sessionToken : null);

        try { await loadSocketIoClient(); } catch (e) { console.warn('Could not load socket.io client from CDN', e); }

        const socketOptions = { path: '/socket.io', transports: ['websocket'], auth: { sessionToken } };
        let socket = null;
        try { if (typeof io !== 'undefined') socket = io(SOCKET_URL, socketOptions); else console.warn('socket.io client not available'); } catch (e) { console.warn('socket connect failed', e); socket = null; }

        // === Auto-upload publicKey (after socket initialization) ===
        async function uploadPublicKeyAfterInit() {
            try {
                const pubB64 = localStorage.getItem('ecdh_pub_' + userId);
                if (pubB64) {
                    if (socket && socket.connected) {
                        socket.emit('upload_public_key', { publicKey: pubB64 }, (ack) => {
                            if (!ack || ack.error) {
                                api.setPublicKey(userId, pubB64).catch(e => console.warn('setPublicKey fallback failed', e));
                            }
                        });
                    } else {
                        api.setPublicKey(userId, pubB64).catch(e => console.warn('setPublicKey failed', e));
                    }
                }
            } catch (e) {
                console.warn('auto upload publicKey error', e);
            }
        }

        // small UI helpers to set user info
        async function fillUserInfo() {
            try {
                const me = await api.getUser(userId);
                if (me && me.ok && me.body && me.body.user) {
                    const u = me.body.user;
                    ['#username-display', '.username-display', '[data-username]'].forEach(sel => document.querySelectorAll(sel).forEach(el => el && (el.textContent = u.username || '')));
                    ['#nickname-display', '.nickname-display', '[data-nickname]'].forEach(sel => document.querySelectorAll(sel).forEach(el => el && (el.textContent = u.nickname || u.username || '')));
                    ['#user-id', '[data-userid]'].forEach(sel => document.querySelectorAll(sel).forEach(el => el && (el.textContent = u.id || '')));
                    ['#user-verified', '[data-verified]'].forEach(sel => document.querySelectorAll(sel).forEach(el => el && (el.textContent = u.verified || '')));
                    if (u.avatar) {
                        document.querySelectorAll('.avatar, .user-avatar, [data-avatar]').forEach(img => {
                            if (img && img.tagName && img.tagName.toLowerCase() === 'img') img.src = u.avatar;
                            else if (img) img.style.backgroundImage = `url(${u.avatar})`;
                        });
                    }
                }
            } catch (e) { /* ignore */ }
        }
        fillUserInfo();

        document.querySelectorAll('#logout-btn, .logout-btn, [data-logout]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                localStorage.removeItem('user');
                window.location.href = '/chat/login/login.html';
            });
        });

        addBtn && addBtn.addEventListener('click', async () => {
            const name = prompt('Benutzername der Person eingeben:');
            if (!name) return;
            try {
                await E2EE.ensureKeypair(userId);
                const resp = await api.addContact(userId, name.trim());
                if (!resp || !resp.ok) {
                    alert('Kontakt konnte nicht hinzugefügt werden: ' + (resp && resp.error ? resp.error : 'Fehler'));
                    return;
                }
                const peerResp = await api.getUser(resp.body.contactId);
                if (peerResp && peerResp.ok && peerResp.body && peerResp.body.user && peerResp.body.user.publicKey) {
                    alert('Kontakt hinzugefügt — PublicKey gefunden');
                } else {
                    alert('Kontakt hinzugefügt — Peer hat noch keinen PublicKey');
                }
                await loadContacts();
            } catch (err) {
                console.error('addContact error', err);
                alert('Netzwerkfehler');
            }
        });

        const fileInput = el('input'); fileInput.type = 'file'; fileInput.style.display = 'none';
        document.body.appendChild(fileInput);
        attachBtn && attachBtn.addEventListener('click', () => fileInput.click());
        fileInput.addEventListener('change', (ev) => {
            attachedFile = ev.target.files[0] || null;
            if (attachedFile) messageInput.placeholder = 'Datei angehängt: ' + attachedFile.name; else messageInput.placeholder = 'Nachricht ...';
        });

        function createEmojiPicker() {
            const emojis = ['😀', '😁', '😂', '😉', '😊', '😍', '😎', '😢', '👍', '🙏', '🔥', '🎉', '❤️'];
            const box = el('div', 'emoji-picker');
            box.style.position = 'absolute'; box.style.bottom = '64px'; box.style.left = '12px';
            box.style.background = 'white'; box.style.border = '1px solid #ccc'; box.style.padding = '6px';
            box.style.display = 'grid'; box.style.gridTemplateColumns = 'repeat(6,28px)'; box.style.gap = '6px';
            emojis.forEach(em => {
                const b = el('button'); b.type = 'button'; b.textContent = em; b.style.fontSize = '16px';
                b.addEventListener('click', () => {
                    const ta = messageInput; const start = ta.selectionStart || 0; const end = ta.selectionEnd || 0;
                    ta.value = ta.value.slice(0, start) + em + ta.value.slice(end);
                    ta.focus(); ta.selectionStart = ta.selectionEnd = start + em.length;
                    ta.dispatchEvent(new Event('input')); box.remove();
                });
                box.appendChild(b);
            });
            return box;
        }
        emojiBtn && emojiBtn.addEventListener('click', () => {
            const existing = document.querySelector('.emoji-picker'); if (existing) { existing.remove(); return; }
            document.body.appendChild(createEmojiPicker());
        });

        function getIconForFilename(name) {
            if (!name) return '/chat/sources/icons/other.png';
            const ext = (name.split('.').pop() || '').toLowerCase();
            if (['xls', 'xlsx', 'csv'].includes(ext)) return '/chat/sources/icons/excel.png';
            if (['doc', 'docx'].includes(ext)) return '/chat/sources/icons/word.png';
            if (ext === 'pdf') return '/chat/sources/icons/pdf.png';
            if (['ppt', 'pptx'].includes(ext)) return '/chat/sources/icons/powerpoint.png';
            return '/chat/sources/icons/other.png';
        }

        function renderContactItem(c) {
            const root = el('div', 'contact');
            root.id = `contact-${c.id}`;

            const avatar = el('img', 'avatar');
            avatar.src = c.avatar || '/chat/sources/avatars/avatar.png';
            root.appendChild(avatar);

            const wrapper = el('div');

            const nameAnchor = el('a', 'contact-name');
            // name text node
            const nameText = document.createElement('span');
            nameText.textContent = c.nickname || c.username || c.id;
            nameAnchor.appendChild(nameText);

            // verified svg (only if verified)
            if (c.verified && String(c.verified).toLowerCase() === 'yes') {
                const svgWrap = document.createElement('span');
                svgWrap.className = 'verified-icon';
                svgWrap.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 -960 960 960" width="18" height="18" style="margin-left:6px;vertical-align:middle;"><path d="m344-60-76-128-144-32 14-148-98-112 98-112-14-148 144-32 76-128 136 58 136-58 76 128 144 32-14 148 98 112-98 112 14 148-144 32-76 128-136-58-136 58Zm94-278 226-226-56-58-170 170-86-84-56 56 142 142Z"/></svg>`;
                nameAnchor.appendChild(svgWrap);
            }

            wrapper.appendChild(nameAnchor);

            const timeAnchor = el('a', 'last-msg-data');
            timeAnchor.classList.add('new');
            timeAnchor.textContent = c.lastMessageStr || '';
            wrapper.appendChild(timeAnchor);

            const activity = el('a', 'contact-activity');
            activity.textContent = c.preview || '';
            wrapper.appendChild(activity);

            const unread = el('a', 'new-msg-count');
            if (c.unread && c.unread > 0) {
                unread.classList.add('new');
                unread.textContent = String(c.unread);
            } else {
                unread.textContent = '';
            }
            wrapper.appendChild(unread);

            root.appendChild(wrapper);

            root.addEventListener('click', async () => {
                document.querySelectorAll('.contacts .contact').forEach(elm => elm.classList.remove('active'));
                root.classList.add('active');
                if (typeof openConversation === 'function') {
                    try { await openConversation(c); } catch (e) { console.error('openConversation error', e); }
                } else if (typeof window.openConversation === 'function') {
                    try { await window.openConversation(c); } catch (e) { console.error('openConversation error', e); }
                }
            });

            return root;
        }

        // tryDecryptMessage: uses cached AES key - accepts message object and optional otherId override
        async function tryDecryptMessage(msg, otherIdOverride) {
            if (!msg) return null;
            const cipher = msg.textEncrypted || msg.cipher || msg.cipherB64 || msg.cipherText;
            const iv = msg.iv || msg.ivB64 || msg.ivBase64;
            if (!cipher || !iv) return null;

            const otherId = otherIdOverride || ((msg.senderId === userId) ? (currentContact && currentContact.id) : msg.senderId);
            if (!otherId) return null;

            const aesKey = await getOrCreateAesKeyForPeer(otherId);
            if (!aesKey) return null;

            try {
                const dec = await E2EE.decryptWithKey(aesKey, cipher, iv);
                return dec;
            } catch (e) {
                console.warn('tryDecryptMessage failed', e);
                return null;
            }
        }

        // -------------------------------
        // Conversation cache helpers
        // -------------------------------
        function getCachedConversation(convId) {
            if (!convId) return null;
            try {
                const raw = localStorage.getItem('conv_cache_' + convId);
                return raw ? JSON.parse(raw) : null;
            } catch (e) { return null; }
        }
        function saveCachedConversation(conv) {
            if (!conv || !conv.id) return;
            // Keep only essential fields to avoid big storage
            const payload = {
                id: conv.id,
                members: conv.members || [],
                messages: (conv.messages || []).slice(-1000) // keep last 1000
            };
            try { localStorage.setItem('conv_cache_' + conv.id, JSON.stringify(payload)); } catch (e) { console.warn('saveCachedConversation failed', e); }
        }
        function appendMessageToConversationCache(convId, message) {
            if (!convId || !message) return;
            try {
                const cached = getCachedConversation(convId) || { id: convId, members: [], messages: [] };
                cached.messages = cached.messages || [];
                cached.messages.push(message);
                // cap to last 1000
                if (cached.messages.length > 1000) cached.messages = cached.messages.slice(-1000);
                saveCachedConversation(cached);
            } catch (e) { console.warn('appendMessageToConversationCache failed', e); }
        }

        // loadContacts: use lastMessageMeta to reduce calls
        async function loadContacts() {
            try {
                const resp = await api.getContacts(userId);
                if (!resp || !resp.ok) {
                    console.warn('getContacts failed', resp && resp.error);
                    // If contacts unavailable, try to at least show cached contacts (not implemented here)
                    return;
                }
                const arr = (resp.body && resp.body.contacts) ? resp.body.contacts : [];
                const enriched = [];

                for (const c of arr) {
                    let preview = '';
                    let lastMessageStr = '';

                    // Wenn server eine lastMessageMeta liefert, nutzen wir sie zunächst
                    if (c.lastMessageMeta) {
                        const last = c.lastMessageMeta;
                        lastMessageStr = formatTime(last.ts);

                        // Heuristik: fehlt iv => vermutlich unverschluesselt/plaintext
                        const ivPresent = !!(last.iv || last.ivB64);

                        if (!ivPresent) {
                            // Plaintext direkt anzeigen (Server speichert text im Feld textEncrypted)
                            preview = last.textEncrypted || '';
                        } else {
                            // Letzte Nachricht scheint verschluesselt zu sein:
                            // Lade die Konversation und suche die letzte unverschluesselte
                            // oder die letzte Nachricht, die wir erfolgreich entschluesseln koennen.
                            if (c.conversationId) {
                                try {
                                    const convResp = await api.getConversation(c.conversationId);
                                    if (convResp && convResp.ok && convResp.body && convResp.body.conversation) {
                                        const conv = convResp.body.conversation;
                                        const msgs = conv.messages || [];
                                        const maxCheck = 99;
                                        for (let i = msgs.length - 1; i >= 0 && i >= msgs.length - maxCheck; i--) {
                                            const m = msgs[i];
                                            if (m.unencrypted) {
                                                const txt = m.textEncrypted || '';
                                                preview = (m.senderId === userId ? 'Du: ' : '') + txt;
                                                break;
                                            }
                                            if (m.textEncrypted) {
                                                const otherId = (m.senderId === userId) ? (conv.members.find(x => x !== userId) || '') : m.senderId;
                                                const dec = await tryDecryptMessage(m, otherId);
                                                if (dec) {
                                                    preview = (m.senderId === userId ? 'Du: ' : '') + dec;
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                } catch (e) {
                                    console.warn('Failed to fetch/scan conversation for preview', e);
                                }
                            }
                            if (!preview) preview = '(verschlüsselt)';
                        }
                    }

                    enriched.push({ ...c, preview, lastMessageStr, nickname: c.nickname || c.username });
                }

                contacts = enriched;
                if (contactsContainer) {
                    contactsContainer.innerHTML = '';
                    contacts.forEach(c => contactsContainer.appendChild(renderContactItem(c)));
                }
            } catch (err) {
                console.error('loadContacts error', err);
            }
        }

        // getOrCreateAesKeyForPeer: CACHE the result and avoid repeated getUser calls when possible
        async function getOrCreateAesKeyForPeer(peerId) {
            try {
                if (!peerId) return null;

                // quick cache hit
                if (cryptoCache.has(peerId)) {
                    const existing = cryptoCache.get(peerId);
                    if (existing && existing.aesKey) return existing.aesKey;
                }

                // fetch user's public key once
                const userResp = await api.getUser(peerId);
                if (!userResp || !userResp.ok || !userResp.body || !userResp.body.user || !userResp.body.user.publicKey) {
                    return null;
                }
                const theirPubB64 = userResp.body.user.publicKey;

                const cached = cryptoCache.get(peerId);
                if (cached && cached.theirPubB64 === theirPubB64 && cached.aesKey) {
                    return cached.aesKey;
                }

                const myJwk = localStorage.getItem('ecdh_jwk_' + userId);
                if (!myJwk) throw new Error('No local private key');

                const myPrivKey = await crypto.subtle.importKey(
                    'jwk',
                    JSON.parse(myJwk),
                    { name: 'ECDH', namedCurve: 'P-256' },
                    true,
                    ['deriveBits']
                );

                const theirPubKey = await E2EE.importPeerPublicKey(theirPubB64);

                const aesKey = await E2EE.deriveAESKey(myPrivKey, theirPubKey);

                cryptoCache.set(peerId, { theirPubB64, aesKey });
                return aesKey;
            } catch (e) {
                console.warn('getOrCreateAesKeyForPeer error', e);
                return null;
            }
        }

        // Render messages: decrypt first, then render (prevents double-appending)
        async function renderMessages(rawMsgs, opts = { autoScroll: false }) {
            if (!messagesContainer) return;
            messagesContainer.innerHTML = '';

            // Ensure rawMsgs is array
            const msgsArr = Array.isArray(rawMsgs) ? rawMsgs : [];

            // Prepare decrypted text for all messages concurrently
            const prepared = await Promise.all(msgsArr.map(async (m) => {
                const msg = Object.assign({}, m); // shallow copy
                // determine cipher/iv presence
                const cipher = msg.textEncrypted || msg.cipher || msg.cipherB64 || null;
                const iv = msg.iv || msg.ivB64 || null;

                // If server already provided plaintext in text field (unencrypted flag), use it
                if (msg.unencrypted && (msg.textEncrypted || msg.text)) {
                    msg._displayText = msg.textEncrypted || msg.text || '';
                    return msg;
                }

                // If msg has plain text field already, prefer it
                if (msg.text && !cipher && !iv) {
                    msg._displayText = msg.text;
                    return msg;
                }

                // Try to decrypt if there's cipher/iv
                if (cipher && iv) {
                    const otherId = (msg.senderId === userId) ? (currentContact && currentContact.id) || (msg.otherId || '') : msg.senderId;
                    let dec = null;
                    try {
                        dec = await tryDecryptMessage(msg, otherId);
                    } catch (e) { dec = null; }
                    if (dec) msg._displayText = dec;
                    else msg._displayText = '(verschlüsselt)';
                } else {
                    // nothing to show
                    msg._displayText = msg.text || '';
                }
                return msg;
            }));

            // build DOM fragment
            const frag = document.createDocumentFragment();
            for (const m of prepared) {
                const container = el('div', 'message-container' + (m.senderId === userId ? ' my' : ''));
                if (m._id) container.setAttribute('data-msg-id', m._id);
                if (m._tempId) container.setAttribute('data-temp-id', m._tempId);

                const avatarImg = el('img', 'message-avatar');
                avatarImg.src = '/chat/sources/avatars/avatar.png';
                const box = el('div', 'message-box' + (m.senderId === userId ? ' my' : ''));

                // attachments
                if (m.attachments && m.attachments.length) {
                    m.attachments.forEach(att => {
                        const mf = el('div', 'message-file');
                        const fi = el('img', 'file-icon');
                        fi.src = (typeof getIconForFilename === 'function') ? getIconForFilename(att.filename) : '/chat/sources/icons/other.png';
                        fi.alt = att.filename || 'file';
                        fi.style.width = '28px'; fi.style.height = '28px'; fi.style.verticalAlign = 'middle';

                        const fp = el('div', 'file-property');
                        const name = el('a', 'file-name'); name.textContent = att.filename || 'file';
                        const btn = el('button', 'file-download'); btn.textContent = 'Download';
                        btn.addEventListener('click', () => downloadAttachment(m, att));

                        fp.appendChild(name);
                        fp.appendChild(document.createElement('br'));
                        fp.appendChild(btn);

                        mf.appendChild(fi);
                        mf.appendChild(fp);
                        box.appendChild(mf);
                    });
                }

                // text
                if (m._displayText && String(m._displayText).trim().length) {
                    const textNode = el('div', 'message-text');
                    textNode.textContent = m._displayText;
                    if (m.attachments && m.attachments.length) textNode.style.marginTop = '6px';
                    box.appendChild(textNode);
                }

                const time = el('a', 'message-time');
                time.textContent = formatTime(m.ts);
                time.style.display = 'block';
                time.style.marginTop = '6px';
                time.style.fontSize = '11px';
                time.style.color = '#666';
                box.appendChild(time);

                if (m.senderId === userId) {
                    container.appendChild(box);
                    container.appendChild(avatarImg);
                } else {
                    container.appendChild(avatarImg);
                    container.appendChild(box);
                }

                frag.appendChild(container);
            }

            messagesContainer.appendChild(frag);

            // auto-scroll logic
            const threshold = 80;
            const nearBottom = (messagesContainer.scrollHeight - messagesContainer.scrollTop - messagesContainer.clientHeight) < threshold;

            if (opts.autoScroll || nearBottom) {
                requestAnimationFrame(() => {
                    messagesContainer.scrollTop = messagesContainer.scrollHeight;
                });
            }
        }

        async function downloadAttachment(messageObj, att) {
            try {
                const otherId = messageObj.senderId === userId ? (currentContact && currentContact.id) : messageObj.senderId;
                const aesKey = await getOrCreateAesKeyForPeer(otherId);
                if (!aesKey) return alert('Kein AES-Key zum Entschlüsseln verfügbar');
                const cipher = att.cipher || att.cipherB64 || att.cipherText;
                const iv = att.iv || att.ivB64 || att.ivBase64;
                if (!cipher || !iv) return alert('Keine korrekten Dateidaten vorhanden');
                const ab = await E2EE.decryptBuffer(aesKey, cipher, iv);
                if (!ab) return alert('Datei konnte nicht entschlüsselt werden');
                const blob = new Blob([ab], { type: att.mime || 'application/octet-stream' });
                const url = URL.createObjectURL(blob);
                const a = el('a'); a.href = url; a.download = att.filename || 'file';
                document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
            } catch (e) {
                console.error('downloadAttachment error', e);
                alert('Fehler beim Herunterladen');
            }
        }

        // cleanup helper: avoid stuck ongoingSends (fallback after timeout)
        function releaseOngoingSendKeyWithTimeout(sendKey, ms = 10000) {
            setTimeout(() => {
                if (ongoingSends.has(sendKey)) {
                    ongoingSends.delete(sendKey);
                    sendLock.delete(sendKey);
                }
            }, ms);
        }

        const lastSendTimes = new Map();

        // SEND-LOGIC (with 5ms temporary lock + button disable)
        async function sendMessage() {
            if (sendCooldown) {
                console.warn('Send blocked by short cooldown');
                return;
            }

            const text = (messageInput.value || '').trim();
            if (!text && !attachedFile) return;

            if (!currentContact) { if (!contacts.length) return alert('Kein Kontakt ausgewählt'); currentContact = contacts[0]; }

            const sendKey = makeSendKey(currentConversationId, text, attachedFile);

            if (sendLock.has(sendKey)) {
                console.warn('Duplicate send suppressed for key (sendLock):', sendKey);
                return;
            }
            sendLock.add(sendKey);
            setTimeout(() => sendLock.delete(sendKey), 5);

            sendCooldown = true;
            if (sendBtn) sendBtn.disabled = true;
            setTimeout(() => { sendCooldown = false; if (sendBtn) sendBtn.disabled = false; }, 5);

            if (ongoingSends.has(sendKey)) {
                console.warn('Duplicate send suppressed for key (ongoing):', sendKey);
                return;
            }

            const nowTs = Date.now();
            const lastTs = lastSendTimes.get(sendKey) || 0;
            const MIN_REPEAT_MS = 5;
            if (nowTs - lastTs < MIN_REPEAT_MS) {
                console.warn('Duplicate send suppressed for key (time-window):', sendKey);
                return;
            }
            lastSendTimes.set(sendKey, nowTs);

            ongoingSends.set(sendKey, true);
            releaseOngoingSendKeyWithTimeout(sendKey, 10000);

            const tempId = `temp-${Date.now()}-${Math.floor(Math.random() * 100000)}`;

            try {
                if (!currentConversationId) {
                    const resp = await api.createConversation([userId, currentContact.id]);
                    if (!resp || !resp.ok) { ongoingSends.delete(sendKey); return alert('Konversation konnte nicht erstellt werden'); }
                    currentConversationId = resp.body.conversation.id;
                }

                const optimisticMsg = {
                    senderId: userId,
                    text: text || (attachedFile ? '[Datei]' : ''),
                    attachments: attachedFile ? [{ filename: attachedFile.name }] : [],
                    ts: Date.now(),
                    _tempId: tempId
                };

                // append optimistic to DOM and cache
                const domEl = appendMessageToDOM(optimisticMsg);
                appendMessageToConversationCache(currentConversationId, {
                    id: null,
                    senderId: optimisticMsg.senderId,
                    ts: optimisticMsg.ts,
                    textEncrypted: optimisticMsg.text,
                    _tempId: tempId,
                    attachments: optimisticMsg.attachments || []
                });

                messageInput.value = '';
                messageInput.placeholder = 'Nachricht ...';
                messageInput.focus();
                messageInput.dispatchEvent(new Event('input'));

                // prepare encryption (get AES key once)
                let aesKey = null;
                try { aesKey = await getOrCreateAesKeyForPeer(currentContact.id); } catch (e) { console.warn('getOrCreateAesKeyForPeer failed', e); aesKey = null; }

                let textEncrypted = '';
                let textIv = '';
                let unencryptedFlag = false;

                if (text && aesKey) {
                    try {
                        const enc = await E2EE.encryptWithKey(aesKey, text);
                        textEncrypted = enc.cipherB64; textIv = enc.ivB64;
                    } catch (e) { console.warn('encryptWithKey failed', e); textEncrypted = text; unencryptedFlag = true; }
                } else if (text && !aesKey) {
                    textEncrypted = text;
                    unencryptedFlag = true;
                }

                const attachments = [];
                if (attachedFile && aesKey) {
                    try {
                        const ab = await attachedFile.arrayBuffer();
                        const enc = await E2EE.encryptBuffer(aesKey, ab);
                        attachments.push({ filename: attachedFile.name, mime: attachedFile.type || 'application/octet-stream', cipher: enc.cipherB64, iv: enc.ivB64 });
                    } catch (e) { console.warn('encrypt attachment failed', e); }
                } else if (attachedFile && !aesKey) {
                    console.warn('Attachment nicht gesendet: Peer hat keinen PublicKey (Attachments werden nicht unverschlüsselt gesendet)');
                }

                const payload = {
                    clientId: tempId,
                    conversationId: currentConversationId,
                    from: userId,
                    to: currentContact.id,
                    textEncrypted,
                    iv: textIv,
                    attachments,
                };
                if (unencryptedFlag) payload.unencrypted = true;

                if (socket && socket.connected) {
                    socket.emit('send_message', payload, (ack) => {
                        try {
                            if (!ack || ack.error) {
                                console.error('send_message ack error', ack && ack.error);
                                markMessageFailed(tempId);
                            } else {
                                updateTempMessageWithServer(tempId, ack.message);
                                // update cache: replace temp by server id
                                appendMessageToConversationCache(currentConversationId, ack.message);
                                loadContacts().catch(() => { });
                            }
                        } finally {
                            ongoingSends.delete(sendKey);
                        }
                    });
                } else {
                    try {
                        const resp = await api.postMessage(payload);
                        if (!resp || !resp.ok) {
                            markMessageFailed(tempId);
                        } else {
                            updateTempMessageWithServer(tempId, resp.body.message || resp.body);
                            appendMessageToConversationCache(currentConversationId, resp.body.message || resp.body);
                            loadContacts().catch(() => { });
                        }
                    } catch (e) {
                        console.error('postMessage fallback error', e);
                        markMessageFailed(tempId);
                    } finally {
                        ongoingSends.delete(sendKey);
                    }
                }

                attachedFile = null;
                fileInput.value = '';
            } catch (e) {
                console.error('sendMessage error', e);
                alert('Fehler beim Senden');
                ongoingSends.delete(sendKey);
            }
        }

        function markMessageFailed(tempId) {
            const el = messagesContainer.querySelector(`[data-temp-id="${tempId}"]`);
            if (!el) return;
            el.classList.add('send-failed');
        }

        function updateTempMessageWithServer(tempId, serverMsg) {
            const elTemp = messagesContainer.querySelector(`[data-temp-id="${tempId}"]`);
            if (!elTemp) {
                if (!serverMsg || !serverMsg.id) return;
                const exists = messagesContainer.querySelector(`[data-msg-id="${serverMsg.id}"]`);
                if (exists) return;
                // render server message (use renderMessages to ensure correct decryption)
                const msg = { senderId: serverMsg.senderId, textEncrypted: serverMsg.textEncrypted || serverMsg.text || '', attachments: serverMsg.attachments || [], ts: serverMsg.ts, _id: serverMsg.id };
                renderMessages([msg], { autoScroll: true });
                return;
            }
            elTemp.setAttribute('data-msg-id', serverMsg.id || '');
            elTemp.removeAttribute('data-temp-id');
            const timeEl = elTemp.querySelector('.message-time');
            if (timeEl) timeEl.textContent = formatTime(serverMsg.ts);
            elTemp.classList.remove('send-failed');
            // update cache as well
            appendMessageToConversationCache(currentConversationId, serverMsg);
        }

        // appendMessageToDOM remains for optimistic messages but uses simpler attribute names
        function appendMessageToDOM(m) {
            if (!messagesContainer) return;
            const container = el('div', 'message-container' + (m.senderId === userId ? ' my' : ''));
            if (m._tempId) container.setAttribute('data-temp-id', m._tempId);
            if (m._id) container.setAttribute('data-msg-id', m._id);

            const avatarImg = el('img', 'message-avatar');
            avatarImg.src = '/chat/sources/avatars/avatar.png';
            const box = el('div', 'message-box' + (m.senderId === userId ? ' my' : ''));

            if (m.attachments && m.attachments.length) {
                m.attachments.forEach(att => {
                    const mf = el('div', 'message-file');
                    const fi = el('img', 'file-icon');
                    fi.src = (typeof getIconForFilename === 'function') ? getIconForFilename(att.filename) : '/chat/sources/icons/other.png';
                    fi.alt = att.filename || 'file';
                    fi.style.width = '28px'; fi.style.height = '28px'; fi.style.verticalAlign = 'middle';

                    const fp = el('div', 'file-property');
                    const name = el('a', 'file-name'); name.textContent = att.filename || 'file';
                    const btn = el('button', 'file-download'); btn.textContent = 'Download';
                    btn.addEventListener('click', () => downloadAttachment(m, att));

                    fp.appendChild(name);
                    fp.appendChild(document.createElement('br'));
                    fp.appendChild(btn);

                    mf.appendChild(fi);
                    mf.appendChild(fp);
                    box.appendChild(mf);
                });
            }

            if (m.text && String(m.text).trim().length) {
                const textNode = el('div', 'message-text');
                textNode.textContent = m.text;
                if (m.attachments && m.attachments.length) textNode.style.marginTop = '6px';
                box.appendChild(textNode);
            }

            const time = el('a', 'message-time');
            time.textContent = formatTime(m.ts);
            time.style.display = 'block';
            time.style.marginTop = '6px';
            time.style.fontSize = '11px';
            time.style.color = '#666';
            box.appendChild(time);

            if (m.senderId === userId) {
                container.appendChild(box);
                container.appendChild(avatarImg);
            } else {
                container.appendChild(avatarImg);
                container.appendChild(box);
            }

            messagesContainer.appendChild(container);
            requestAnimationFrame(() => { messagesContainer.scrollTop = messagesContainer.scrollHeight; });

            return container;
        }

        await loadContacts();
        if (contacts.length && contactsContainer) {
            const first = contactsContainer.querySelector('.contact');
            if (first) first.click();
        }

        // ===== helper: robust decrypt for incoming messages =====
        async function decryptIncomingText(incoming) {
            const otherId = (incoming.senderId === userId) ? (currentContact && currentContact.id) || '' : incoming.senderId;

            // 1) try cached aesKey
            let entry = cryptoCache.get(otherId);
            let aesKey = entry && entry.aesKey ? entry.aesKey : null;

            // 2) derive if needed (getOrCreateAesKeyForPeer caches the result)
            if (!aesKey) {
                aesKey = await getOrCreateAesKeyForPeer(otherId);
                entry = cryptoCache.get(otherId) || entry || null;
            }

            // 3) if still no key, try forcing a user fetch & derive once more
            if (!aesKey) {
                const uresp = await api.getUser(otherId);
                if (uresp && uresp.ok && uresp.body && uresp.body.user && uresp.body.user.publicKey) {
                    aesKey = await getOrCreateAesKeyForPeer(otherId);
                }
            }

            if (!aesKey) return '(verschlüsselt)';

            const cipher = incoming.textEncrypted || incoming.cipher || incoming.cipherB64;
            const iv = incoming.iv || incoming.ivB64;
            if (!cipher || !iv) return '(verschlüsselt)';

            try {
                const dec = await E2EE.decryptWithKey(aesKey, cipher, iv);
                return dec || '(verschlüsselt)';
            } catch (e) {
                console.warn('decryptIncomingText failed', e);
                return '(verschlüsselt)';
            }
        }

        // Socket handlers (update cache on incoming)
        if (socket) {
            socket.on('message', async (data) => {
                try {
                    if (!data || !data.message) return;
                    const incoming = data.message;
                    const convId = data.conversationId;

                    // Belongs to current conversation?
                    if (currentConversationId && convId === currentConversationId) {

                        // Unencrypted messages (server-flag)
                        if (incoming.unencrypted) {
                            const clientId = incoming.clientId || incoming.clientid || null;
                            if (clientId) {
                                const tempEl = messagesContainer.querySelector(`[data-temp-id="${clientId}"]`);
                                if (tempEl) {
                                    tempEl.setAttribute('data-msg-id', incoming.id || '');
                                    tempEl.removeAttribute('data-temp-id');
                                    const txtEl = tempEl.querySelector('.message-text');
                                    if (txtEl) txtEl.textContent = incoming.textEncrypted || txtEl.textContent;
                                    const timeEl = tempEl.querySelector('.message-time');
                                    if (timeEl) timeEl.textContent = formatTime(incoming.ts || Date.now());
                                    tempEl.classList.remove('send-failed');
                                    try { api.markRead(currentConversationId, userId); } catch (e) { }
                                    // update cache
                                    appendMessageToConversationCache(currentConversationId, incoming);
                                    loadContacts().catch(() => { });
                                    return;
                                }
                            }

                            if (incoming.id) {
                                const exists = messagesContainer.querySelector(`[data-msg-id="${incoming.id}"]`);
                                if (exists) return;
                            }

                            const msgObj = { senderId: incoming.senderId, text: incoming.textEncrypted || '', attachments: incoming.attachments || [], ts: incoming.ts || Date.now(), _id: incoming.id };
                            appendMessageToDOM(msgObj);
                            appendMessageToConversationCache(convId, incoming);
                            try { api.markRead(currentConversationId, userId); } catch (e) { }
                            loadContacts().catch(() => { });
                            return;
                        }

                        // Encrypted flow: always try to decrypt using helper
                        const clientId = incoming.clientId || incoming.clientid || null;
                        let text = '';
                        try {
                            text = await decryptIncomingText(incoming);
                        } catch (e) {
                            console.warn('decryptIncomingText error', e);
                            text = '(verschlüsselt)';
                        }

                        if (clientId) {
                            const tempEl = messagesContainer.querySelector(`[data-temp-id="${clientId}"]`);
                            if (tempEl) {
                                tempEl.setAttribute('data-msg-id', incoming.id || '');
                                tempEl.removeAttribute('data-temp-id');
                                const txtEl = tempEl.querySelector('.message-text');
                                if (txtEl) txtEl.textContent = text || txtEl.textContent;
                                const timeEl = tempEl.querySelector('.message-time');
                                if (timeEl) timeEl.textContent = formatTime(incoming.ts || Date.now());
                                tempEl.classList.remove('send-failed');
                                try { api.markRead(currentConversationId, userId); } catch (e) { }
                                appendMessageToConversationCache(currentConversationId, incoming);
                                loadContacts().catch(() => { });
                                return;
                            }
                        }

                        if (incoming.id) {
                            const exists = messagesContainer.querySelector(`[data-msg-id="${incoming.id}"]`);
                            if (exists) return;
                        }

                        // render using renderMessages so decryption and attachments handled consistently
                        const msgObj = { senderId: incoming.senderId, textEncrypted: incoming.textEncrypted || '', attachments: incoming.attachments || [], ts: incoming.ts || Date.now(), _id: incoming.id };
                        renderMessages([msgObj], { autoScroll: true });
                        appendMessageToConversationCache(convId, incoming);
                        try { api.markRead(currentConversationId, userId); } catch (e) { }
                        loadContacts().catch(() => { });
                        return;
                    }

                    // otherwise: refresh contacts (new messages)
                    await loadContacts();
                } catch (e) {
                    console.error('socket message handler', e);
                }
            });

            socket.on('contacts_update', async (data) => {
                try {
                    await loadContacts();
                    const updatedUserId = data && (data.userId || data.contactId || data.updatedUserId);
                    if (updatedUserId && currentContact && updatedUserId === currentContact.id) {
                        try {
                            const k = await getOrCreateAesKeyForPeer(currentContact.id);
                            if (k) {
                                const lockEl = document.querySelector(`#contact-${currentContact.id} .contact-lock`);
                                if (lockEl) lockEl.textContent = '🔒';
                            }
                        } catch (e) { /* ignore */ }
                    }
                } catch (e) {
                    console.error('contacts_update handler', e);
                }
            });

            socket.on('conversation_update', () => { loadContacts().catch(() => { }); });
            socket.on('connect', () => { console.log('[socket] connected', socket.id); uploadPublicKeyAfterInit().catch(() => { }); });
            socket.on('disconnect', (reason) => { console.log('[socket] disconnected', reason); });
            socket.on('connect_error', (err) => {
                console.error('[socket] connect_error:', err && err.message ? err.message : err);
                const msg = err && err.message ? err.message : 'Socket-Fehler';
                switch (msg) {
                    case 'AUTH_NO_TOKEN':
                        alert('Socket-Verbindung fehlgeschlagen: Kein Login-Token vorhanden.');
                        break;
                    case 'AUTH_INVALID_TOKEN':
                        alert('Socket-Verbindung fehlgeschlagen: Login abgelaufen oder ungültig.');
                        localStorage.removeItem('user');
                        window.location.href = '/chat/login/login.html';
                        break;
                    case 'AUTH_INTERNAL_ERROR':
                        alert('Interner Serverfehler bei der Socket-Anmeldung.');
                        break;
                    default:
                        console.warn('Socket-Fehler:', msg);
                }
            });
        }

        // OPEN conversation loads from server; if server fails, fallback to cached conversation
        async function openConversation(contact) {
            try {
                currentContact = contact;
                if (headerName) headerName.textContent = contact.nickname || contact.username || contact.id;
                if (headerStatus) headerStatus.textContent = 'Online';

                try {
                    const k = await getOrCreateAesKeyForPeer(contact.id);
                    if (k) {
                        const lockEl = document.querySelector(`#contact-${contact.id} .contact-lock`);
                        if (lockEl) lockEl.textContent = '🔒';
                    }
                } catch (e) { /* ignore */ }

                let convId = contact.conversationId;
                if (!convId) {
                    const convsResp = await api.getConversationsForUser(userId);
                    if (convsResp && convsResp.ok && convsResp.body && convsResp.body.conversations) {
                        const found = (convsResp.body.conversations || []).find(c => (c.members || []).includes(contact.id));
                        if (found) convId = found.id;
                    }
                }
                if (!convId) {
                    currentConversationId = null;
                    if (messagesContainer) messagesContainer.innerHTML = '';
                    return;
                }
                currentConversationId = convId;

                if (socket && socket.connected) socket.emit('join_conv', currentConversationId, () => { });

                // try server first, fallback to cache
                let resp = null;
                try {
                    resp = await api.getConversation(convId);
                } catch (e) { resp = null; }

                let conv = null;
                if (resp && resp.ok && resp.body && resp.body.conversation) {
                    conv = resp.body.conversation;
                    saveCachedConversation(conv);
                } else {
                    const cached = getCachedConversation(convId);
                    if (cached) {
                        conv = { id: cached.id, members: cached.members || [], messages: cached.messages || [] };
                    } else {
                        // nothing to show
                        if (messagesContainer) messagesContainer.innerHTML = '';
                        return;
                    }
                }

                // render conversation messages (let renderMessages handle decryption)
                const msgsForRender = (conv.messages || []).map(m => {
                    // unify fields: server might store textEncrypted or text
                    return {
                        _id: m.id || m._id || m._msgId || null,
                        _tempId: m.clientId || m.clientid || m._tempId || null,
                        senderId: m.senderId || m.from,
                        textEncrypted: m.textEncrypted || m.text || m.cipher || null,
                        iv: m.iv || m.ivB64 || null,
                        attachments: m.attachments || [],
                        ts: m.ts || m.createdAt || Date.now(),
                        unencrypted: !!m.unencrypted
                    };
                });

                await renderMessages(msgsForRender, { autoScroll: true });
                try { api.markRead(convId, userId); } catch (e) { }
                await loadContacts();
            } catch (e) {
                console.error('openConversation error', e);
            }
        }

        window.sendMessage = sendMessage;
        sendBtn && sendBtn.addEventListener('click', (e) => { e.preventDefault(); sendMessage(); });
        messageInput && messageInput.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); } });

    });
})();