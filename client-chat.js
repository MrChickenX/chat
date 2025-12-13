(() => {
    const api = {
        getContacts: (userId) => fetch(`/contacts?userId=${encodeURIComponent(userId)}`).then(r => r.json()),
        getConversation: (convId) => fetch(`/conversation/${encodeURIComponent(convId)}`).then(r => r.json()),
        getConversationsForUser: (userId) => fetch(`/conversations?userId=${encodeURIComponent(userId)}`).then(r => r.json()),
        createConversation: (members) => fetch('/conversation', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ members }) }).then(r => r.json()),
        postMessage: (payload) => fetch('/message', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }).then(r => r.json()),
        markRead: (convId, userId) => fetch(`/conversation/${encodeURIComponent(convId)}/read`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ userId }) }).then(r => r.json()),
        getUser: (id) => fetch(`/user/${encodeURIComponent(id)}`).then(r => r.json()),
        setPublicKey: (id, publicKeyBase64) => fetch(`/user/${encodeURIComponent(id)}/publicKey`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ publicKey: publicKeyBase64 }) }).then(r => r.json()),
        addContact: (id, contactUsername) => fetch(`/user/${encodeURIComponent(id)}/contacts`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ contactUsername }) }).then(r => r.json())
    };

    const API_BASE = window.__API_BASE__ || '';
    const socketUrl = API_BASE || undefined; // wenn '' -> relative (same origin)
    const socket = io(socketUrl, { path: '/socket.io', auth: { sessionToken }, transports: ['websocket', 'polling'] });

    function apiFetch(path, opts = {}) {
        const url = API_BASE ? `${API_BASE}${path}` : path;
        return fetch(url, {
            ...opts,
            credentials: 'include', // wenn du Cookies nutzt; ansonsten entferne
            headers: {
                'Content-Type': 'application/json',
                ...(opts.headers || {})
            }
        }).then(async res => {
            if (!res.ok) {
                const text = await res.text();
                console.error('apiFetch error', res.status, text.slice(0, 200));
                throw new Error(`HTTP ${res.status}`);
            }
            // safe parse
            const ct = res.headers.get('content-type') || '';
            if (ct.includes('application/json')) return res.json();
            return res.text();
        });
    }

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

    function el(tag, cls) {
        const e = document.createElement(tag);
        if (cls) e.className = cls;
        return e;
    }
    function formatTime(ts) {
        if (!ts) return '';
        const d = new Date(ts);
        const now = new Date();
        if (d.toDateString() === now.toDateString()) return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        return d.toLocaleDateString();
    }

    // E2EE helpers (unchanged)...
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
        const raw = localStorage.getItem('user');
        const user = raw ? JSON.parse(raw) : null;
        if (!user || !user.id) {
            window.location.href = '/login/login.html';
            return;
        }
        const userId = user.id;
        await E2EE.ensureKeypair(userId);
        const sessionToken = (user && user.sessionToken) ? user.sessionToken : (localStorage.getItem('user') ? JSON.parse(localStorage.getItem('user')).sessionToken : null);

        // socket
        const socket = io({ auth: { sessionToken } });

        // UI refs
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

        // cache for peer publickey/aesKey to speed up repeated sends
        // key: peerId => { theirPubB64, aesKeyPromise }
        const cryptoCache = new Map();

        // ---------- NEW: in-flight send dedupe map ----------
        // key => true while sending (key = convId|text|filename)
        const ongoingSends = new Map();

        function makeSendKey(convId, text, file) {
            const t = String(text || '').trim();
            const fname = file && file.name ? file.name : '';
            // Note: we do NOT include timestamp/random here so duplicates (same content) are detected
            return `${convId || 'nocv'}|${t}|${fname}`;
        }

        function setText(selectors, text) {
            selectors.forEach(sel => {
                document.querySelectorAll(sel).forEach(el => {
                    if (el) el.textContent = text;
                });
            });
        }

        try {
            const me = await api.getUser(userId);
            if (me.ok && me.user) {
                setText(['#username-display', '.username-display', '[data-username]'], me.user.username || '');
                setText(['#nickname-display', '.nickname-display', '[data-nickname]'], me.user.nickname || me.user.username || '');
                setText(['#user-id', '[data-userid]'], me.user.id || '');
                setText(['#user-verified', '[data-verified]'], me.user.verified || '');
                setText(['#user-publickey', '[data-publickey]'], me.user.publicKey || '');
                if (me.user.avatar) {
                    document.querySelectorAll('.avatar, .user-avatar, [data-avatar]').forEach(img => {
                        if (img && img.tagName && img.tagName.toLowerCase() === 'img') img.src = me.user.avatar;
                        else if (img) img.style.backgroundImage = `url(${me.user.avatar})`;
                    });
                }
            }
        } catch (e) { /* ignore */ }

        document.querySelectorAll('#logout-btn, .logout-btn, [data-logout]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                localStorage.removeItem('user');
                window.location.href = '/login/login.html';
            });
        });

        addBtn && addBtn.addEventListener('click', async () => {
            const name = prompt('Benutzername der Person eingeben:');
            if (!name) return;
            try {
                await E2EE.ensureKeypair(userId);
                const resp = await api.addContact(userId, name.trim());
                if (resp.ok) {
                    const peerResp = await api.getUser(resp.contactId);
                    if (peerResp.ok && peerResp.user && peerResp.user.publicKey) {
                        alert('Kontakt hinzugefügt — PublicKey gefunden');
                    } else {
                        alert('Kontakt hinzugefügt — Peer hat noch keinen PublicKey');
                    }
                    await loadContacts();
                } else {
                    alert('Kontakt konnte nicht hinzugefügt werden: ' + (resp.error || 'Fehler'));
                }
            } catch (err) {
                console.error('addContact error', err);
                alert('Netzwerkfehler');
            }
        });

        // file attach
        const fileInput = el('input'); fileInput.type = 'file'; fileInput.style.display = 'none';
        document.body.appendChild(fileInput);
        attachBtn && attachBtn.addEventListener('click', () => fileInput.click());
        fileInput.addEventListener('change', (ev) => { attachedFile = ev.target.files[0] || null; if (attachedFile) messageInput.placeholder = 'Datei angehängt: ' + attachedFile.name; else messageInput.placeholder = 'Nachricht ...'; });

        // emoji picker unchanged...
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
            if (!name) return '/sources/icons/other.png';
            const ext = (name.split('.').pop() || '').toLowerCase();
            if (['xls', 'xlsx', 'csv'].includes(ext)) return '/sources/icons/excel.png';
            if (['doc', 'docx'].includes(ext)) return '/sources/icons/word.png';
            if (ext === 'pdf') return '/sources/icons/pdf.png';
            if (['ppt', 'pptx'].includes(ext)) return '/sources/icons/powerpoint.png';
            return '/sources/icons/other.png';
        }

        function renderContactItem(c) {
            const root = el('div', 'contact');
            root.id = `contact-${c.id}`;

            const avatar = el('img', 'avatar');
            avatar.src = c.avatar || '/sources/avatars/avatar.png';
            root.appendChild(avatar);

            const wrapper = el('div');

            const nameAnchor = el('a', 'contact-name');
            nameAnchor.id = 'contact-name';
            nameAnchor.textContent = c.nickname || c.username || c.id;

            if (c.verified && String(c.verified).toLowerCase() === 'yes') {
                const svgHTML = `
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 -960 960 960" fill="#000000" style="width:18px;height:18px;margin-left:6px;vertical-align:middle;">
                        <path d="m344-60-76-128-144-32 14-148-98-112 98-112-14-148 144-32 76-128 136 58 136-58 76 128 144 32-14 148 98 112-98 112 14 148-144 32-76 128-136-58-136 58Zm94-278 226-226-56-58-170 170-86-84-56 56 142 142Z"/>
                    </svg>
                `;
                nameAnchor.insertAdjacentHTML('beforeend', svgHTML);
            }

            const timeAnchor = el('a', 'last-msg-data');
            timeAnchor.classList.add('new');
            timeAnchor.textContent = c.lastMessageStr || '';
            wrapper.appendChild(nameAnchor);
            wrapper.appendChild(timeAnchor);

            const activity = el('a', 'contact-activity');
            activity.id = 'contact-activity';
            activity.textContent = c.preview || '';
            wrapper.appendChild(activity);

            const unread = el('a', 'new-msg-count');
            unread.id = 'new-msg-count';
            if (c.unread && c.unread > 0) {
                unread.classList.add('new');
                unread.textContent = String(c.unread);
            } else {
                unread.textContent = '';
            }
            wrapper.appendChild(unread);

            root.appendChild(wrapper);

            root.addEventListener('click', async () => {
                document.querySelectorAll('.contacts .contact').forEach(el => el.classList.remove('active'));
                root.classList.add('active');
                if (typeof openConversation === 'function') {
                    try { await openConversation(c); } catch (e) { console.error('openConversation error', e); }
                } else if (typeof window.openConversation === 'function') {
                    try { await window.openConversation(c); } catch (e) { console.error('openConversation error', e); }
                }
            });

            return root;
        }

        // decryption helper (unchanged)
        async function tryDecryptMessage(msg, otherId) {
            if (!msg || !msg.textEncrypted) return '';
            try {
                const userResp = await api.getUser(otherId);
                if (!userResp.ok || !userResp.user.publicKey) return '(verschlüsselt)';
                const theirPub = await E2EE.importPeerPublicKey(userResp.user.publicKey);
                const myJwk = localStorage.getItem('ecdh_jwk_' + userId);
                if (!myJwk) return '(verschlüsselt)';
                const myPriv = await crypto.subtle.importKey('jwk', JSON.parse(myJwk), { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
                const aes = await E2EE.deriveAESKey(myPriv, theirPub);
                const dec = await E2EE.decryptWithKey(aes, msg.textEncrypted, msg.iv || msg.ivB64);
                return dec || '(verschlüsselt)';
            } catch (e) {
                console.warn('tryDecryptMessage failed', e);
                return '(verschlüsselt)';
            }
        }

        async function loadContacts() {
            try {
                const resp = await apiFetch(`/contacts?userId=${encodeURIComponent(userId)}`)
                    .then(x => typeof x === 'string' ? JSON.parse(x) : x);
                if (!resp.ok) return;
                const arr = resp.contacts || [];
                const enriched = [];
                for (const c of arr) {
                    let preview = '';
                    let lastMessageStr = '';
                    if (c.conversationId) {
                        const convResp = await api.getConversation(c.conversationId);
                        if (convResp.ok) {
                            const conv = convResp.conversation;
                            const last = conv.messages && conv.messages.length ? conv.messages[conv.messages.length - 1] : null;
                            if (last) {
                                const otherId = last.senderId === userId ? (conv.members.find(x => x !== userId) || '') : last.senderId;
                                const dec = await tryDecryptMessage(last, otherId);
                                preview = dec ? ((last.senderId === userId ? 'Du: ' : '') + dec) : '(verschlüsselt)';
                                lastMessageStr = formatTime(last.ts);
                            }
                        }
                    }
                    enriched.push({ ...c, preview, lastMessageStr, nickname: c.nickname || c.username });
                }
                contacts = enriched;
                contactsContainer.innerHTML = '';
                contacts.forEach(c => contactsContainer.appendChild(renderContactItem(c)));
            } catch (err) {
                console.error('loadContacts error', err);
            }
        }

        async function openConversation(contact) {
            try {
                currentContact = contact;
                headerName && (headerName.textContent = contact.nickname || contact.username || contact.id);
                headerStatus && (headerStatus.textContent = 'Online');

                let convId = contact.conversationId;
                if (!convId) {
                    const convs = await api.getConversationsForUser(userId);
                    if (convs.ok) {
                        const found = (convs.conversations || []).find(c => (c.members || []).includes(contact.id));
                        if (found) convId = found.id;
                    }
                }
                if (!convId) {
                    currentConversationId = null;
                    messagesContainer.innerHTML = '';
                    return;
                }
                currentConversationId = convId;

                if (socket && currentConversationId) {
                    socket.emit('join_conv', currentConversationId);
                }

                const resp = await api.getConversation(convId);
                if (!resp.ok) { messagesContainer.innerHTML = ''; return; }
                const conv = resp.conversation;

                const msgs = [];
                for (const m of conv.messages || []) {
                    const otherId = m.senderId === userId ? (conv.members.find(x => x !== userId) || '') : m.senderId;
                    let text = '';
                    if (m.textEncrypted) {
                        const dec = await tryDecryptMessage(m, otherId);
                        text = dec || '(konnte nicht entschlüsselt werden)';
                    }
                    msgs.push({ ...m, text });
                }

                renderMessages(msgs.map(mm => ({ senderId: mm.senderId, text: mm.text, attachments: mm.attachments || [], ts: mm.ts })), { autoScroll: true });
                await api.markRead(convId, userId).catch(() => { });
                await loadContacts();
            } catch (e) {
                console.error('openConversation error', e);
            }
        }

        function renderMessages(msgs, opts = { autoScroll: false }) {
            messagesContainer.innerHTML = '';
            const frag = document.createDocumentFragment();

            msgs.forEach(m => {
                const container = el('div', 'message-container' + (m.senderId === userId ? ' my' : ''));
                if (m._id) container.dataset.msgId = m._id;
                if (m._tempId) container.dataset.tempId = m._tempId;

                const avatarImg = el('img', 'message-avatar');
                avatarImg.src = '/sources/avatars/avatar.png';
                const box = el('div', 'message-box' + (m.senderId === userId ? ' my' : ''));

                if (m.attachments && m.attachments.length) {
                    m.attachments.forEach(att => {
                        const mf = el('div', 'message-file');
                        const fi = el('img', 'file-icon');
                        fi.src = (typeof getIconForFilename === 'function') ? getIconForFilename(att.filename) : '/sources/icons/other.png';
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

                frag.appendChild(container);
            });

            messagesContainer.appendChild(frag);

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
                const uresp = await api.getUser(otherId);
                if (!uresp.ok) return alert('Konnte Absender nicht finden');
                const theirPubB64 = uresp.user.publicKey;
                if (!theirPubB64) return alert('Kein PublicKey');
                const theirPub = await E2EE.importPeerPublicKey(theirPubB64);
                const myPriv = await crypto.subtle.importKey('jwk', JSON.parse(localStorage.getItem('ecdh_jwk_' + userId)), { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
                const aesKey = await E2EE.deriveAESKey(myPriv, theirPub);
                const ab = await E2EE.decryptBuffer(aesKey, att.cipher, att.iv);
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

        // --- AES key cache helper (unchanged) ---
        async function getOrCreateAesKeyForPeer(peerId) {
            if (cryptoCache.has(peerId)) {
                const entry = cryptoCache.get(peerId);
                const userResp = await api.getUser(peerId);
                const theirPubB64 = userResp.ok ? (userResp.user.publicKey || '') : '';
                if (entry.theirPubB64 === theirPubB64 && entry.aesKeyPromise) return entry.aesKeyPromise;
            }
            const userResp = await api.getUser(peerId);
            if (!userResp.ok || !userResp.user.publicKey) throw new Error('Peer has no publicKey');
            const theirPubB64 = userResp.user.publicKey;
            const myJwk = localStorage.getItem('ecdh_jwk_' + userId);
            if (!myJwk) throw new Error('No local private key');
            const myPrivKey = await crypto.subtle.importKey('jwk', JSON.parse(myJwk), { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
            const theirPubKey = await E2EE.importPeerPublicKey(theirPubB64);
            const aesKeyPromise = E2EE.deriveAESKey(myPrivKey, theirPubKey);
            const entry = { theirPubB64, aesKeyPromise };
            cryptoCache.set(peerId, entry);
            return aesKeyPromise;
        }

        // ---------- SEND-LOGIC (überarbeitet + dedupe + clientId) ----------
        async function sendMessage() {
            const text = (messageInput.value || '').trim();
            if (!text && !attachedFile) return;

            if (!currentContact) { if (!contacts.length) return alert('Kein Kontakt ausgewählt'); currentContact = contacts[0]; }

            // Erstelle einen dedupe-key: conv|text|filename
            const sendKey = makeSendKey(currentConversationId, text, attachedFile);
            if (ongoingSends.has(sendKey)) {
                // bereits im Senden; ignoriere diese erneute Anforderung
                console.warn('Duplicate send suppressed for key', sendKey);
                return;
            }
            ongoingSends.set(sendKey, true);

            // generiere tempId / clientId frühzeitig
            const tempId = `temp-${Date.now()}-${Math.floor(Math.random() * 100000)}`;

            try {
                // ensure conversation exists
                if (!currentConversationId) {
                    const resp = await api.createConversation([userId, currentContact.id]);
                    if (!resp.ok) return alert('Konversation konnte nicht erstellt werden');
                    currentConversationId = resp.conversation.id;
                }

                // optimistic message object with temporary id
                const optimisticMsg = {
                    senderId: userId,
                    text: text || (attachedFile ? '[Datei]' : ''),
                    attachments: attachedFile ? [{ filename: attachedFile.name }] : [],
                    ts: Date.now(),
                    _tempId: tempId
                };

                // show immediately (optimistic UI)
                appendMessageToDOM(optimisticMsg);

                // reset input quickly for snappy UX
                messageInput.value = '';
                messageInput.placeholder = 'Nachricht ...';
                messageInput.focus();
                messageInput.dispatchEvent(new Event('input'));

                // prepare encryption
                let aesKey = null;
                try {
                    aesKey = await getOrCreateAesKeyForPeer(currentContact.id);
                } catch (e) {
                    console.warn('getOrCreateAesKeyForPeer failed (continuing):', e);
                    aesKey = null;
                }

                let textEncrypted = '';
                let textIv = '';
                if (text && aesKey) {
                    try {
                        const enc = await E2EE.encryptWithKey(aesKey, text);
                        textEncrypted = enc.cipherB64; textIv = enc.ivB64;
                    } catch (e) {
                        console.warn('encryptWithKey failed', e);
                        textEncrypted = '';
                        textIv = '';
                    }
                }

                const attachments = [];
                if (attachedFile && aesKey) {
                    try {
                        const ab = await attachedFile.arrayBuffer();
                        const enc = await E2EE.encryptBuffer(aesKey, ab);
                        attachments.push({ filename: attachedFile.name, mime: attachedFile.type || 'application/octet-stream', cipher: enc.cipherB64, iv: enc.ivB64 });
                    } catch (e) {
                        console.warn('encrypt attachment failed', e);
                    }
                }

                // payload now includes clientId so server can echo it back
                const payload = {
                    clientId: tempId,
                    conversationId: currentConversationId,
                    from: userId,
                    to: currentContact.id,
                    textEncrypted,
                    iv: textIv,
                    attachments
                };

                // Primary: socket if connected
                if (socket && socket.connected) {
                    socket.emit('send_message', payload, (ack) => {
                        if (!ack) {
                            console.error('no ack from server for send_message');
                            markMessageFailed(tempId);
                            ongoingSends.delete(sendKey);
                            return;
                        }
                        if (ack.error) {
                            console.error('send_message ack error', ack.error);
                            markMessageFailed(tempId);
                            ongoingSends.delete(sendKey);
                            return;
                        }
                        // server acked and will broadcast; also update optimistic element now
                        try {
                            updateTempMessageWithServer(tempId, ack.message);
                        } catch (e) {
                            console.warn('updateTempMessageWithServer failed', e);
                        }
                        loadContacts().catch(() => { });
                        ongoingSends.delete(sendKey);
                    });
                } else {
                    // Fallback: use REST to persist message (socket offline)
                    try {
                        const resp = await api.postMessage(payload);
                        if (!resp || !resp.ok) {
                            console.warn('postMessage fallback failed', resp && resp.error);
                            markMessageFailed(tempId);
                            ongoingSends.delete(sendKey);
                        } else {
                            updateTempMessageWithServer(tempId, resp.message || resp.message || resp);
                            loadContacts().catch(() => { });
                            ongoingSends.delete(sendKey);
                        }
                    } catch (e) {
                        console.error('postMessage fallback error', e);
                        markMessageFailed(tempId);
                        ongoingSends.delete(sendKey);
                    }
                }

                // reset attachment state
                attachedFile = null;
                fileInput.value = '';
            } catch (e) {
                console.error('sendMessage error', e);
                alert('Fehler beim Senden');
                ongoingSends.delete(sendKey);
            }
        }

        // mark message with tempId as failed
        function markMessageFailed(tempId) {
            const el = messagesContainer.querySelector(`[data-temp-id="${tempId}"]`);
            if (!el) return;
            el.classList.add('send-failed');
        }

        // replace temp element with server info (or update it)
        function updateTempMessageWithServer(tempId, serverMsg) {
            // try to find optimistic element
            const el = messagesContainer.querySelector(`[data-temp-id="${tempId}"]`);
            if (!el) {
                // not found -> append server message (avoid duplicates: if data-msg-id exists, skip)
                const existing = messagesContainer.querySelector(`[data-msg-id="${serverMsg.id}"]`);
                if (existing) return;
                const msg = { senderId: serverMsg.senderId, text: '(verschlüsselt)', attachments: serverMsg.attachments || [], ts: serverMsg.ts, _id: serverMsg.id };
                renderMessages([msg], { autoScroll: true });
                return;
            }
            // set server id, remove temp marker
            el.dataset.msgId = serverMsg.id;
            delete el.dataset.tempId;
            // update time
            const timeEl = el.querySelector('.message-time');
            if (timeEl) timeEl.textContent = formatTime(serverMsg.ts);
            el.classList.remove('send-failed');
        }

        window.sendMessage = sendMessage;
        sendBtn && sendBtn.addEventListener('click', (e) => { e.preventDefault(); sendMessage(); });
        messageInput && messageInput.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); } });

        // socket incoming message handler (verbesserte Dupe-Erkennung)
        socket.on('message', async (data) => {
            try {
                if (!data || !data.message) return;
                const incoming = data.message;
                const convId = data.conversationId;

                // Wenn Nachricht zur geöffneten Konversation gehört
                if (currentConversationId && convId === currentConversationId) {
                    const otherId = incoming.senderId === userId ? (currentContact && currentContact.id) || '' : incoming.senderId;
                    let text = '';
                    if (incoming.textEncrypted) {
                        try {
                            text = await tryDecryptMessage(incoming, otherId);
                        } catch (e) {
                            console.warn('decrypt on socket message failed', e);
                            text = '(verschlüsselt)';
                        }
                    }

                    // --- DUPLICATE CHECK: if clientId matches an optimistic element, update it instead of appending ---
                    const clientId = incoming.clientId || incoming.clientid || null;
                    if (clientId) {
                        const tempEl = messagesContainer.querySelector(`[data-temp-id="${clientId}"]`);
                        if (tempEl) {
                            // update existing optimistic element: set real id, update text/time
                            tempEl.dataset.msgId = incoming.id || incoming._id || '';
                            delete tempEl.dataset.tempId;
                            const txtEl = tempEl.querySelector('.message-text');
                            if (txtEl) txtEl.textContent = text || txtEl.textContent;
                            const timeEl = tempEl.querySelector('.message-time');
                            if (timeEl) timeEl.textContent = formatTime(incoming.ts || incoming.ts);
                            // mark delivered
                            tempEl.classList.remove('send-failed');
                            try { api.markRead(currentConversationId, userId).catch(() => { }); } catch (e) { }
                            loadContacts().catch(() => { });
                            return;
                        }
                    }

                    // avoid adding duplicate by msg id if it already exists
                    if (incoming.id) {
                        const exists = messagesContainer.querySelector(`[data-msg-id="${incoming.id}"]`);
                        if (exists) return;
                    }

                    // build message object similar to renderMessages expects
                    const msgObj = {
                        senderId: incoming.senderId,
                        text: text || '',
                        attachments: incoming.attachments || [],
                        ts: incoming.ts || Date.now()
                    };
                    appendMessageToDOM(msgObj);
                    try { api.markRead(currentConversationId, userId).catch(() => { }); } catch (e) { }
                    loadContacts().catch(() => { });
                    return;
                }

                // otherwise update contacts
                await loadContacts();
            } catch (e) {
                console.error('socket message handler', e);
            }
        });

        socket.on('conversation_update', (data) => { loadContacts().catch(() => { }); });
        socket.on('contacts_update', (data) => { loadContacts().catch(() => { }); });
        socket.on('connect', () => { console.log('[socket] connected', socket.id); });
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
                    window.location.href = '/login/login.html';
                    break;
                case 'AUTH_INTERNAL_ERROR':
                    alert('Interner Serverfehler bei der Socket-Anmeldung.');
                    break;
                default:
                    alert('Socket-Fehler: ' + msg);
            }
        });

        // appendMessageToDOM - erweitert um tempId support (unverändert)
        function appendMessageToDOM(m) {
            if (!messagesContainer) return;

            const container = el('div', 'message-container' + (m.senderId === userId ? ' my' : ''));
            if (m._tempId) container.dataset.tempId = m._tempId;
            if (m._id) container.dataset.msgId = m._id;

            const avatarImg = el('img', 'message-avatar');
            avatarImg.src = '/sources/avatars/avatar.png';
            const box = el('div', 'message-box' + (m.senderId === userId ? ' my' : ''));

            if (m.attachments && m.attachments.length) {
                m.attachments.forEach(att => {
                    const mf = el('div', 'message-file');
                    const fi = el('img', 'file-icon');
                    fi.src = (typeof getIconForFilename === 'function') ? getIconForFilename(att.filename) : '/sources/icons/other.png';
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

            requestAnimationFrame(() => {
                messagesContainer.scrollTop = messagesContainer.scrollHeight;
            });

            return container;
        }

        await loadContacts();
        if (contacts.length) {
            const first = contactsContainer.querySelector('.contact');
            if (first) first.click();
        }
    });
})();