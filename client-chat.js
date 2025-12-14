(() => {
    const API_BASE = window.__API_BASE__ || 'https://rhythm-flu-portal-vehicle.trycloudflare.com';
    const SOCKET_URL = window.__SOCKET_URL__ || 'https://rhythm-flu-portal-vehicle.trycloudflare.com';
    const SOCKET_IO_CDN = 'https://cdn.socket.io/4.7.1/socket.io.min.js';

    // Lade socket.io client falls nötig
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

    // Helper: API Fetch (nutzt API_BASE)
    async function apiFetch(path, opts = {}) {
        const url = API_BASE ? `${API_BASE}${path}` : path;
        const res = await fetch(url, {
            ...opts,
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json',
                ...(opts.headers || {})
            }
        });
        if (!res.ok) {
            const text = await res.text().catch(() => '');
            throw new Error(`HTTP ${res.status} ${text.slice(0, 200)}`);
        }
        const ct = res.headers.get('content-type') || '';
        return ct.includes('application/json') ? res.json() : res.text();
    }

    // API convenience (nutzt apiFetch)
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

    // DOM helpers
    function el(tag, cls) { const e = document.createElement(tag); if (cls) e.className = cls; return e; }
    function formatTime(ts) {
        if (!ts) return '';
        const d = new Date(ts);
        const now = new Date();
        if (d.toDateString() === now.toDateString()) return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        return d.toLocaleDateString();
    }

    // E2EE helpers (wie von dir)
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

    // Haupt-Init
    document.addEventListener('DOMContentLoaded', async () => {
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

        // crypto cache: peerId => { theirPubB64, aesKey (CryptoKey) }
        const cryptoCache = new Map();

        // send dedupe map
        const ongoingSends = new Map();
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

        // Ensure socket.io client loaded and connect
        try {
            await loadSocketIoClient();
        } catch (e) {
            console.warn('Could not load socket.io client from CDN, socket functionality may be unavailable', e);
        }

        const socketOptions = {
            path: '/socket.io',
            transports: ['websocket'],
            auth: { sessionToken }
        };

        let socket = null;
        try {
            // if io exists, connect
            if (typeof io !== 'undefined') {
                socket = io(SOCKET_URL, socketOptions);
            } else {
                console.warn('socket.io client not available, will use REST fallback for sends');
            }
        } catch (e) {
            console.warn('socket connect failed', e);
            socket = null;
        }

        if (!sessionToken) {
            console.warn('Kein sessionToken vorhanden, Socket.IO Auth wird null sein');
        }

        // small UI helpers to set user info
        async function fillUserInfo() {
            try {
                const me = await api.getUser(userId);
                if (me && me.user) {
                    const u = me.user;
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

        // logout
        document.querySelectorAll('#logout-btn, .logout-btn, [data-logout]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                localStorage.removeItem('user');
                window.location.href = '/chat/login/login.html';
            });
        });

        // add contact
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
        fileInput.addEventListener('change', (ev) => {
            attachedFile = ev.target.files[0] || null;
            if (attachedFile) messageInput.placeholder = 'Datei angehängt: ' + attachedFile.name; else messageInput.placeholder = 'Nachricht ...';
        });

        // emoji
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

        // Render contact with lock badge
        function renderContactItem(c) {
            const root = el('div', 'contact');
            root.id = `contact-${c.id}`;

            const avatar = el('img', 'avatar');
            avatar.src = c.avatar || '/chat/sources/avatars/avatar.png';
            root.appendChild(avatar);

            const wrapper = el('div');

            const headerRow = el('div', 'contact-header-row');

            const nameAnchor = el('a', 'contact-name');
            nameAnchor.id = 'contact-name';
            nameAnchor.textContent = c.nickname || c.username || c.id;
            headerRow.appendChild(nameAnchor);

            // lock badge (🔒 = has key, 🔓 = no key)
            const lockBadge = el('span', 'contact-lock');
            lockBadge.style.marginLeft = '8px';
            lockBadge.textContent = '…'; // loading
            headerRow.appendChild(lockBadge);

            // check publicKey async
            api.getUser(c.id).then(u => {
                if (u && u.user && u.user.publicKey) lockBadge.textContent = '🔒';
                else lockBadge.textContent = '🔓';
            }).catch(() => { lockBadge.textContent = '🔓'; });

            wrapper.appendChild(headerRow);

            const timeAnchor = el('a', 'last-msg-data');
            timeAnchor.classList.add('new');
            timeAnchor.textContent = c.lastMessageStr || '';
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

        // decryption helper (uses direct derive each time to be safe)
        async function tryDecryptMessage(msg, otherId) {
            if (!msg || !msg.textEncrypted) return '';
            try {
                const userResp = await api.getUser(otherId);
                if (!userResp || !userResp.user || !userResp.user.publicKey) return '(verschlüsselt)';
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
                const resp = await api.getContacts(userId);
                if (!resp || !resp.ok) return;
                const arr = resp.contacts || [];
                const enriched = [];
                for (const c of arr) {
                    let preview = '';
                    let lastMessageStr = '';
                    if (c.conversationId) {
                        const convResp = await api.getConversation(c.conversationId);
                        if (convResp && convResp.ok) {
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
                if (contactsContainer) {
                    contactsContainer.innerHTML = '';
                    contacts.forEach(c => contactsContainer.appendChild(renderContactItem(c)));
                }
            } catch (err) {
                console.error('loadContacts error', err);
            }
        }

        async function openConversation(contact) {
            try {
                currentContact = contact;
                if (headerName) headerName.textContent = contact.nickname || contact.username || contact.id;
                if (headerStatus) headerStatus.textContent = 'Online';

                // try precompute AES key for this contact (so next send can be encrypted)
                (async () => {
                    try {
                        const k = await getOrCreateAesKeyForPeer(contact.id);
                        if (k) {
                            // update lock badge in UI if present
                            const lockEl = document.querySelector(`#contact-${contact.id} .contact-lock`);
                            if (lockEl) lockEl.textContent = '🔒';
                        }
                    } catch (e) { /* ignore */ }
                })();

                let convId = contact.conversationId;
                if (!convId) {
                    const convs = await api.getConversationsForUser(userId);
                    if (convs && convs.ok) {
                        const found = (convs.conversations || []).find(c => (c.members || []).includes(contact.id));
                        if (found) convId = found.id;
                    }
                }
                if (!convId) {
                    currentConversationId = null;
                    if (messagesContainer) messagesContainer.innerHTML = '';
                    return;
                }
                currentConversationId = convId;

                if (socket && socket.connected) {
                    socket.emit('join_conv', currentConversationId, () => { });
                }

                const resp = await api.getConversation(convId);
                if (!resp || !resp.ok) { if (messagesContainer) messagesContainer.innerHTML = ''; return; }
                const conv = resp.conversation;

                const msgs = [];
                for (const m of conv.messages || []) {
                    const otherId = m.senderId === userId ? (conv.members.find(x => x !== userId) || '') : m.senderId;
                    let text = '';
                    if (m.unencrypted) {
                        // server flagged as unencrypted -> show plaintext
                        text = m.textEncrypted || '';
                    } else if (m.textEncrypted) {
                        const dec = await tryDecryptMessage(m, otherId);
                        text = dec || '(konnte nicht entschlüsselt werden)';
                    }
                    msgs.push({ ...m, text });
                }

                renderMessages(msgs.map(mm => ({ senderId: mm.senderId, text: mm.text, attachments: mm.attachments || [], ts: mm.ts, _id: mm.id })), { autoScroll: true });
                await api.markRead(convId, userId).catch(() => { });
                await loadContacts();
            } catch (e) {
                console.error('openConversation error', e);
            }
        }

        function renderMessages(msgs, opts = { autoScroll: false }) {
            if (!messagesContainer) return;
            messagesContainer.innerHTML = '';
            const frag = document.createDocumentFragment();

            msgs.forEach(m => {
                const container = el('div', 'message-container' + (m.senderId === userId ? ' my' : ''));
                if (m._id) container.dataset.msgId = m._id;
                if (m._tempId) container.dataset.tempId = m._tempId;

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
                if (!uresp || !uresp.user) return alert('Konnte Absender nicht finden');
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

        // NEW: getOrCreateAesKeyForPeer returns a CryptoKey or null (does not throw if peer has no key)
        async function getOrCreateAesKeyForPeer(peerId) {
            try {
                if (cryptoCache.has(peerId)) {
                    const entry = cryptoCache.get(peerId);
                    const userResp = await api.getUser(peerId);
                    const theirPubB64 = userResp && userResp.user ? (userResp.user.publicKey || '') : '';
                    if (entry.theirPubB64 === theirPubB64 && entry.aesKey) return entry.aesKey;
                }
                const userResp = await api.getUser(peerId);
                if (!userResp || !userResp.user || !userResp.user.publicKey) {
                    return null; // peer has no publicKey
                }
                const theirPubB64 = userResp.user.publicKey;
                const myJwk = localStorage.getItem('ecdh_jwk_' + userId);
                if (!myJwk) throw new Error('No local private key');
                const myPrivKey = await crypto.subtle.importKey('jwk', JSON.parse(myJwk), { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
                const theirPubKey = await E2EE.importPeerPublicKey(theirPubB64);
                const aesKey = await E2EE.deriveAESKey(myPrivKey, theirPubKey);
                const entry = { theirPubB64, aesKey };
                cryptoCache.set(peerId, entry);
                return aesKey;
            } catch (e) {
                console.warn('getOrCreateAesKeyForPeer error', e);
                return null;
            }
        }

        // SEND-LOGIC (sends unencrypted text if no peer key available; attachments only if encrypted)
        async function sendMessage() {
            const text = (messageInput.value || '').trim();
            if (!text && !attachedFile) return;

            if (!currentContact) { if (!contacts.length) return alert('Kein Kontakt ausgewählt'); currentContact = contacts[0]; }

            const sendKey = makeSendKey(currentConversationId, text, attachedFile);
            if (ongoingSends.has(sendKey)) {
                console.warn('Duplicate send suppressed for key', sendKey);
                return;
            }
            ongoingSends.set(sendKey, true);

            const tempId = `temp-${Date.now()}-${Math.floor(Math.random() * 100000)}`;

            try {
                if (!currentConversationId) {
                    const resp = await api.createConversation([userId, currentContact.id]);
                    if (!resp || !resp.ok) { ongoingSends.delete(sendKey); return alert('Konversation konnte nicht erstellt werden'); }
                    currentConversationId = resp.conversation.id;
                }

                const optimisticMsg = {
                    senderId: userId,
                    text: text || (attachedFile ? '[Datei]' : ''),
                    attachments: attachedFile ? [{ filename: attachedFile.name }] : [],
                    ts: Date.now(),
                    _tempId: tempId
                };

                appendMessageToDOM(optimisticMsg);

                // quick reset input
                messageInput.value = '';
                messageInput.placeholder = 'Nachricht ...';
                messageInput.focus();
                messageInput.dispatchEvent(new Event('input'));

                // prepare encryption
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
                    // Peer has no key -> send plaintext (server will mark unencrypted)
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
                    // do not send attachments unencrypted
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
                        if (!ack || ack.error) {
                            console.error('send_message ack error', ack && ack.error);
                            markMessageFailed(tempId);
                            ongoingSends.delete(sendKey);
                            return;
                        }
                        try { updateTempMessageWithServer(tempId, ack.message); } catch (e) { console.warn('updateTempMessageWithServer failed', e); }
                        loadContacts().catch(() => { });
                        ongoingSends.delete(sendKey);
                    });
                } else {
                    try {
                        const resp = await api.postMessage(payload);
                        if (!resp || !resp.ok) {
                            markMessageFailed(tempId);
                            ongoingSends.delete(sendKey);
                        } else {
                            updateTempMessageWithServer(tempId, resp.message || resp);
                            loadContacts().catch(() => { });
                            ongoingSends.delete(sendKey);
                        }
                    } catch (e) {
                        console.error('postMessage fallback error', e);
                        markMessageFailed(tempId);
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
                // append server message if not already present
                if (!serverMsg || !serverMsg.id) return;
                const exists = messagesContainer.querySelector(`[data-msg-id="${serverMsg.id}"]`);
                if (exists) return;
                const text = serverMsg.unencrypted ? (serverMsg.textEncrypted || '') : '(verschlüsselt)';
                const msg = { senderId: serverMsg.senderId, text, attachments: serverMsg.attachments || [], ts: serverMsg.ts, _id: serverMsg.id };
                renderMessages([msg], { autoScroll: true });
                return;
            }
            elTemp.dataset.msgId = serverMsg.id || '';
            delete elTemp.dataset.tempId;
            const timeEl = elTemp.querySelector('.message-time');
            if (timeEl) timeEl.textContent = formatTime(serverMsg.ts);
            elTemp.classList.remove('send-failed');
        }

        window.sendMessage = sendMessage;
        sendBtn && sendBtn.addEventListener('click', (e) => { e.preventDefault(); sendMessage(); });
        messageInput && messageInput.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); } });

        // socket: incoming message handler (handles unencrypted)
        if (socket) {
            socket.on('message', async (data) => {
                try {
                    if (!data || !data.message) return;
                    const incoming = data.message;
                    const convId = data.conversationId;

                    // belongs to current conversation?
                    if (currentConversationId && convId === currentConversationId) {
                        // if unencrypted, show directly
                        if (incoming.unencrypted) {
                            const clientId = incoming.clientId || incoming.clientid || null;
                            if (clientId) {
                                const tempEl = messagesContainer.querySelector(`[data-temp-id="${clientId}"]`);
                                if (tempEl) {
                                    tempEl.dataset.msgId = incoming.id || '';
                                    delete tempEl.dataset.tempId;
                                    const txtEl = tempEl.querySelector('.message-text');
                                    if (txtEl) txtEl.textContent = incoming.textEncrypted || txtEl.textContent;
                                    const timeEl = tempEl.querySelector('.message-time');
                                    if (timeEl) timeEl.textContent = formatTime(incoming.ts || Date.now());
                                    tempEl.classList.remove('send-failed');
                                    try { api.markRead(currentConversationId, userId).catch(() => { }); } catch (e) { }
                                    loadContacts().catch(() => { });
                                    return;
                                }
                            }
                            if (incoming.id) {
                                const exists = messagesContainer.querySelector(`[data-msg-id="${incoming.id}"]`);
                                if (exists) return;
                            }
                            const msgObj = { senderId: incoming.senderId, text: incoming.textEncrypted || '', attachments: incoming.attachments || [], ts: incoming.ts || Date.now() };
                            appendMessageToDOM(msgObj);
                            try { api.markRead(currentConversationId, userId).catch(() => { }); } catch (e) { }
                            loadContacts().catch(() => { });
                            return;
                        }

                        // else: encrypted flow
                        const otherId = incoming.senderId === userId ? (currentContact && currentContact.id) || '' : incoming.senderId;
                        let text = '';
                        if (incoming.textEncrypted) {
                            try { text = await tryDecryptMessage(incoming, otherId); } catch (e) { console.warn('decrypt on socket message failed', e); text = '(verschlüsselt)'; }
                        }

                        const clientId = incoming.clientId || incoming.clientid || null;
                        if (clientId) {
                            const tempEl = messagesContainer.querySelector(`[data-temp-id="${clientId}"]`);
                            if (tempEl) {
                                tempEl.dataset.msgId = incoming.id || '';
                                delete tempEl.dataset.tempId;
                                const txtEl = tempEl.querySelector('.message-text');
                                if (txtEl) txtEl.textContent = text || txtEl.textContent;
                                const timeEl = tempEl.querySelector('.message-time');
                                if (timeEl) timeEl.textContent = formatTime(incoming.ts || Date.now());
                                tempEl.classList.remove('send-failed');
                                try { api.markRead(currentConversationId, userId).catch(() => { }); } catch (e) { }
                                loadContacts().catch(() => { });
                                return;
                            }
                        }

                        if (incoming.id) {
                            const exists = messagesContainer.querySelector(`[data-msg-id="${incoming.id}"]`);
                            if (exists) return;
                        }

                        const msgObj = { senderId: incoming.senderId, text: text || '', attachments: incoming.attachments || [], ts: incoming.ts || Date.now() };
                        appendMessageToDOM(msgObj);
                        try { api.markRead(currentConversationId, userId).catch(() => { }); } catch (e) { }
                        loadContacts().catch(() => { });
                        return;
                    }

                    // otherwise refresh contacts (new messages)
                    await loadContacts();
                } catch (e) {
                    console.error('socket message handler', e);
                }
            });

            // when contacts update (e.g. someone uploaded publicKey), reload contacts and precompute AES for current contact
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

        // appendMessageToDOM (unterstützt tempId)
        function appendMessageToDOM(m) {
            if (!messagesContainer) return;
            const container = el('div', 'message-container' + (m.senderId === userId ? ' my' : ''));
            if (m._tempId) container.dataset.tempId = m._tempId;
            if (m._id) container.dataset.msgId = m._id;

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

        // initial load
        await loadContacts();
        if (contacts.length) {
            const first = contactsContainer.querySelector('.contact');
            if (first) first.click();
        }
    });
})();