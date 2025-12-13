// public/client-chat.js (überarbeitet: send-guard, contact markup, icons, pubkey upload)
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

    // base64 helpers (works on iPad/Safari for large buffers)
    function arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        const chunkSize = 0x8000; // 32KB
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

    // E2EE helpers (ECDH P-256 -> AES-GCM)
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
                console.groupCollapsed('decrypt debug');
                console.log('Error:', e && e.name ? e.name : e);
                console.log('cipherB64 len:', cipherB64 ? cipherB64.length : 'no');
                console.log('ivB64 len:', ivB64 ? ivB64.length : 'no');
                try { console.log('myJwk present?', !!localStorage.getItem('ecdh_jwk_' + userId)); } catch (_) { }
                try { console.log('peerPub preview:', (window._lastPeerPubB64 || '').slice(0, 40) + '...'); } catch (_) { }
                console.groupEnd();
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
        // load user
        const raw = localStorage.getItem('user');
        const user = raw ? JSON.parse(raw) : null;
        if (!user || !user.id) {
            window.location.href = '/login/login.html';
            return;
        }
        const userId = user.id;
        // ensure keypair exists (will also attempt to upload)
        await E2EE.ensureKeypair(userId);

        const sessionToken = (user && user.sessionToken) ? user.sessionToken : (localStorage.getItem('user') ? JSON.parse(localStorage.getItem('user')).sessionToken : null);

        // create socket
        const socket = io({ auth: { sessionToken } });

        // handle incoming message for this user
        socket.on('message', async (data) => {
            try {
                // data: { conversationId, message }
                if (!data || !data.message) return;

                const incoming = data.message;
                const convId = data.conversationId;

                // immer contacts neu laden (unread/preview aktualisieren)
                // falls du das zu häufig findest, kannst du das nur ausführen, wenn conv nicht offen ist
                // await loadContacts();

                // 1) Wenn die eingehende Nachricht zur aktuell geöffneten Konversation gehört:
                if (currentConversationId && convId === currentConversationId) {
                    // Versuche Nachricht zu entschlüsseln
                    const otherId = incoming.senderId === userId ? (/* sender is me */ (currentContact && currentContact.id) || '') : incoming.senderId;
                    let text = '';
                    if (incoming.textEncrypted) {
                        try {
                            text = await tryDecryptMessage(incoming, otherId);
                        } catch (e) {
                            console.warn('decrypt on socket message failed', e);
                            text = '(verschlüsselt)';
                        }
                    }
                    // build message object like renderMessages expects
                    const msgObj = {
                        senderId: incoming.senderId,
                        text: text || '',
                        attachments: incoming.attachments || [],
                        ts: incoming.ts || Date.now()
                    };

                    // append to DOM (neuen Node erstellen)
                    appendMessageToDOM(msgObj);

                    // mark as read on server (optional)
                    try { await api.markRead(currentConversationId, userId); } catch (e) { /* ignore */ }

                    // update contacts preview/unread quickly
                    loadContacts().catch(() => { });
                    return;
                }

                // 2) Wenn andere Konversation -> update contacts (unread + preview)
                // (do not open conversation automatically)
                await loadContacts();
            } catch (e) {
                console.error('socket message handler', e);
            }
        });

        // conv room updates
        socket.on('conversation_update', (data) => {
            // if needed, update UI (last message preview)
            loadContacts().catch(() => { });
        });

        // contacts update
        socket.on('contacts_update', (data) => {
            loadContacts().catch(() => { });
        });

        // on connect
        socket.on('connect', () => {
            console.log('[socket] connected', socket.id);
        });
        socket.on('disconnect', (reason) => {
            console.log('[socket] disconnected', reason);
        });

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
        let isSending = false; // guard to prevent double-send

        // setText helper (fills many selectors)
        function setText(selectors, text) {
            selectors.forEach(sel => {
                document.querySelectorAll(sel).forEach(el => {
                    if (el) el.textContent = text;
                });
            });
        }
        // fill profile data from server
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

        // Logout buttons
        document.querySelectorAll('#logout-btn, .logout-btn, [data-logout]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                localStorage.removeItem('user');
                window.location.href = '/login/login.html';
            });
        });

        // add contact
        addBtn && addBtn.addEventListener('click', async () => {
            const name = prompt('Benutzername der Person eingeben:');
            if (!name) return;
            try {
                // ensure our keys & publicKey uploaded before adding contact
                await E2EE.ensureKeypair(userId);
                const resp = await api.addContact(userId, name.trim());
                if (resp.ok) {
                    // try to fetch the new contact to check publicKey (informational)
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

        // emoji picker
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

        // choose icon for filename
        function getIconForFilename(name) {
            if (!name) return '/sources/icons/other.png';
            const ext = (name.split('.').pop() || '').toLowerCase();
            if (['xls', 'xlsx', 'csv'].includes(ext)) return '/sources/icons/excel.png';
            if (['doc', 'docx'].includes(ext)) return '/sources/icons/word.png';
            if (ext === 'pdf') return '/sources/icons/pdf.png';
            if (['ppt', 'pptx'].includes(ext)) return '/sources/icons/powerpoint.png';
            return '/sources/icons/other.png';
        }

        // render contact item EXACTLY like your markup (classes preserved)
        function renderContactItem(c) {
            // helper el(tag, className) sollte bereits existieren; sonst:
            // function el(tag, cls) { const e = document.createElement(tag); if (cls) e.className = cls; return e; }

            const root = el('div', 'contact');
            root.id = `contact-${c.id}`;

            const avatar = el('img', 'avatar');
            avatar.src = c.avatar || '/sources/avatars/avatar.png';
            root.appendChild(avatar);

            const wrapper = el('div');

            // contact-name (with optional verified SVG)
            const nameAnchor = el('a', 'contact-name');
            nameAnchor.id = 'contact-name';
            nameAnchor.textContent = c.nickname || c.username || c.id;

            if (c.verified && String(c.verified).toLowerCase() === 'yes') {
                const svgHTML = `
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 -960 960 960" fill="#000000">
                        <path d="m344-60-76-128-144-32 14-148-98-112 98-112-14-148 144-32 76-128 136 58 136-58 76 128 144 32-14 148 98 112-98 112 14 148-144 32-76 128-136-58-136 58Zm94-278 226-226-56-58-170 170-86-84-56 56 142 142Z"/>
                    </svg>
                `;

                nameAnchor.insertAdjacentHTML('beforeend', svgHTML);
            }

            // last message time (separate anchor, like in your desired layout)
            const timeAnchor = el('a', 'last-msg-data');
            timeAnchor.classList.add('new'); // beibehalten wie im Beispiel
            timeAnchor.textContent = c.lastMessageStr || '';
            // append name and time similar placement as in your example
            wrapper.appendChild(nameAnchor);
            wrapper.appendChild(timeAnchor);

            // activity / preview
            const activity = el('a', 'contact-activity');
            activity.id = 'contact-activity';
            activity.textContent = c.preview || '';
            wrapper.appendChild(activity);

            // new message count
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

            // click handler: mark active + open conversation
            root.addEventListener('click', async () => {
                document.querySelectorAll('.contacts .contact').forEach(el => el.classList.remove('active'));
                root.classList.add('active');
                if (typeof openConversation === 'function') {
                    // openConversation ist in deinem client code definiert — rufe es auf
                    try { await openConversation(c); } catch (e) { console.error('openConversation error', e); }
                } else if (typeof window.openConversation === 'function') {
                    try { await window.openConversation(c); } catch (e) { console.error('openConversation error', e); }
                }
            });

            return root;
        }

        // unified tryDecryptMessage (single place)
        async function tryDecryptMessage(msg, otherId) {
            if (!msg || !msg.textEncrypted) return '';
            try {
                const userResp = await api.getUser(otherId);
                if (!userResp.ok || !userResp.user.publicKey) return '(verschlüsselt)';
                const theirPub = await E2EE.importPeerPublicKey(userResp.user.publicKey);
                const myJwk = localStorage.getItem('ecdh_jwk_' + userId);
                if (!myJwk) {
                    console.warn('tryDecryptMessage: my private jwk not found for user', userId);
                    return '(verschlüsselt)';
                }
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
                                if (dec) {
                                    preview = (last.senderId === userId ? 'Du: ' : '') + dec;
                                    lastMessageStr = formatTime(last.ts);
                                } else {
                                    preview = '(verschlüsselt)';
                                    lastMessageStr = formatTime(last.ts);
                                }
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

                // entschluesseln / aufbereiten wie zuvor (erstelle msgs array in aufsteigender Reihenfolge)
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

                // rendern und beim Oeffnen immer ans Ende scrollen (autoScroll = true)
                renderMessages(msgs.map(mm => ({ senderId: mm.senderId, text: mm.text, attachments: mm.attachments || [], ts: mm.ts })), { autoScroll: true });

                // mark as read
                await api.markRead(convId, userId);
                await loadContacts();
            } catch (e) {
                console.error('openConversation error', e);
            }
        }

        function renderMessages(msgs, opts = { autoScroll: false }) {
            // msgs: array in aufsteigender Reihenfolge (älteste -> neueste)
            // opts.autoScroll: true = immer ans Ende scrollen

            messagesContainer.innerHTML = '';

            // Ein Hilfs-Fragment für performance
            const frag = document.createDocumentFragment();

            msgs.forEach(m => {
                // container
                const container = el('div', 'message-container' + (m.senderId === userId ? ' my' : ''));
                const avatarImg = el('img', 'message-avatar');
                avatarImg.src = '/sources/avatars/avatar.png';

                // box
                const box = el('div', 'message-box' + (m.senderId === userId ? ' my' : ''));

                // 1) Anhänge zuerst (falls vorhanden)
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

                // 2) Begleittext unter den Dateien (falls vorhanden)
                if (m.text && String(m.text).trim().length) {
                    const textNode = el('div', 'message-text');
                    textNode.textContent = m.text;
                    if (m.attachments && m.attachments.length) textNode.style.marginTop = '6px';
                    box.appendChild(textNode);
                }

                // 3) Zeit ganz unten
                const time = el('a', 'message-time');
                time.textContent = formatTime(m.ts);
                time.style.display = 'block';
                time.style.marginTop = '6px';
                time.style.fontSize = '11px';
                time.style.color = '#666';
                box.appendChild(time);

                // Anordnung Avatar / Box
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

            // Scroll-Handling:
            // - Wenn opts.autoScroll === true -> immer an Ende scrollen
            // - Wenn opts.autoScroll === false -> nur scrollen, wenn User vorher bereits nahe am Ende war
            const threshold = 80; // px
            const nearBottom = (messagesContainer.scrollHeight - messagesContainer.scrollTop - messagesContainer.clientHeight) < threshold;

            if (opts.autoScroll || nearBottom) {
                // kleine Verzögerung sicherstellt, dass Browser Elementgrösse berechnet hat
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

        async function sendMessage() {
            if (isSending) return; // prevent double-send
            const text = messageInput.value.trim();
            if (!text && !attachedFile) return;

            if (!currentContact) { if (!contacts.length) return alert('Keine Kontakt ausgewählt'); currentContact = contacts[0]; }

            isSending = true;
            if (sendBtn) sendBtn.disabled = true;

            try {
                if (!currentConversationId) {
                    const resp = await api.createConversation([userId, currentContact.id]);
                    if (!resp.ok) return alert('Konversation konnte nicht erstellt werden');
                    currentConversationId = resp.conversation.id;
                }

                // peer public key
                const peerResp = await api.getUser(currentContact.id);
                if (!peerResp.ok) return alert('Peer nicht gefunden');
                const theirPubB64 = peerResp.user.publicKey;
                if (!theirPubB64) return alert('Peer hat keinen publicKey');

                const theirPub = await E2EE.importPeerPublicKey(theirPubB64);
                const myPriv = await crypto.subtle.importKey('jwk', JSON.parse(localStorage.getItem('ecdh_jwk_' + userId)), { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
                const aesKey = await E2EE.deriveAESKey(myPriv, theirPub);

                let textEncrypted = '';
                let textIv = '';
                if (text) {
                    const enc = await E2EE.encryptWithKey(aesKey, text);
                    textEncrypted = enc.cipherB64; textIv = enc.ivB64;
                }

                const attachments = [];
                if (attachedFile) {
                    const ab = await attachedFile.arrayBuffer();
                    const enc = await E2EE.encryptBuffer(aesKey, ab);
                    attachments.push({ filename: attachedFile.name, mime: attachedFile.type || 'application/octet-stream', cipher: enc.cipherB64, iv: enc.ivB64 });
                }

                const post = await api.postMessage({ conversationId: currentConversationId, from: userId, to: currentContact.id, textEncrypted, iv: textIv, attachments });
                if (!post.ok) return alert('Senden fehlgeschlagen');

                // reload conv
                await openConversation(currentContact);

                // reset
                attachedFile = null; fileInput.value = ''; messageInput.value = ''; messageInput.placeholder = 'Nachricht ...';
                messageInput.dispatchEvent(new Event('input'));
                await loadContacts();
            } catch (e) {
                console.error('sendMessage error', e);
                alert('Fehler beim Senden');
            } finally {
                isSending = false;
                if (sendBtn) sendBtn.disabled = false;
            }
        }

        window.sendMessage = sendMessage;

        sendBtn && sendBtn.addEventListener('click', (e) => { e.preventDefault(); sendMessage(); });
        messageInput && messageInput.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); } });

        await loadContacts();
        if (contacts.length) {
            const first = contactsContainer.querySelector('.contact');
            if (first) first.click();
        }

        socket.on('connect_error', (err) => {
            console.error('[socket] connect_error:', err.message);

            switch (err.message) {
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
                    alert('Socket-Fehler: ' + err.message);
            }
        });

        function appendMessageToDOM(m) {
            if (!messagesContainer) return;

            const container = el('div', 'message-container' + (m.senderId === userId ? ' my' : ''));
            const avatarImg = el('img', 'message-avatar');
            avatarImg.src = '/sources/avatars/avatar.png';

            const box = el('div', 'message-box' + (m.senderId === userId ? ' my' : ''));

            // Anhänge zuerst
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

            // Text unter Dateien
            if (m.text && String(m.text).trim().length) {
                const textNode = el('div', 'message-text');
                textNode.textContent = m.text;
                if (m.attachments && m.attachments.length) textNode.style.marginTop = '6px';
                box.appendChild(textNode);
            }

            // Zeit
            const time = el('a', 'message-time');
            time.textContent = formatTime(m.ts);
            time.style.display = 'block';
            time.style.marginTop = '6px';
            time.style.fontSize = '11px';
            time.style.color = '#666';
            box.appendChild(time);

            // Anordnung Avatar / Box
            if (m.senderId === userId) {
                container.appendChild(box);
                container.appendChild(avatarImg);
            } else {
                container.appendChild(avatarImg);
                container.appendChild(box);
            }

            messagesContainer.appendChild(container);

            // scroll to bottom
            requestAnimationFrame(() => {
                messagesContainer.scrollTop = messagesContainer.scrollHeight;
            });
        }
    });
})();