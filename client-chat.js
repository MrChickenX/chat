(() => {
    const API_BASE = window.__API_BASE__ || "https://variety-latitude-cooperative-symbols.trycloudflare.com";
    const SOCKET_URL = window.__SOCKET_URL__ || "https://variety-latitude-cooperative-symbols.trycloudflare.com";
    const SOCKET_IO_CDN = "https://cdn.socket.io/4.7.1/socket.io.min.js";

    let socket = null;

    /* -------------------------
       Utilities
       ------------------------- */
    const safeParse = (s) => {
        try {
            return JSON.parse(s);
        } catch {
            return null;
        }
    };
    const el = (tag, cls) => {
        const e = document.createElement(tag);
        if (cls) e.className = cls;
        return e;
    };
    const $all = (sel) => Array.from(document.querySelectorAll(sel));

    function formatTime(ts) {
        if (!ts) return "";
        const d = new Date(ts);
        const now = new Date();
        if (d.toDateString() === now.toDateString())
            return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
        return d.toLocaleDateString();
    }

    function verifiedSvgHtml() {
        return (
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 -960 960 960" width="16" height="16">' +
            '<path d="m344-60-76-128-144-32 14-148-98-112 98-112-14-148 144-32 76-128 136 58 136-58 76 128 144 32-14 148 98 112-98 112 14 148-144 32-76 128-136-58-136 58Zm94-278 226-226-56-58-170 170-86-84-56 56 142 142Z"/>' +
            "</svg>"
        );
    }

    // base64 <-> ArrayBuffer helpers
    function arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        const chunkSize = 0x8000;
        let binary = "";
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

    /* -------------------------
       Load socket.io client (CDN fallback)
       ------------------------- */
    function loadSocketIoClient() {
        return new Promise((resolve, reject) => {
            if (typeof io !== "undefined") return resolve();
            const s = document.createElement("script");
            s.src = SOCKET_IO_CDN;
            s.onload = () => resolve();
            s.onerror = () => reject(new Error("socket.io client load failed"));
            document.head.appendChild(s);
        });
    }

    /* -------------------------
       Small API wrapper
       ------------------------- */
    async function apiFetch(path, opts = {}) {
        const url = API_BASE ? `${API_BASE}${path}` : path;
        try {
            const res = await fetch(url, {
                ...opts,
                credentials: "include",
                headers: {
                    "Content-Type": "application/json",
                    ...(opts.headers || {}),
                },
            });
            const text = await res.text().catch(() => "");
            const ct = res.headers.get("content-type") || "";
            let parsed = text;
            if (ct.includes("application/json")) {
                try {
                    parsed = JSON.parse(text);
                } catch {
                    parsed = text;
                }
            }
            if (!res.ok) {
                return {
                    ok: false,
                    status: res.status,
                    body: parsed,
                    error:
                        typeof parsed === "string"
                            ? parsed
                            : (parsed && parsed.error) || "HTTP error",
                };
            }
            return { ok: true, status: res.status, body: parsed };
        } catch (err) {
            return { ok: false, status: 0, body: null, error: err?.message || "Network error" };
        }
    }

    const api = {
        getContacts: (userId) => apiFetch(`/contacts?userId=${encodeURIComponent(userId)}`),
        getConversation: (convId) => apiFetch(`/conversation/${encodeURIComponent(convId)}`),
        getConversationsForUser: (userId) =>
            apiFetch(`/conversations?userId=${encodeURIComponent(userId)}`),
        createConversation: (members) => apiFetch("/conversation", { method: "POST", body: JSON.stringify({ members }) }),
        postMessage: (payload) => apiFetch("/message", { method: "POST", body: JSON.stringify(payload) }),
        markRead: (convId, userId) =>
            apiFetch(`/conversation/${encodeURIComponent(convId)}/read`, { method: "PATCH", body: JSON.stringify({ userId }) }),
        getUser: (id) => apiFetch(`/user/${encodeURIComponent(id)}`),
        setPublicKey: (id, publicKeyBase64) =>
            apiFetch(`/user/${encodeURIComponent(id)}/publicKey`, { method: "POST", body: JSON.stringify({ publicKey: publicKeyBase64 }) }),
        addContact: (id, contactUsername) =>
            apiFetch(`/user/${encodeURIComponent(id)}/contacts`, { method: "POST", body: JSON.stringify({ contactUsername }) }),
    };

    /* -------------------------
       E2EE helpers
       ------------------------- */
    const E2EE = {
        async ensureKeypair(userId) {
            // try to reuse existing keys
            const storedPriv = localStorage.getItem("ecdh_jwk_" + userId);
            const storedPub = localStorage.getItem("ecdh_pub_" + userId);
            if (storedPriv && storedPub) {
                try {
                    const jwk = JSON.parse(storedPriv);
                    const priv = await crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
                    // best-effort announce via REST (socket announce removed to avoid referencing undefined socket)
                    try { await api.setPublicKey(userId, storedPub); } catch (_) { /* ignore */ }
                    return { privateKey: priv, publicBase64: storedPub };
                } catch (e) {
                    console.warn("ensureKeypair import failed, regenerating keys", e);
                    // fallthrough to generate new keys
                }
            }

            // generate new keypair
            const kp = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
            const pubRaw = await crypto.subtle.exportKey("raw", kp.publicKey);
            const pubB64 = arrayBufferToBase64(pubRaw);
            const privJwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
            localStorage.setItem("ecdh_pub_" + userId, pubB64);
            localStorage.setItem("ecdh_jwk_" + userId, JSON.stringify(privJwk));
            try { await api.setPublicKey(userId, pubB64); } catch (e) { console.warn("setPublicKey failed", e); }
            const priv = await crypto.subtle.importKey("jwk", privJwk, { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
            return { privateKey: priv, publicBase64: pubB64 };
        },

        async importPeerPublicKey(base64) {
            const raw = base64ToArrayBuffer(base64);
            return crypto.subtle.importKey("raw", raw, { name: "ECDH", namedCurve: "P-256" }, true, []);
        },

        async deriveAESKey(myPrivKey, theirPubKey) {
            const bits = await crypto.subtle.deriveBits({ name: "ECDH", public: theirPubKey }, myPrivKey, 256);
            return crypto.subtle.importKey("raw", bits, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
        },

        async encryptWithKey(aesKey, plaintext) {
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const enc = new TextEncoder().encode(plaintext);
            const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, enc);
            return { cipherB64: arrayBufferToBase64(cipher), ivB64: arrayBufferToBase64(iv) };
        },

        async decryptWithKey(aesKey, cipherB64, ivB64) {
            try {
                if (!cipherB64 || !ivB64) return null;
                const cipher = base64ToArrayBuffer(cipherB64);
                const ivArr = new Uint8Array(base64ToArrayBuffer(ivB64));
                const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: ivArr }, aesKey, cipher);
                return new TextDecoder().decode(plain);
            } catch (e) {
                console.warn("decrypt error", e);
                return null;
            }
        },

        async encryptBuffer(aesKey, buffer) {
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, buffer);
            return { cipherB64: arrayBufferToBase64(cipher), ivB64: arrayBufferToBase64(iv) };
        },

        async decryptBuffer(aesKey, cipherB64, ivB64) {
            try {
                if (!cipherB64 || !ivB64) return null;
                const cipher = base64ToArrayBuffer(cipherB64);
                const iv = new Uint8Array(base64ToArrayBuffer(ivB64));
                const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, cipher);
                return plain;
            } catch (e) {
                console.warn("decryptBuffer error", e);
                return null;
            }
        },
    };

    /* -------------------------
       DOM ready
       ------------------------- */
    document.addEventListener("DOMContentLoaded", async () => {
        // DOM elements (may be missing in some pages)
        const contactsContainer = document.querySelector(".contacts");
        const messagesContainer = document.querySelector("main.chat-messages") || document.querySelector(".chat-messages");
        const headerName = document.querySelector(".current-contact-name");
        const headerStatus = document.querySelector(".current-contact-status");
        const messageInput = document.getElementById("message-input");
        const sendBtn = document.getElementById("send-btn");
        const addBtn = document.getElementById("add-btn");
        const attachBtn = document.getElementById("attach-btn");
        const emojiBtn = document.getElementById("emoji-btn");

        let contacts = [];
        let currentConversationId = null;
        let currentContact = null;
        let attachedFile = null;

        // crypto cache: peerId => { theirPubB64, aesKey }
        const cryptoCache = new Map();
        const processedMessageIds = new Set();

        // send dedupe utilities
        const ongoingSends = new Map();
        const sendLock = new Set();
        let sendCooldown = false;
        const lastSendTimes = new Map();

        function makeSendKey(convId, text, file) {
            const t = String(text || "").trim();
            const fname = file && file.name ? file.name : "";
            return `${convId || "nocv"}|${t}|${fname}`;
        }

        // load local user once
        const localUserRaw = localStorage.getItem("user");
        const user = localUserRaw ? safeParse(localUserRaw) : null;
        if (!user || !user.id) {
            window.location.href = "/chat/login/login.html";
            return;
        }
        const userId = user.id;

        // ensure keypair present
        try {
            await E2EE.ensureKeypair(userId);
        } catch (e) {
            console.warn("ensureKeypair error", e);
        }

        const sessionToken = user.sessionToken || null;

        // try to load socket.io client (best-effort)
        try {
            await loadSocketIoClient();
        } catch (e) {
            console.warn("Could not load socket.io client from CDN", e);
        }

        // create socket (if io available)
        try {
            if (typeof io !== "undefined") {
                const socketOptions = { path: "/socket.io", transports: ["websocket"], auth: { sessionToken } };
                socket = io(SOCKET_URL, socketOptions);
            } else {
                console.warn("socket.io client not available");
            }
        } catch (e) {
            console.warn("socket connect failed", e);
            socket = null;
        }

        /* -------------------------
           UI helpers
           ------------------------- */
        async function fillUserInfo() {
            try {
                const me = await api.getUser(userId);
                if (me?.ok && me.body?.user) {
                    const u = me.body.user;
                    ["#username-display", ".username-display", "[data-username]"].forEach((sel) =>
                        $all(sel).forEach((el) => el && (el.textContent = u.username || ""))
                    );
                    ["#nickname-display", ".nickname-display", "[data-nickname]"].forEach((sel) =>
                        $all(sel).forEach((el) => el && (el.textContent = u.nickname || u.username || ""))
                    );
                    ["#user-id", "[data-userid]"].forEach((sel) =>
                        $all(sel).forEach((el) => el && (el.textContent = u.id || ""))
                    );
                    ["#user-verified", "[data-verified]"].forEach((sel) =>
                        $all(sel).forEach((el) => el && (el.textContent = u.verified || ""))
                    );
                    if (u.avatar) {
                        $all(".avatar, .user-avatar, [data-avatar]").forEach((img) => {
                            if (!img) return;
                            if (img.tagName && img.tagName.toLowerCase() === "img") img.src = u.avatar;
                            else img.style.backgroundImage = `url(${u.avatar})`;
                        });
                    }
                }
            } catch {
                /* ignore */
            }
        }
        fillUserInfo();

        // logout handlers
        $all("#logout-btn, .logout-btn, [data-logout]").forEach((btn) =>
            btn.addEventListener("click", (e) => {
                e.preventDefault();
                localStorage.removeItem("user");
                window.location.href = "/chat/login/login.html";
            })
        );

        // add contact
        if (addBtn) {
            addBtn.addEventListener("click", async () => {
                const name = prompt("Benutzername der Person eingeben:");
                if (!name) return;
                try {
                    await E2EE.ensureKeypair(userId);
                    const resp = await api.addContact(userId, name.trim());
                    if (!resp?.ok) {
                        alert("Kontakt konnte nicht hinzugefügt werden: " + (resp?.error || "Fehler"));
                        return;
                    }
                    const contactId = resp.body.contactId;
                    const peerResp = await api.getUser(contactId);
                    if (peerResp?.ok && peerResp.body?.user?.publicKey) {
                        alert("Kontakt erfolgreich hinzugefügt");
                    } else {
                        alert(
                            "Kontakt hinzugefügt. Hinweis: Der Kontakt hat noch keinen Public Key hochgeladen, verschlüsselte Nachrichten sind erst möglich, wenn der Kontakt sich eingeloggt hat."
                        );
                    }
                    await loadContacts();
                } catch (err) {
                    console.error("addContact error", err);
                    alert("Netzwerkfehler");
                }
            });
        }

        // file attach helpers
        const fileInput = el("input");
        fileInput.type = "file";
        fileInput.style.display = "none";
        document.body.appendChild(fileInput);
        if (attachBtn) attachBtn.addEventListener("click", () => fileInput.click());
        // Check file size after file selection (max 50MB)
        fileInput.addEventListener("change", (ev) => {
            attachedFile = ev.target.files[0] || null;
            if (attachedFile && attachedFile.size > 50 * 1024 * 1024) { // 50MB in bytes
                alert("Datei ist zu gross. Maximale Dateigroesse ist 50MB.");
                attachedFile = null;
                fileInput.value = "";
            }
            if (messageInput) {
                messageInput.placeholder = attachedFile ? "Datei angehaengt: " + attachedFile.name : "Nachricht ...";
            }
        });

        // emoji picker
        function createEmojiPicker() {
            const emojis = ["😀", "😁", "😂", "😉", "😊", "😍", "😎", "😢", "👍", "🙏", "🔥", "🎉", "❤️"];
            const box = el("div", "emoji-picker");
            emojis.forEach((em) => {
                const b = el("button");
                b.type = "button";
                b.textContent = em;
                b.style.fontSize = "16px";
                b.addEventListener("click", () => {
                    if (!messageInput) return;
                    const start = messageInput.selectionStart || 0;
                    const end = messageInput.selectionEnd || 0;
                    messageInput.value = messageInput.value.slice(0, start) + em + messageInput.value.slice(end);
                    messageInput.focus();
                    messageInput.selectionStart = messageInput.selectionEnd = start + em.length;
                    messageInput.dispatchEvent(new Event("input"));
                    box.remove();
                });
                box.appendChild(b);
            });
            return box;
        }
        if (emojiBtn) {
            emojiBtn.addEventListener("click", () => {
                const existing = document.querySelector(".emoji-picker");
                if (existing) {
                    existing.remove();
                    return;
                }
                document.body.appendChild(createEmojiPicker());
            });
        }

        // icon helper
        function getIconForFilename(name) {
            if (!name) return "/chat/sources/icons/other.png";
            const ext = (name.split(".").pop() || "").toLowerCase();
            if (["xls", "xlsx", "csv"].includes(ext)) return "/chat/sources/icons/excel.png";
            if (["doc", "docx"].includes(ext)) return "/chat/sources/icons/word.png";
            if (ext === "pdf") return "/chat/sources/icons/pdf.png";
            if (["ppt", "pptx"].includes(ext)) return "/chat/sources/icons/powerpoint.png";
            return "/chat/sources/icons/other.png";
        }

        // render contact entry
        function renderContactItem(c) {
            const root = el("div", "contact");
            root.id = `contact-${c.id}`;

            const avatar = el("img", "avatar");
            avatar.src = c.avatar || "/chat/sources/avatars/avatar.png";
            root.appendChild(avatar);

            const wrapper = el("div");

            const nameAnchor = el("a", "contact-name");
            if (c.verified === "yes") {
                nameAnchor.innerHTML = `${c.nickname || c.username || c.id} ${verifiedSvgHtml()}`;
            } else {
                nameAnchor.textContent = c.nickname || c.username || c.id;
            }
            wrapper.appendChild(nameAnchor);

            const timeAnchor = el("a", "last-msg-data");
            timeAnchor.classList.add("new");
            timeAnchor.textContent = c.lastMessageStr || "";
            wrapper.appendChild(timeAnchor);

            const activity = el("a", "contact-activity");
            activity.textContent = c.preview || "";
            wrapper.appendChild(activity);

            const unread = el("a", "new-msg-count");
            if (c.unread && c.unread > 0) {
                unread.classList.add("new");
                unread.textContent = String(c.unread);
            } else {
                unread.textContent = "";
            }
            wrapper.appendChild(unread);

            root.appendChild(wrapper);

            root.addEventListener("click", async () => {
                $all(".contacts .contact").forEach((elm) => elm.classList.remove("active"));
                root.classList.add("active");
                try {
                    await openConversation(c);
                } catch (e) {
                    console.error("openConversation error", e);
                }
            });

            return root;
        }

        /* -------------------------
           Decryption helpers
           ------------------------- */
        function pickIvFromMessage(msg) {
            if (!msg) return null;
            const candidates = [msg.iv, msg.ivB64, msg.ivBase64, msg?.meta?.iv];
            for (const c of candidates) {
                if (c && String(c).trim()) return String(c);
            }
            return null;
        }

        async function decryptTextForDisplay(msg, otherId) {
            if (!msg) return null;
            if (msg.unencrypted) return msg.textEncrypted || "";
            const iv = pickIvFromMessage(msg);
            if (!msg.textEncrypted && !msg.attachments) return "";
            if (!iv) return msg.textEncrypted || "";

            try {
                let entry = cryptoCache.get(otherId);
                if (!entry || !entry.aesKey) {
                    const aes = await getOrCreateAesKeyForPeer(otherId);
                    if (!aes) return "(verschluesselt)";
                    entry = cryptoCache.get(otherId) || { aesKey: aes };
                    cryptoCache.set(otherId, entry);
                }
                const dec = await E2EE.decryptWithKey(entry.aesKey, msg.textEncrypted, iv);
                return dec || "(konnte nicht entschluesselt werden)";
            } catch (e) {
                console.warn("decryptTextForDisplay failed", e);
                return "(verschluesselt)";
            }
        }

        async function tryDecryptMessage(msg, otherId) {
            if (!msg) return "";
            try {
                const t = await decryptTextForDisplay(msg, otherId);
                return t || "(verschluesselt)";
            } catch (e) {
                console.warn("tryDecryptMessage failed", e);
                return "(verschluesselt)";
            }
        }

        /* -------------------------
           Contacts + conversations
           ------------------------- */
        async function loadContacts() {
            try {
                const resp = await api.getContacts(userId);
                if (!resp?.ok) {
                    console.warn("getContacts failed", resp?.error);
                    return;
                }
                const arr = resp.body?.contacts || [];
                const enriched = [];

                for (const c of arr) {
                    let preview = "";
                    let lastMessageStr = "";

                    if (c.lastMessageMeta) {
                        const last = c.lastMessageMeta;
                        lastMessageStr = formatTime(last.ts);
                        const ivPresent = !!last.iv;
                        if (!ivPresent) {
                            preview = last.textEncrypted || "";
                        } else {
                            if (c.conversationId) {
                                try {
                                    const convResp = await api.getConversation(c.conversationId);
                                    if (convResp?.ok && convResp.body?.conversation) {
                                        const conv = convResp.body.conversation;
                                        const msgs = conv.messages || [];
                                        const maxCheck = 99;
                                        for (let i = msgs.length - 1; i >= 0 && i >= msgs.length - maxCheck; i--) {
                                            const m = msgs[i];
                                            if (m.unencrypted) {
                                                const txt = m.textEncrypted || "";
                                                preview = (m.senderId === userId ? "Du: " : "") + txt;
                                                break;
                                            }
                                            if (m.textEncrypted) {
                                                const otherId = m.senderId === userId ? (conv.members.find((x) => x !== userId) || "") : m.senderId;
                                                const dec = await tryDecryptMessage(m, otherId);
                                                if (dec && dec !== "(verschluesselt)") {
                                                    preview = (m.senderId === userId ? "Du: " : "") + dec;
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                } catch (e) {
                                    console.warn("Failed to fetch/scan conversation for preview", e);
                                }
                            }
                            if (!preview) preview = "(verschluesselt)";
                        }
                    }

                    enriched.push({ ...c, preview, lastMessageStr, nickname: c.nickname || c.username });
                }

                contacts = enriched;
                if (contactsContainer) {
                    contactsContainer.innerHTML = "";
                    contacts.forEach((c) => contactsContainer.appendChild(renderContactItem(c)));
                }
            } catch (err) {
                console.error("loadContacts error", err);
            }
        }

        async function getOrCreateAesKeyForPeer(peerId) {
            try {
                if (cryptoCache.has(peerId)) {
                    const entry = cryptoCache.get(peerId);
                    if (entry?.aesKey) return entry.aesKey;
                }

                const userResp = await api.getUser(peerId);
                if (!userResp?.ok || !userResp.body?.user) {
                    return null;
                }
                const peer = userResp.body.user;
                const theirPubB64 = peer.publicKey || "";
                if (!theirPubB64) return null;

                let myJwk = localStorage.getItem("ecdh_jwk_" + userId);
                if (!myJwk) {
                    await E2EE.ensureKeypair(userId);
                    myJwk = localStorage.getItem("ecdh_jwk_" + userId);
                }
                if (!myJwk) {
                    console.warn("Local private key missing after ensureKeypair; cannot derive AES key");
                    return null;
                }

                const myPrivKey = await crypto.subtle.importKey("jwk", JSON.parse(myJwk), { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
                const theirPubKey = await E2EE.importPeerPublicKey(theirPubB64);
                const aesKey = await E2EE.deriveAESKey(myPrivKey, theirPubKey);
                cryptoCache.set(peerId, { theirPubB64, aesKey });
                return aesKey;
            } catch (e) {
                console.warn("getOrCreateAesKeyForPeer error (returning null):", e);
                return null;
            }
        }

        /* -------------------------
           Conversation rendering
           ------------------------- */
        async function openConversation(contact) {
            try {
                currentContact = contact;
                if (headerName) {
                    if (contact.verified === "yes") headerName.innerHTML = `${contact.nickname || contact.username || contact.id} ${verifiedSvgHtml()}`;
                    else headerName.textContent = contact.nickname || contact.username || contact.id;
                }
                if (headerStatus) headerStatus.textContent = "Online";

                try {
                    const k = await getOrCreateAesKeyForPeer(contact.id);
                    if (k) {
                        const lockEl = document.querySelector(`#contact-${contact.id} .contact-lock`);
                        if (lockEl) lockEl.textContent = "🔒";
                    }
                } catch { }

                let convId = contact.conversationId;
                if (!convId) {
                    const convsResp = await api.getConversationsForUser(userId);
                    if (convsResp?.ok && convsResp.body?.conversations) {
                        const found = (convsResp.body.conversations || []).find((c) => (c.members || []).includes(contact.id));
                        if (found) convId = found.id;
                    }
                }
                if (!convId) {
                    currentConversationId = null;
                    if (messagesContainer) messagesContainer.innerHTML = "";
                    return;
                }
                currentConversationId = convId;

                if (socket?.connected) {
                    try { socket.emit("join_conv", currentConversationId, () => { }); } catch { }
                }

                const resp = await api.getConversation(convId);
                if (!resp?.ok || !resp.body?.conversation) {
                    if (messagesContainer) messagesContainer.innerHTML = "";
                    return;
                }
                const conv = resp.body.conversation;

                // gather AES keys for other members once
                const otherKeys = {};
                for (const mid of conv.members || []) {
                    if (mid === userId) continue;
                    const k = await getOrCreateAesKeyForPeer(mid);
                    if (k) otherKeys[mid] = k;
                }

                const msgs = [];
                for (const m of conv.messages || []) {
                    const otherId = m.senderId === userId ? (conv.members.find((x) => x !== userId) || "") : m.senderId;
                    let text = "";
                    if (m.unencrypted) {
                        text = m.textEncrypted || "";
                    } else if (m.textEncrypted) {
                        const aesKey = otherKeys[otherId] || await getOrCreateAesKeyForPeer(otherId);
                        if (aesKey) {
                            const iv = pickIvFromMessage(m);
                            const dec = iv ? await E2EE.decryptWithKey(aesKey, m.textEncrypted, iv) : null;
                            text = dec || "(konnte nicht entschluesselt werden)";
                        } else {
                            text = "(verschluesselt)";
                        }
                    }
                    msgs.push({ ...m, text });
                }

                renderMessages(msgs.map((mm) => ({ senderId: mm.senderId, text: mm.text, attachments: mm.attachments || [], ts: mm.ts, _id: mm.id })), { autoScroll: true });
                await api.markRead(convId, userId).catch(() => { });
                await loadContacts();
            } catch (e) {
                console.error("openConversation error", e);
            }
        }

        function renderMessages(msgs, opts = { autoScroll: false }) {
            if (!messagesContainer) return;
            messagesContainer.innerHTML = "";
            const frag = document.createDocumentFragment();

            msgs.forEach((m) => {
                const container = el("div", "message-container" + (m.senderId === userId ? " my" : ""));
                if (m._id) container.dataset.msgId = m._id;
                if (m._tempId) container.dataset.tempId = m._tempId;

                const avatarImg = el("img", "message-avatar");
                avatarImg.src = "/chat/sources/avatars/avatar.png";

                const box = el("div", "message-box" + (m.senderId === userId ? " my" : ""));

                if (m.attachments && m.attachments.length) {
                    m.attachments.forEach((att) => {
                        const mf = el("div", "message-file");
                        const fi = el("img", "file-icon");
                        fi.src = getIconForFilename(att.filename);
                        fi.alt = att.filename || "file";
                        fi.style.width = "28px";
                        fi.style.height = "28px";
                        fi.style.verticalAlign = "middle";

                        const fp = el("div", "file-property");
                        const name = el("a", "file-name");
                        name.textContent = att.filename || "file";
                        const btn = el("button", "file-download");
                        btn.textContent = "Download";

                        const hasCipher = (!!(att.cipher || att.cipherB64 || att.cipherBase64)) && (!!(att.iv || att.ivB64 || att.ivBase64));
                        if (!hasCipher) {
                            btn.disabled = true;
                            btn.title = "Datei wird noch hochgeladen/verschlüsselt";
                        } else {
                            btn.disabled = false;
                            btn.title = "";
                        }

                        btn.addEventListener("click", async () => {
                            try {
                                await downloadAttachment({ senderId: m.senderId }, att);
                            } catch (e) {
                                alert("Datei kann nicht heruntergeladen werden: " + (e?.message || "Fehler"));
                            }
                        });

                        fp.appendChild(name);
                        fp.appendChild(document.createElement("br"));
                        fp.appendChild(btn);

                        mf.appendChild(fi);
                        mf.appendChild(fp);
                        box.appendChild(mf);
                    });
                }

                if (m.text && String(m.text).trim().length) {
                    const textNode = el("div", "message-text");
                    textNode.textContent = m.text;
                    if (m.attachments && m.attachments.length) textNode.style.marginTop = "6px";
                    box.appendChild(textNode);
                }

                const time = el("a", "message-time");
                time.textContent = formatTime(m.ts);
                time.style.display = "block";
                time.style.marginTop = "6px";
                time.style.fontSize = "11px";
                time.style.color = "#666";
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

        function appendMessageToDOM(m) {
            if (!messagesContainer) return null;

            if (m._id) {
                const exists = messagesContainer.querySelector(`[data-msg-id="${m._id}"]`);
                if (exists) return exists;
            }
            if (m._tempId) {
                const tempExists = messagesContainer.querySelector(`[data-temp-id="${m._tempId}"]`);
                if (tempExists) return tempExists;
            }

            const container = el("div", "message-container" + (m.senderId === userId ? " my" : ""));
            if (m._tempId) container.dataset.tempId = m._tempId;
            if (m._id) {
                container.dataset.msgId = m._id;
                processedMessageIds.add(String(m._id));
            }

            const avatarImg = el("img", "message-avatar");
            avatarImg.src = "/chat/sources/avatars/avatar.png";
            const box = el("div", "message-box" + (m.senderId === userId ? " my" : ""));

            if (m.attachments && m.attachments.length) {
                m.attachments.forEach((att) => {
                    const mf = el("div", "message-file");
                    const fi = el("img", "file-icon");
                    fi.src = getIconForFilename(att.filename);
                    fi.alt = att.filename || "file";
                    fi.style.width = "28px";
                    fi.style.height = "28px";
                    fi.style.verticalAlign = "middle";

                    const fp = el("div", "file-property");
                    const name = el("a", "file-name");
                    name.textContent = att.filename || "file";
                    const btn = el("button", "file-download");
                    btn.textContent = "Download";

                    const hasCipher = (!!(att.cipher || att.cipherB64 || att.cipherBase64)) && (!!(att.iv || att.ivB64 || att.ivBase64));
                    if (!hasCipher) {
                        btn.disabled = true;
                        btn.title = "Datei wird noch hochgeladen/verschlüsselt";
                    } else {
                        btn.disabled = false;
                        btn.title = "";
                    }

                    btn.addEventListener("click", () => downloadAttachment(m, att));

                    fp.appendChild(name);
                    fp.appendChild(document.createElement("br"));
                    fp.appendChild(btn);

                    mf.appendChild(fi);
                    mf.appendChild(fp);
                    box.appendChild(mf);
                });
            }

            if (m.text && String(m.text).trim().length) {
                const textNode = el("div", "message-text");
                textNode.textContent = m.text;
                if (m.attachments && m.attachments.length) textNode.style.marginTop = "6px";
                box.appendChild(textNode);
            }

            const time = el("a", "message-time");
            time.textContent = formatTime(m.ts);
            time.style.display = "block";
            time.style.marginTop = "6px";
            time.style.fontSize = "11px";
            time.style.color = "#666";
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

        /* -------------------------
           Download attachment
           ------------------------- */
        async function downloadAttachment(messageObj, att) {
            try {
                const otherId = messageObj.senderId === userId ? (currentContact?.id) : messageObj.senderId;
                const iv = att.iv || att.ivB64 || att.ivBase64 || null;
                const cipher = att.cipher || att.cipherB64 || att.cipherBase64 || null;
                if (!cipher || !iv) return alert("Anhang hat keine Verschlüsselungsdaten");
                const aesKey = await getOrCreateAesKeyForPeer(otherId);
                if (!aesKey) return alert("Kein AES-Key zum Entschlüsseln vorhanden");
                const ab = await E2EE.decryptBuffer(aesKey, cipher, iv);
                if (!ab) return alert("Datei konnte nicht entschlüsselt werden");
                const blob = new Blob([ab], { type: att.mime || "application/octet-stream" });
                const url = URL.createObjectURL(blob);
                const a = el("a");
                a.href = url;
                a.download = att.filename || "file";
                document.body.appendChild(a);
                a.click();
                a.remove();
                URL.revokeObjectURL(url);
            } catch (e) {
                console.error("downloadAttachment error", e);
                alert("Fehler beim Herunterladen: " + (e?.message || "Fehler"));
            }
        }

        /* -------------------------
           Send message logic
           ------------------------- */
        function releaseOngoingSendKeyWithTimeout(sendKey, ms = 10000) {
            setTimeout(() => {
                if (ongoingSends.has(sendKey)) {
                    ongoingSends.delete(sendKey);
                    sendLock.delete(sendKey);
                }
            }, ms);
        }

        function markMessageFailed(tempId) {
            const elTemp = messagesContainer?.querySelector(`[data-temp-id="${tempId}"]`);
            if (!elTemp) return;
            elTemp.classList.add("send-failed");
        }

        async function updateTempMessageWithServer(tempId, serverMsg) {
            try {
                if (!serverMsg || !serverMsg.id) return;

                if (processedMessageIds.has(String(serverMsg.id))) {
                    const maybeTemp = messagesContainer?.querySelector(`[data-temp-id="${tempId}"]`);
                    if (maybeTemp) maybeTemp.remove();
                    return;
                }

                processedMessageIds.add(String(serverMsg.id));
                const elTemp = messagesContainer?.querySelector(`[data-temp-id="${tempId}"]`);
                const otherId = serverMsg.senderId === userId ? (currentContact?.id) || null : serverMsg.senderId;

                // decrypt server message for display (safe fallbacks)
                let plainText = "";
                if (serverMsg.unencrypted) {
                    plainText = serverMsg.textEncrypted || "";
                } else if (serverMsg.textEncrypted) {
                    try {
                        let aesKey = null;
                        if (otherId) aesKey = await getOrCreateAesKeyForPeer(otherId);
                        if (!aesKey && currentContact?.id) aesKey = await getOrCreateAesKeyForPeer(currentContact.id);
                        if (aesKey) {
                            const iv = pickIvFromMessage(serverMsg);
                            if (iv) {
                                const dec = await E2EE.decryptWithKey(aesKey, serverMsg.textEncrypted, iv);
                                plainText = dec || "(konnte nicht entschlüsselt werden)";
                            } else {
                                plainText = serverMsg.textEncrypted || "(verschlüsselt)";
                            }
                        } else {
                            plainText = "(verschlüsselt)";
                        }
                    } catch (e) {
                        console.warn("updateTempMessageWithServer decrypt failed", e);
                        plainText = "(verschlüsselt)";
                    }
                }

                const msgObj = {
                    senderId: serverMsg.senderId,
                    text: plainText,
                    attachments: serverMsg.attachments || [],
                    ts: serverMsg.ts,
                    _id: serverMsg.id,
                };

                if (elTemp) {
                    appendMessageToDOM({ senderId: msgObj.senderId, text: msgObj.text, attachments: msgObj.attachments, ts: msgObj.ts, _id: msgObj._id });
                    elTemp.remove();
                    api.markRead(currentConversationId, userId).catch(() => { });
                    loadContacts().catch(() => { });
                    return;
                }

                const exists = messagesContainer?.querySelector(`[data-msg-id="${serverMsg.id}"]`);
                if (!exists) {
                    appendMessageToDOM({ senderId: msgObj.senderId, text: msgObj.text, attachments: msgObj.attachments, ts: msgObj.ts, _id: msgObj._id });
                    api.markRead(currentConversationId, userId).catch(() => { });
                    loadContacts().catch(() => { });
                }
            } catch (e) {
                console.error("updateTempMessageWithServer error", e);
            }
        }

        async function sendMessage() {
            if (sendCooldown) {
                console.warn("Send blocked by short cooldown");
                return;
            }
            const text = (messageInput?.value || "").trim();
            if (!text && !attachedFile) return;

            if (!currentContact) {
                if (!contacts.length) return alert("Kein Kontakt ausgewählt");
                currentContact = contacts[0];
            }

            const sendKey = makeSendKey(currentConversationId, text, attachedFile);

            if (sendLock.has(sendKey)) {
                console.warn("Duplicate send suppressed for key (sendLock):", sendKey);
                return;
            }
            sendLock.add(sendKey);
            setTimeout(() => sendLock.delete(sendKey), 5);

            sendCooldown = true;
            if (sendBtn) sendBtn.disabled = true;
            setTimeout(() => { sendCooldown = false; if (sendBtn) sendBtn.disabled = false; }, 5);

            if (ongoingSends.has(sendKey)) {
                console.warn("Duplicate send suppressed for key (ongoing):", sendKey);
                return;
            }

            const nowTs = Date.now();
            const lastTs = lastSendTimes.get(sendKey) || 0;
            const MIN_REPEAT_MS = 5;
            if (nowTs - lastTs < MIN_REPEAT_MS) {
                console.warn("Duplicate send suppressed for key (time-window):", sendKey);
                return;
            }
            lastSendTimes.set(sendKey, nowTs);

            ongoingSends.set(sendKey, true);
            releaseOngoingSendKeyWithTimeout(sendKey, 10000);

            const tempId = `temp-${Date.now()}-${Math.floor(Math.random() * 100000)}`;

            try {
                if (!currentConversationId) {
                    const resp = await api.createConversation([userId, currentContact.id]);
                    if (!resp?.ok) { ongoingSends.delete(sendKey); return alert("Konversation konnte nicht erstellt werden"); }
                    currentConversationId = resp.body.conversation.id;
                }

                let aesKey = null;
                try { aesKey = await getOrCreateAesKeyForPeer(currentContact.id); } catch (e) { console.warn("getOrCreateAesKeyForPeer failed", e); aesKey = null; }

                let textEncrypted = "";
                let textIv = "";
                let unencryptedFlag = false;

                if (text && aesKey) {
                    try {
                        const enc = await E2EE.encryptWithKey(aesKey, text);
                        textEncrypted = enc.cipherB64; textIv = enc.ivB64;
                    } catch (e) {
                        console.warn("encryptWithKey failed", e);
                        textEncrypted = text;
                        unencryptedFlag = true;
                    }
                } else if (text && !aesKey) {
                    textEncrypted = text;
                    unencryptedFlag = true;
                }

                // attachments (NEVER send attachments unencrypted)
                const attachments = [];
                if (attachedFile) {
                    if (!aesKey) {
                        alert("Der Empfänger hat noch keinen PublicKey hinterlegt. Bitte den Kontakt bitten, sich einmal einzuloggen, damit sichere Anhänge möglich sind. Die Nachricht wurde nicht gesendet.");
                        const tempEl = messagesContainer?.querySelector(`[data-temp-id="${tempId}"]`);
                        if (tempEl) tempEl.remove();
                        ongoingSends.delete(sendKey);
                        return;
                    }
                    try {
                        const ab = await attachedFile.arrayBuffer();
                        const enc = await E2EE.encryptBuffer(aesKey, ab);
                        attachments.push({ filename: attachedFile.name, mime: attachedFile.type || "application/octet-stream", cipher: enc.cipherB64, iv: enc.ivB64 });
                    } catch (e) {
                        console.warn("encrypt attachment failed", e);
                    }
                }

                const optimisticAttachments = attachments.length > 0 ? attachments.map(a => ({ ...a })) : (attachedFile ? [{ filename: attachedFile.name, mime: attachedFile.type || "application/octet-stream", pending: true }] : []);

                const optimisticMsg = {
                    senderId: userId,
                    text: text || (attachedFile ? "[Datei]" : ""),
                    attachments: optimisticAttachments,
                    ts: Date.now(),
                    _tempId: tempId,
                };

                appendMessageToDOM(optimisticMsg);

                if (messageInput) {
                    messageInput.value = "";
                    messageInput.placeholder = "Nachricht ...";
                    messageInput.focus();
                    messageInput.dispatchEvent(new Event("input"));
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

                if (socket?.connected) {
                    socket.emit("send_message", payload, (ack) => {
                        try {
                            if (!ack || ack.error) {
                                console.error("send_message ack error", ack?.error);
                                markMessageFailed(tempId);
                            } else {
                                updateTempMessageWithServer(tempId, ack.message);
                                loadContacts().catch(() => { });
                            }
                        } finally {
                            ongoingSends.delete(sendKey);
                        }
                    });
                } else {
                    try {
                        const resp = await api.postMessage(payload);
                        if (!resp?.ok) {
                            markMessageFailed(tempId);
                        } else {
                            updateTempMessageWithServer(tempId, resp.body.message || resp.body);
                            loadContacts().catch(() => { });
                        }
                    } catch (e) {
                        console.error("postMessage fallback error", e);
                        markMessageFailed(tempId);
                    } finally {
                        ongoingSends.delete(sendKey);
                    }
                }

                attachedFile = null;
                fileInput.value = "";
            } catch (e) {
                console.error("sendMessage error", e);
                alert("Fehler beim Senden");
                ongoingSends.delete(sendKey);
            }
        }

        window.sendMessage = sendMessage;
        if (sendBtn) sendBtn.addEventListener("click", (e) => { e.preventDefault(); sendMessage(); });
        if (messageInput) {
            messageInput.addEventListener("keydown", (e) => {
                if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(); }
            });
        }

        /* -------------------------
           Socket event handlers
           ------------------------- */
        if (socket) {
            socket.on("message", async (data) => {
                try {
                    if (!data || !data.message) return;
                    const incoming = data.message;
                    const convId = data.conversationId;
                    const clientId = incoming.clientId || incoming.clientid || null;

                    if (incoming.id && processedMessageIds.has(String(incoming.id))) return;

                    // message for currently open conversation
                    if (currentConversationId && convId === currentConversationId) {
                        if (clientId) {
                            const tempEl = messagesContainer?.querySelector(`[data-temp-id="${clientId}"]`);
                            if (tempEl) {
                                await updateTempMessageWithServer(clientId, incoming);
                                api.markRead(currentConversationId, userId).catch(() => { });
                                loadContacts().catch(() => { });
                                return;
                            }
                        }

                        if (incoming.unencrypted) {
                            if (incoming.id && processedMessageIds.has(String(incoming.id))) return;
                            if (incoming.id) {
                                const exists = messagesContainer?.querySelector(`[data-msg-id="${incoming.id}"]`);
                                if (exists) return;
                            }
                            const msgObj = {
                                senderId: incoming.senderId,
                                text: incoming.textEncrypted || "",
                                attachments: incoming.attachments || [],
                                ts: incoming.ts || Date.now(),
                                _id: incoming.id,
                            };
                            appendMessageToDOM(msgObj);
                            if (incoming.id) processedMessageIds.add(String(incoming.id));
                            api.markRead(currentConversationId, userId).catch(() => { });
                            loadContacts().catch(() => { });
                            return;
                        }

                        const otherId = incoming.senderId === userId ? (currentContact?.id) || "" : incoming.senderId;
                        let text = "";
                        if (incoming.textEncrypted) {
                            try {
                                text = await decryptTextForDisplay(incoming, otherId);
                            } catch (e) {
                                console.warn("decrypt on socket message failed", e);
                                text = "(verschluesselt)";
                            }
                        }

                        if (incoming.id && processedMessageIds.has(String(incoming.id))) return;

                        if (clientId) {
                            const tempEl2 = messagesContainer?.querySelector(`[data-temp-id="${clientId}"]`);
                            if (tempEl2) {
                                await updateTempMessageWithServer(clientId, incoming);
                                api.markRead(currentConversationId, userId).catch(() => { });
                                loadContacts().catch(() => { });
                                return;
                            }
                        }

                        if (incoming.id) {
                            const exists = messagesContainer?.querySelector(`[data-msg-id="${incoming.id}"]`);
                            if (exists) return;
                        }

                        appendMessageToDOM({
                            senderId: incoming.senderId,
                            text: text || "",
                            attachments: incoming.attachments || [],
                            ts: incoming.ts || Date.now(),
                            _id: incoming.id,
                        });
                        if (incoming.id) processedMessageIds.add(String(incoming.id));
                        api.markRead(currentConversationId, userId).catch(() => { });
                        loadContacts().catch(() => { });
                        return;
                    }

                    await loadContacts();
                } catch (e) {
                    console.error("socket message handler", e);
                }
            });

            socket.on("contacts_update", async (data) => {
                try {
                    await loadContacts();
                    const updatedUserId = data && (data.userId || data.contactId || data.updatedUserId);
                    if (updatedUserId && currentContact && updatedUserId === currentContact.id) {
                        try {
                            const k = await getOrCreateAesKeyForPeer(currentContact.id);
                            if (k) {
                                const lockEl = document.querySelector(`#contact-${currentContact.id} .contact-lock`);
                                if (lockEl) lockEl.textContent = "🔒";
                            }
                        } catch { }
                    }
                } catch (e) {
                    console.error("contacts_update handler", e);
                }
            });

            socket.on("conversation_update", () => { loadContacts().catch(() => { }); });
            socket.on("connect", () => { console.log("[socket] connected", socket.id); });
            socket.on("disconnect", (reason) => { console.log("[socket] disconnected", reason); });
            socket.on("connect_error", (err) => {
                console.error("[socket] connect_error:", err?.message || err);
                const msg = err?.message || "Socket-Fehler";
                switch (msg) {
                    case "AUTH_NO_TOKEN":
                        alert("Socket-Verbindung fehlgeschlagen: Kein Login-Token vorhanden.");
                        break;
                    case "AUTH_INVALID_TOKEN":
                        alert("Socket-Verbindung fehlgeschlagen: Login abgelaufen oder ungültig.");
                        localStorage.removeItem("user");
                        window.location.href = "/chat/login/login.html";
                        break;
                    case "AUTH_INTERNAL_ERROR":
                        alert("Interner Serverfehler bei der Socket-Anmeldung.");
                        break;
                    default:
                        console.warn("Socket-Fehler:", msg);
                }
            });
        }

        await loadContacts();
        if (contacts.length && contactsContainer) {
            const first = contactsContainer.querySelector('.contact');
            if (first) first.click();
        }
    });
})();