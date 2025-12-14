const API_URL = window.API_URL || 'https://rhythm-flu-portal-vehicle.trycloudflare.com';
const SOCKET_URL = window.SOCKET_URL || 'https://rhythm-flu-portal-vehicle.trycloudflare.com';
const SOCKET_IO_CDN = 'https://cdn.socket.io/4.7.1/socket.io.min.js';

function loadSocketIoClientIfNeeded() {
    return new Promise((resolve, reject) => {
        if (!SOCKET_URL) return resolve(); // keine socket-url konfiguriert
        if (typeof io !== 'undefined') return resolve();
        const s = document.createElement('script');
        s.src = SOCKET_IO_CDN;
        s.onload = () => resolve();
        s.onerror = () => reject(new Error('socket.io client load failed'));
        document.head.appendChild(s);
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

async function ensureKeyAndUploadAfterRegister(userId) {
    const keyName = 'ecdh_jwk_' + userId;
    const pubName = 'ecdh_pub_' + userId;

    if (localStorage.getItem(pubName) && localStorage.getItem(keyName)) {
        const pub = localStorage.getItem(pubName);
        // versuche socket upload wenn möglich, ansonsten REST fallback
        if (SOCKET_URL && typeof io !== 'undefined') {
            const sock = io(SOCKET_URL, { transports: ['websocket'] });
            sock.on('connect', () => {
                sock.emit('upload_public_key', { publicKey: pub }, (r) => {
                    if (!r || !r.ok) console.warn('upload pubkey (socket) failed', r);
                    sock.disconnect();
                });
            });
            sock.on('connect_error', (e) => { console.warn('socket connect error', e); sock.disconnect(); });
        } else {
            fetch(`${API_URL}/user/${encodeURIComponent(userId)}/publicKey`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ publicKey: pub })
            }).catch(() => { });
        }
        return;
    }

    const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    const rawPub = await crypto.subtle.exportKey('raw', kp.publicKey);
    const pubB64 = arrayBufferToBase64(rawPub);
    const jwkPriv = await crypto.subtle.exportKey('jwk', kp.privateKey);

    localStorage.setItem(pubName, pubB64);
    localStorage.setItem(keyName, JSON.stringify(jwkPriv));

    if (SOCKET_URL) {
        try {
            await loadSocketIoClientIfNeeded();
            if (typeof io !== 'undefined') {
                const sock = io(SOCKET_URL, { transports: ['websocket'] });
                sock.on('connect', () => {
                    sock.emit('upload_public_key', { publicKey: pubB64 }, (r) => {
                        if (!r || !r.ok) console.warn('upload pubkey (socket) failed', r);
                        sock.disconnect();
                    });
                });
                sock.on('connect_error', (e) => { console.warn('socket connect error', e); sock.disconnect(); });
                return;
            }
        } catch (e) {
            console.warn('socket upload attempt failed, falling back to REST', e);
            // fallthrough to REST
        }
    }

    // REST fallback
    fetch(`${API_URL}/user/${encodeURIComponent(userId)}/publicKey`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ publicKey: pubB64 })
    }).catch((e) => { console.warn('upload pubkey (rest) failed', e); });
}

document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('register-form');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const username = form.querySelector('#username').value.trim();
        const nickname = form.querySelector('#nickname') ? form.querySelector('#nickname').value.trim() : '';
        const password = form.querySelector('#password').value;
        const repeatPassword = form.querySelector('#repeatPassword').value;
        const policy = form.querySelector('#policy').checked;
        const dataPolicy = form.querySelector('#data-policy').checked;

        if (!username) { document.getElementById("error").innerHTML = "Bitte Benutzernamen eingeben"; return; }
        if (!password) { document.getElementById("error").innerHTML = "Bitte Passwort eingeben"; return; }
        if (password !== repeatPassword) { document.getElementById("error").innerHTML = "Passwörter stimmen nicht überrein"; return; }
        if (!policy) { document.getElementById("error").innerHTML = "Nutzungsbedinungen nicht akteptiert"; return; }
        if (!dataPolicy) { document.getElementById("error").innerHTML = "Nutzungsbedinungen nicht akteptiert"; return; }

        try {
            const resp = await fetch(`${API_URL}/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password, nickname })
            });

            const data = await resp.json().catch(() => ({}));
            console.log('[client] register response', resp.status, data);

            if (resp.ok && data.ok) {
                // keys generieren + upload (socket bevorzugt, resp liefert user id)
                try {
                    await ensureKeyAndUploadAfterRegister(data.id);
                } catch (e) {
                    console.warn('ensureKeyAndUploadAfterRegister error', e);
                }

                // speichere minimalen User inkl sessionToken
                const user = { id: data.id, username: data.username, sessionToken: data.sessionToken };
                localStorage.setItem('user', JSON.stringify(user));

                // redirect
                window.location.href = '/chat/index.html';
            } else {
                document.getElementById("error").innerHTML = "Fehler: " + (data.error || 'unbekannt');
            }
        } catch (err) {
            console.error('[client] register error', err);
            document.getElementById("error").innerHTML = "Netzwerkfehler";
        }
    });
});