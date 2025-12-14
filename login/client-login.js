const SOCKET_URL = window.SOCKET_URL || 'https://rhythm-flu-portal-vehicle.trycloudflare.com';
const SOCKET_IO_CDN = 'https://cdn.socket.io/4.7.1/socket.io.min.js';

function loadSocketIoClient() {
    return new Promise((resolve, reject) => {
        if (typeof io !== 'undefined') return resolve();
        const s = document.createElement('script');
        s.src = SOCKET_IO_CDN;
        s.onload = () => resolve();
        s.onerror = (e) => reject(new Error('socket.io client load failed'));
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

async function ensureKeyAndUpload(socket, userId) {
    const keyName = 'ecdh_jwk_' + userId;
    const pubName = 'ecdh_pub_' + userId;

    if (localStorage.getItem(pubName) && localStorage.getItem(keyName)) {
        // Wenn Socket verbunden: upload via socket, sonst per REST fallback
        const pub = localStorage.getItem(pubName);
        if (socket && socket.connected) {
            socket.emit('upload_public_key', { publicKey: pub }, (r) => {
                if (!r || !r.ok) console.warn('upload pubkey (socket) failed', r);
            });
        } else {
            // REST fallback (relativ/absolute)
            const apiBase = window.API_URL || '';
            fetch(`${apiBase}/user/${encodeURIComponent(userId)}/publicKey`, {
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

    if (socket && socket.connected) {
        socket.emit('upload_public_key', { publicKey: pubB64 }, (r) => {
            if (!r || !r.ok) console.warn('upload pubkey (socket) failed', r);
        });
    } else {
        const apiBase = window.API_URL || '';
        fetch(`${apiBase}/user/${encodeURIComponent(userId)}/publicKey`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ publicKey: pubB64 })
        }).catch((e) => { console.warn('upload pubkey (rest) failed', e); });
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('login-form');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = form.querySelector('#username').value.trim();
        const password = form.querySelector('#password').value;

        if (!username) { document.getElementById("error").innerHTML = "Bitte Benutzername eingeben"; return; }
        if (!password) { document.getElementById("error").innerHTML = "Bitte Passwort eingeben"; return; }

        let socket = null;
        try {
            // Lade socket.io client falls nötig
            await loadSocketIoClient();

            // Erstelle socket-Verbindung (websocket-transport)
            socket = io(SOCKET_URL, {
                transports: ['websocket'],
                auth: {} // wir loggen uns per Event ein
            });

            socket.on('connect_error', (err) => {
                console.warn('[socket] connect_error', err);
            });

            // login per socket.emit (ack)
            socket.emit('login', { username, password }, async (resp) => {
                console.log('[client] socket login resp', resp);
                if (!resp || !resp.ok) {
                    document.getElementById("error").innerHTML = "Login fehlgeschlagen: " + (resp && resp.error ? resp.error : 'ungueltig');
                    socket.disconnect();
                    return;
                }

                try {
                    // Keypair erzeugen/upload (nutze user id aus resp)
                    await ensureKeyAndUpload(socket, resp.id);
                } catch (e) {
                    console.warn('ensureKeyAndUpload error', e);
                }

                // speichere minimalen User inkl sessionToken
                const user = { id: resp.id, username: resp.username, sessionToken: resp.sessionToken };
                localStorage.setItem('user', JSON.stringify(user));

                // Weiterleitung
                window.location.href = '/chat/index.html';
            });

        } catch (err) {
            console.error('[client] login error', err);
            document.getElementById("error").innerHTML = "Netzwerkfehler";
            if (socket) try { socket.disconnect(); } catch (_) { }
        }
    });
});