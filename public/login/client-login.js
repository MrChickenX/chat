document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('login-form');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = form.querySelector('#username').value.trim();
        const password = form.querySelector('#password').value;

        if (!username) { document.getElementById("error").innerHTML = "Bitte Benutzername eingeben"; return; }
        if (!password) { document.getElementById("error").innerHTML = "Bitte Passwort eingeben"; return; }

        try {
            const resp = await fetch('/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            const data = await resp.json().catch(() => ({}));
            console.log('[client] login response', resp.status, data);

            if (resp.ok && data.ok) {
                // helper: base64 helpers (Safari/iPad safe)
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

                // generiere/hochlade Keypair (wenn nicht vorhanden)
                async function ensureKeyAndUpload(userId) {
                    const keyName = 'ecdh_jwk_' + userId;
                    const pubName = 'ecdh_pub_' + userId;

                    if (localStorage.getItem(pubName) && localStorage.getItem(keyName)) {
                        // sende publicKey falls server ihn nicht hat
                        await fetch(`/user/${encodeURIComponent(userId)}/publicKey`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ publicKey: localStorage.getItem(pubName) })
                        }).catch(() => { });
                        return;
                    }

                    const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
                    const rawPub = await crypto.subtle.exportKey('raw', kp.publicKey);
                    const pubB64 = arrayBufferToBase64(rawPub);
                    const jwkPriv = await crypto.subtle.exportKey('jwk', kp.privateKey);

                    localStorage.setItem(pubName, pubB64);
                    localStorage.setItem(keyName, JSON.stringify(jwkPriv));

                    // upload publicKey to server
                    await fetch(`/user/${encodeURIComponent(userId)}/publicKey`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ publicKey: pubB64 })
                    }).catch((e) => { console.warn('upload pubkey failed', e); });
                }

                // warte auf key-upload bevor speichern und weiterleiten
                await ensureKeyAndUpload(data.id);

                // speichere minimalen User im localStorage
                const user = { id: data.id, username: data.username };
                localStorage.setItem('user', JSON.stringify(user));

                if (resp.ok && data.ok) {
                    // speichere minimalen User im localStorage inklusive sessionToken
                    const user = { id: data.id, username: data.username, sessionToken: data.sessionToken };
                    localStorage.setItem('user', JSON.stringify(user));

                    // ensure keypair & upload (optional): call ensureKeyAndUpload(user.id) if you want synchronously
                    // Weiterleitung zum Chat
                    window.location.href = '/chat.html';
                }

                // Weiterleitung zum Chat
                window.location.href = '/index.html';
            } else {
                document.getElementById("error").innerHTML = "Login fehlgeschlagen: " + (data.error || 'ungueltig');
            }
        } catch (err) {
            console.error('[client] login error', err);
            document.getElementById("error").innerHTML = "Netzwerkfehler";
        }
    });
});