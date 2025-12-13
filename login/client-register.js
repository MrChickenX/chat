document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('register-form');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const username = form.querySelector('#username').value.trim();
        const nickname = form.querySelector('#nickname') ? form.querySelector('#nickname').value.trim() : '';
        const password = form.querySelector('#password').value;
        const repeatPassword = form.querySelector('#repeatPassword').value;

        if (!username) { alert('Bitte Benutzername eingeben'); return; }
        if (!password) { alert('Bitte Passwort eingeben'); return; }
        if (password !== repeatPassword) { alert('Passwoerter stimmen nicht ueberein'); return; }

        try {
            const resp = await fetch('/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password, nickname })
            });

            const data = await resp.json().catch(() => ({}));
            console.log('[client] register response', resp.status, data);

            if (resp.ok && data.ok) {
                // generiere keypair und lade publicKey hoch, dann speichern & weiterleiten
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

                async function ensureKeyAndUpload(userId) {
                    const keyName = 'ecdh_jwk_' + userId;
                    const pubName = 'ecdh_pub_' + userId;
                    if (localStorage.getItem(pubName) && localStorage.getItem(keyName)) {
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

                    await fetch(`/user/${encodeURIComponent(userId)}/publicKey`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ publicKey: pubB64 })
                    }).catch((e) => { console.warn('upload pubkey failed', e); });
                }

                // erst keys, dann speichern + redirect
                await ensureKeyAndUpload(data.id);
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

                window.location.href = '/index.html';
            } else {
                alert('Fehler: ' + (data.error || 'unbekannt'));
            }
        } catch (err) {
            console.error('[client] register error', err);
            alert('Netzwerkfehler');
        }
    });
});