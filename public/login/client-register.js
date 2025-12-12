// public/client-register.js
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
                // automatisch einloggen: speichere user minimal und weiterleiten
                const user = { id: data.id, username: data.username };
                localStorage.setItem('user', JSON.stringify(user));
                window.location.href = '/chat.html';
            } else {
                alert('Fehler: ' + (data.error || 'unbekannt'));
            }
        } catch (err) {
            console.error('[client] register error', err);
            alert('Netzwerkfehler');
        }
    });
});
