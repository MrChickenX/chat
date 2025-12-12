// public/client-login.js
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
                // speichere minimalen User im localStorage
                const user = { id: data.id, username: data.username };
                localStorage.setItem('user', JSON.stringify(user));
                // Weiterleitung zum Chat
                window.location.href = '/chat.html';
            } else {
                document.getElementById("error").innerHTML = "Login fehlgeschlagen: " + (data.error || 'ungueltig');
            }
        } catch (err) {
            console.error('[client] login error', err);
            document.getElementById("error").innerHTML = "Netzwerkfehler";
        }
    });
});
