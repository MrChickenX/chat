// public/client-chat.js
document.addEventListener('DOMContentLoaded', () => {
    try {
        // --- load user from localStorage ---
        const raw = localStorage.getItem('user');
        const user = raw ? JSON.parse(raw) : null;

        if (!user || !user.username) {
            // nicht eingeloggt -> weiterleiten
            // anpassen falls Login in Unterordner liegt:
            window.location.href = '/login/login.html';
            return;
        }

        // --- Utility: set text for many selectors safely ---
        function setText(selectors, text) {
            selectors.forEach(sel => {
                document.querySelectorAll(sel).forEach(el => {
                    if (el) el.textContent = text;
                });
            });
        }

        // --- Fill username / nickname / id / verified / publicKey ---
        setText(['#username-display', '.username-display', '[data-username]'], user.username || '');
        setText(['#nickname-display', '.nickname-display', '[data-nickname]'], user.nickname || user.username || '');
        // data-userid or #user-id
        setText(['#user-id', '[data-userid]'], user.id || '');
        setText(['#user-verified', '[data-verified]'], user.verified || '');
        setText(['#user-publickey', '[data-publickey]'], user.publicKey || '');

        // --- Avatar: if you store avatar path in user.avatar (optional) ---
        if (user.avatar) {
            document.querySelectorAll('.avatar, .user-avatar, [data-avatar]').forEach(img => {
                if (img && img.tagName.toLowerCase() === 'img') {
                    img.src = user.avatar;
                } else if (img) {
                    // fallback: set background-image for non-img elements
                    img.style.backgroundImage = `url(${user.avatar})`;
                }
            });
        }

        // --- Contacts: render list if container exists and contacts array provided ---
        const contactsContainer = document.getElementById('contacts-list'); // put <div id="contacts-list"></div> in chat.html
        if (contactsContainer && Array.isArray(user.contacts)) {
            contactsContainer.innerHTML = ''; // clear
            user.contacts.forEach(contactId => {
                // If you want to show details, you must fetch them from server or keep them in localStorage.
                const el = document.createElement('div');
                el.className = 'contact-item';
                el.dataset.contactId = contactId;
                el.textContent = contactId; // simple: show id. Extend by fetching contact meta
                contactsContainer.appendChild(el);
            });
        }

        // --- Logout handler: attach to all .logout-btn or [data-logout] ---
        const logoutEls = Array.from(document.querySelectorAll('.logout-btn, [data-logout], #logout-btn'));
        logoutEls.forEach(btn => {
            if (!btn) return;
            btn.addEventListener('click', async (e) => {
                e.preventDefault();
                // optional: call server logout if you implement sessions
                // await fetch('/logout', { method: 'POST' });

                localStorage.removeItem('user');
                localStorage.removeItem('token'); // if used
                window.location.href = '/login/login.html';
            });
        });

        // --- small debug: ensure UI restored if you previously hid it ---
        document.body.style.opacity = '1';
    } catch (err) {
        console.error('client-chat init error', err);
        // make UI visible to avoid "disappearing" effect
        document.body.style.opacity = '1';
    }
});
