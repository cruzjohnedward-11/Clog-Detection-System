const loginForm = document.getElementById('loginForm');

if (loginForm) {
    loginForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const loginError = document.getElementById('loginError');
        const submitButton = loginForm.querySelector('button[type="submit"]');
        loginError.classList.add('hidden');
        submitButton.disabled = true;

        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username: document.getElementById('loginUsername').value,
                    password: document.getElementById('loginPassword').value,
                    role: document.getElementById('loginRole').value
                })
            });
            const result = await response.json();
            if (!response.ok) throw new Error(result.error || 'Sign in failed.');

            window.sessionStorage.setItem('userRole', result.role);
            window.location.href = 'overview.html';
        } catch (error) {
            loginError.textContent = error.message || 'Unable to sign in. Check the server connection.';
            loginError.classList.remove('hidden');
        } finally {
            submitButton.disabled = false;
        }
    });
}

const settingsPage = window.sessionStorage.getItem('userRole') === 'DRRM Officer'
    ? 'settingsDRRM.html'
    : 'settings.html';

document.querySelectorAll('a[href="settings.html"], a[href="settingsDRRM.html"]').forEach((link) => {
    link.href = settingsPage;
});