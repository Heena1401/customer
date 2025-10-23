const form = document.getElementById('loginForm');
const btn = document.getElementById('loginBtn');
const statusEl = document.getElementById('status');
const welcomeEl = document.getElementById('welcome');

function setStatus(msg, type = '') {
  statusEl.textContent = msg || '';
  statusEl.className = `status ${type}`;
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  setStatus('');

  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value;

  if (!email || !password) {
    setStatus('Please enter email and password.', 'error');
    return;
  }

  btn.disabled = true;
  setStatus('Checking credentials…');

  try {
    const res = await fetch('/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }) // plain text password (as requested)
    });

    // Try to parse JSON even on error status
    const data = await res.json().catch(() => ({}));

    if (!res.ok || !data.success) {
      const msg = data.message || 'Invalid credentials.';
      setStatus(msg, 'error');
      btn.disabled = false;
      return;
    }

    // Success → show the email & role
    const roleText = data.role ? data.role.charAt(0).toUpperCase() + data.role.slice(1) : 'User';
    setStatus('Login successful!', 'ok');
    <a href="/dashboard.html">dashboard</a>

    // // Hide the form and show a friendly welcome box
    // form.classList.add('hidden');
    // welcomeEl.classList.remove('hidden');
    // welcomeEl.innerHTML = `
    //   <h2 style="margin:0 0 8px;">Welcome 🎉</h2>
    //   <p><strong>Role:</strong> ${roleText}</p>
    //   <p><strong>Email:</strong> ${data.email}</p>
    //   <div style="margin-top:10px; display:flex; gap:8px; flex-wrap:wrap;">
    //     <!-- Replace these with real routes if needed -->
    //     <a href="/" class="btn" style="text-decoration:none;display:inline-block;text-align:center;">Go Home</a>
    //     <a href="dashboard.html" class="btn" style="text-decoration:none;display:inline-block;text-align:center; background:#3b82f6; color:white;">Continue</a>
    //   </div>
    // `;
  } catch (err) {
    console.error(err);
    setStatus('Network error. Please try again.', 'error');
  } finally {
    // Keep disabled if success (form hidden). Re-enable on failure.
    if (!form.classList.contains('hidden')) btn.disabled = false;
  }
});
