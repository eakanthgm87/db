// ============================================================
// VeilDB Demo — In-Browser Auth App
// Uses a simplified VeilDB mock to demonstrate encrypted
// user credential storage in the database.
// ============================================================

// ---------- Mini VeilDB Mock (in-memory KV store) ----------

const VeilDB = (() => {
  let db = null;

  function randomHex(len) {
    const chars = '0123456789abcdef';
    let out = '';
    for (let i = 0; i < len; i++) out += chars[Math.floor(Math.random() * 16)];
    return out;
  }

  // Simple hash for password verification (NOT secure — demo only)
  async function hashPassword(password, salt) {
    const encoder = new TextEncoder();
    const data = encoder.encode(salt + password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hashBuffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  return {
    async init(name, passphrase) {
      db = {
        name,
        passphrase,
        id: randomHex(64),
        deviceId: randomHex(64),
        data: new Map(),
        opCount: 0,
        merkleRoot: randomHex(64),
      };
      return { success: true, dbId: db.id, deviceId: db.deviceId };
    },

    isOpen() {
      return db !== null;
    },

    async put(key, value) {
      if (!db) throw new Error('Database not initialized');
      db.data.set(key, value);
      db.opCount++;
      db.merkleRoot = randomHex(64);
      return { success: true };
    },

    async get(key) {
      if (!db) throw new Error('Database not initialized');
      const val = db.data.get(key);
      return val !== undefined ? { success: true, data: val } : { success: false };
    },

    async createUser(username, email, password, role) {
      if (!db) throw new Error('Database not initialized');

      // Check existing
      const existing = db.data.get(`user:${username}`);
      if (existing) throw new Error('Username already exists');

      // Hash password
      const salt = randomHex(32);
      const hash = await hashPassword(password, salt);

      const userData = {
        username,
        email,
        role,
        passwordHash: hash,
        salt,
        createdAt: new Date().toISOString(),
        id: randomHex(16),
      };

      // Store user
      db.data.set(`user:${username}`, JSON.stringify(userData));

      // Update index
      let index = [];
      const indexData = db.data.get('users:index');
      if (indexData) index = JSON.parse(indexData);
      index.push(username);
      db.data.set('users:index', JSON.stringify(index));

      db.opCount += 2;
      db.merkleRoot = randomHex(64);

      return { success: true, user: { username, email, role, createdAt: userData.createdAt, id: userData.id } };
    },

    async signIn(username, password) {
      if (!db) throw new Error('Database not initialized');

      const raw = db.data.get(`user:${username}`);
      if (!raw) throw new Error('Invalid username or password');

      const userData = JSON.parse(raw);
      const hash = await hashPassword(password, userData.salt);

      if (hash !== userData.passwordHash) {
        throw new Error('Invalid username or password');
      }

      return {
        success: true,
        user: {
          username: userData.username,
          email: userData.email,
          role: userData.role,
          createdAt: userData.createdAt,
          id: userData.id,
        }
      };
    },

    async listUsers() {
      if (!db) return [];
      const indexData = db.data.get('users:index');
      if (!indexData) return [];

      const index = JSON.parse(indexData);
      const users = [];
      for (const uname of index) {
        const raw = db.data.get(`user:${uname}`);
        if (raw) {
          const u = JSON.parse(raw);
          users.push({
            username: u.username,
            email: u.email,
            role: u.role,
            createdAt: u.createdAt,
            id: u.id,
          });
        }
      }
      return users;
    },

    async deleteUser(username) {
      if (!db) throw new Error('Database not initialized');
      db.data.delete(`user:${username}`);
      const indexData = db.data.get('users:index');
      if (indexData) {
        let index = JSON.parse(indexData);
        index = index.filter(u => u !== username);
        db.data.set('users:index', JSON.stringify(index));
      }
      db.opCount++;
      db.merkleRoot = randomHex(64);
    },

    getStats() {
      if (!db) return { users: 0, operations: 0, merkleRoot: '—', dbId: '—' };
      const indexData = db.data.get('users:index');
      const userCount = indexData ? JSON.parse(indexData).length : 0;
      return {
        users: userCount,
        operations: db.opCount,
        merkleRoot: db.merkleRoot.slice(0, 16) + '…',
        dbId: db.id.slice(0, 16) + '…',
      };
    },
  };
})();


// ---------- App State ----------

let currentView = 'auth'; // 'auth' | 'dashboard'
let authMode = 'login';   // 'login' | 'register'
let currentUser = null;
let isLoading = false;

// ---------- DOM Helpers ----------

function $(sel) { return document.querySelector(sel); }
function $$(sel) { return document.querySelectorAll(sel); }

function show(el) { el.style.display = ''; }
function hide(el) { el.style.display = 'none'; }

// ---------- Rendering ----------

function render() {
  const main = $('#main-content');
  if (currentView === 'auth') {
    renderAuth(main);
  } else {
    renderDashboard(main);
  }
  updateNav();
}

function updateNav() {
  $$('.header-nav button').forEach(btn => btn.classList.remove('active'));
  if (currentView === 'auth') {
    if (authMode === 'login') {
      $('#nav-signin')?.classList.add('active');
    } else {
      $('#nav-signup')?.classList.add('active');
    }
  } else {
    $('#nav-dashboard')?.classList.add('active');
  }
}

function renderAuth(container) {
  if (authMode === 'login') {
    container.innerHTML = `
      <div class="auth-card" id="auth-card">
        <h2 class="auth-card-title">Welcome Back</h2>
        <p class="auth-card-subtitle">Sign in to your VeilDB-secured account</p>
        <div id="auth-alert"></div>
        <form id="login-form" autocomplete="off">
          <div class="form-group">
            <label class="form-label" for="login-username">Username</label>
            <input class="form-input" id="login-username" type="text" placeholder="Enter your username" required />
          </div>
          <div class="form-group">
            <label class="form-label" for="login-password">Password</label>
            <input class="form-input" id="login-password" type="password" placeholder="Enter your password" required />
          </div>
          <button type="submit" class="btn btn-primary" id="login-btn">
            Sign In
          </button>
        </form>
        <p class="toggle-link">
          Don't have an account? <a id="switch-to-register">Create one</a>
        </p>
      </div>
    `;

    $('#login-form').addEventListener('submit', handleLogin);
    $('#switch-to-register').addEventListener('click', () => {
      authMode = 'register';
      render();
    });
  } else {
    container.innerHTML = `
      <div class="auth-card" id="auth-card">
        <h2 class="auth-card-title">Create Account</h2>
        <p class="auth-card-subtitle">Your credentials are encrypted in VeilDB</p>
        <div id="auth-alert"></div>
        <form id="register-form" autocomplete="off">
          <div class="form-group">
            <label class="form-label" for="reg-username">Username</label>
            <input class="form-input" id="reg-username" type="text" placeholder="Choose a username" required minlength="3" />
          </div>
          <div class="form-group">
            <label class="form-label" for="reg-email">Email</label>
            <input class="form-input" id="reg-email" type="email" placeholder="you@example.com" required />
          </div>
          <div class="form-group">
            <label class="form-label" for="reg-role">Role</label>
            <select class="form-select" id="reg-role">
              <option value="user">User</option>
              <option value="admin">Admin</option>
              <option value="moderator">Moderator</option>
            </select>
          </div>
          <div class="form-group">
            <label class="form-label" for="reg-password">Password</label>
            <input class="form-input" id="reg-password" type="password" placeholder="Create a strong password" required minlength="4" />
            <div class="password-strength" id="pw-strength">
              <div class="password-strength-bar" id="pw-bar-1"></div>
              <div class="password-strength-bar" id="pw-bar-2"></div>
              <div class="password-strength-bar" id="pw-bar-3"></div>
              <div class="password-strength-bar" id="pw-bar-4"></div>
            </div>
            <span class="password-strength-label" id="pw-label"></span>
          </div>
          <button type="submit" class="btn btn-primary" id="register-btn">
            Create Account
          </button>
        </form>
        <p class="toggle-link">
          Already have an account? <a id="switch-to-login">Sign in</a>
        </p>
      </div>
    `;

    $('#register-form').addEventListener('submit', handleRegister);
    $('#switch-to-login').addEventListener('click', () => {
      authMode = 'login';
      render();
    });
    $('#reg-password').addEventListener('input', updatePasswordStrength);
  }
}

async function renderDashboard(container) {
  const stats = VeilDB.getStats();
  const users = await VeilDB.listUsers();

  const userRows = users.map((u, i) => {
    const colors = ['#3b82f6', '#8b5cf6', '#22c55e', '#f59e0b', '#ef4444', '#06b6d4'];
    const color = colors[i % colors.length];
    const initial = u.username.charAt(0).toUpperCase();
    const roleClass = `role-${u.role}`;
    const date = new Date(u.createdAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });

    return `
      <tr>
        <td>
          <div style="display:flex;align-items:center;gap:0.75rem">
            <span class="user-avatar" style="background:${color}">${initial}</span>
            <div>
              <div style="font-weight:500">${escapeHtml(u.username)}</div>
              <div style="font-size:0.75rem;color:var(--text-muted)">${escapeHtml(u.email)}</div>
            </div>
          </div>
        </td>
        <td><span class="user-badge ${roleClass}">${escapeHtml(u.role)}</span></td>
        <td style="color:var(--text-secondary)">${date}</td>
        <td>
          <button class="btn btn-danger btn-sm delete-user-btn" data-username="${escapeHtml(u.username)}">Delete</button>
        </td>
      </tr>
    `;
  }).join('');

  container.innerHTML = `
    <div class="dashboard-container">
      <div class="dashboard-header">
        <div>
          <h2 class="dashboard-title">Dashboard</h2>
          <p class="dashboard-welcome">Welcome back, <strong>${escapeHtml(currentUser.username)}</strong></p>
        </div>
        <div style="display:flex;gap:0.5rem;align-items:center">
          <span class="user-badge role-${currentUser.role}">${escapeHtml(currentUser.role)}</span>
          <button class="btn btn-secondary btn-sm" id="logout-btn">Sign Out</button>
        </div>
      </div>

      <div id="dashboard-alert"></div>

      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-label">Total Users</div>
          <div class="stat-value">${stats.users}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Operations</div>
          <div class="stat-value">${stats.operations}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Merkle Root</div>
          <div class="stat-value" style="font-size:0.9rem;font-family:monospace">${stats.merkleRoot}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Database ID</div>
          <div class="stat-value" style="font-size:0.9rem;font-family:monospace">${stats.dbId}</div>
        </div>
      </div>

      <div class="users-section">
        <h3 class="users-section-title">📋 Stored Users</h3>
        ${users.length === 0 ? `
          <div class="empty-state">
            <div class="empty-state-icon">👤</div>
            <p class="empty-state-text">No users registered yet. Create your first account!</p>
          </div>
        ` : `
          <table class="users-table">
            <thead>
              <tr>
                <th>User</th>
                <th>Role</th>
                <th>Created</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              ${userRows}
            </tbody>
          </table>
        `}
      </div>
    </div>
  `;

  $('#logout-btn').addEventListener('click', handleLogout);
  $$('.delete-user-btn').forEach(btn => {
    btn.addEventListener('click', () => handleDeleteUser(btn.dataset.username));
  });
}

// ---------- Event Handlers ----------

async function handleLogin(e) {
  e.preventDefault();
  const username = $('#login-username').value.trim();
  const password = $('#login-password').value;

  if (!username || !password) {
    showAlert('auth-alert', 'Please fill in all fields', 'error');
    return;
  }

  setButtonLoading('login-btn', true);

  try {
    // Make sure DB is initialized
    if (!VeilDB.isOpen()) {
      await VeilDB.init('demo-app', 'demo-passphrase');
    }

    const result = await VeilDB.signIn(username, password);
    currentUser = result.user;
    currentView = 'dashboard';
    render();
  } catch (err) {
    showAlert('auth-alert', err.message, 'error');
  } finally {
    setButtonLoading('login-btn', false);
  }
}

async function handleRegister(e) {
  e.preventDefault();
  const username = $('#reg-username').value.trim();
  const email = $('#reg-email').value.trim();
  const password = $('#reg-password').value;
  const role = $('#reg-role').value;

  if (!username || !email || !password) {
    showAlert('auth-alert', 'Please fill in all fields', 'error');
    return;
  }

  if (username.length < 3) {
    showAlert('auth-alert', 'Username must be at least 3 characters', 'error');
    return;
  }

  setButtonLoading('register-btn', true);

  try {
    // Make sure DB is initialized
    if (!VeilDB.isOpen()) {
      await VeilDB.init('demo-app', 'demo-passphrase');
    }

    const result = await VeilDB.createUser(username, email, password, role);
    currentUser = result.user;

    showAlert('auth-alert', `Account created for ${username}! Redirecting…`, 'success');
    setTimeout(() => {
      currentView = 'dashboard';
      render();
    }, 1200);
  } catch (err) {
    showAlert('auth-alert', err.message, 'error');
  } finally {
    setButtonLoading('register-btn', false);
  }
}

function handleLogout() {
  currentUser = null;
  currentView = 'auth';
  authMode = 'login';
  render();
}

async function handleDeleteUser(username) {
  if (username === currentUser?.username) {
    showAlert('dashboard-alert', 'Cannot delete your own account while logged in', 'error');
    return;
  }

  try {
    await VeilDB.deleteUser(username);
    showAlert('dashboard-alert', `User "${username}" deleted`, 'info');
    // Re-render after a moment
    setTimeout(() => render(), 400);
  } catch (err) {
    showAlert('dashboard-alert', err.message, 'error');
  }
}

// ---------- Helpers ----------

function showAlert(containerId, message, type) {
  const container = $(`#${containerId}`);
  if (!container) return;
  const icon = type === 'success' ? '✓' : type === 'error' ? '✕' : 'ℹ';
  container.innerHTML = `<div class="alert alert-${type}">${icon} ${escapeHtml(message)}</div>`;
  setTimeout(() => {
    if (container.querySelector('.alert')) {
      container.innerHTML = '';
    }
  }, 5000);
}

function setButtonLoading(btnId, loading) {
  const btn = $(`#${btnId}`);
  if (!btn) return;
  if (loading) {
    btn.classList.add('btn-loading');
    btn.dataset.originalText = btn.textContent;
    btn.innerHTML = '<span class="spinner"></span> Processing…';
  } else {
    btn.classList.remove('btn-loading');
    btn.textContent = btn.dataset.originalText || btn.textContent;
  }
}

function updatePasswordStrength() {
  const password = $('#reg-password').value;
  let strength = 0;
  if (password.length >= 4) strength++;
  if (password.length >= 8) strength++;
  if (/[A-Z]/.test(password) && /[0-9]/.test(password)) strength++;
  if (/[^A-Za-z0-9]/.test(password) && password.length >= 10) strength++;

  const labels = ['', 'Weak', 'Fair', 'Good', 'Strong'];
  const classes = ['', 'weak', 'medium', 'medium', 'strong'];

  for (let i = 1; i <= 4; i++) {
    const bar = $(`#pw-bar-${i}`);
    if (i <= strength) {
      bar.classList.add('active', classes[strength]);
    } else {
      bar.className = 'password-strength-bar';
    }
  }
  $('#pw-label').textContent = labels[strength];
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ---------- Nav Events ----------

function setupNav() {
  $('#nav-signin').addEventListener('click', () => {
    authMode = 'login';
    currentView = 'auth';
    render();
  });

  $('#nav-signup').addEventListener('click', () => {
    authMode = 'register';
    currentView = 'auth';
    render();
  });

  $('#nav-dashboard').addEventListener('click', () => {
    if (currentUser) {
      currentView = 'dashboard';
      render();
    } else {
      authMode = 'login';
      currentView = 'auth';
      render();
      showAlert('auth-alert', 'Please sign in first', 'info');
    }
  });
}

// ---------- Init ----------

async function initApp() {
  // Pre-initialize the VeilDB mock
  await VeilDB.init('demo-app', 'demo-passphrase');

  setupNav();
  render();
}

document.addEventListener('DOMContentLoaded', initApp);
