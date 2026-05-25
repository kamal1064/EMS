document.addEventListener('DOMContentLoaded', () => {
  // Initialize dark/light mode state
  initTheme();

  // Handle mobile navbar toggles
  initMobileNavigation();

  // Intercept profile dropdown triggers
  initProfileDropdown();

  // Load and render user profile session details if on the dashboard page
  if (window.location.pathname.endsWith('dashboard.html') || window.location.pathname === '/' || window.location.pathname.endsWith('dashboard')) {
    loadUserProfile();
  }

  // Intercept login callbacks and parse toast parameters
  checkUrlParams();
});

/* ── THEME INITIALIZATION & TOGGLE ── */
function initTheme() {
  const toggleSwitch = document.querySelector('.theme-switch input[type="checkbox"]');
  const currentTheme = localStorage.getItem('theme') || 'light';

  if (currentTheme) {
    document.documentElement.setAttribute('data-theme', currentTheme);
    if (currentTheme === 'dark' && toggleSwitch) {
      toggleSwitch.checked = true;
    }
  }

  if (toggleSwitch) {
    toggleSwitch.addEventListener('change', (e) => {
      if (e.target.checked) {
        document.documentElement.setAttribute('data-theme', 'dark');
        localStorage.setItem('theme', 'dark');
        showToast('Dark theme activated ✓', 'success');
      } else {
        document.documentElement.setAttribute('data-theme', 'light');
        localStorage.setItem('theme', 'light');
        showToast('Light theme activated ✓', 'success');
      }
    });
  }
}

/* ── MOBILE VIEWPORT SIDEBAR INTERACTION ── */
function initMobileNavigation() {
  const sidebar = document.querySelector('.sidebar');
  const toggleBtn = document.getElementById('mobile-toggle');
  const closeBtn = document.getElementById('sidebar-close');

  if (toggleBtn && sidebar) {
    toggleBtn.addEventListener('click', () => {
      sidebar.classList.add('open');
    });
  }

  if (closeBtn && sidebar) {
    closeBtn.addEventListener('click', () => {
      sidebar.classList.remove('open');
    });
  }
}

/* ── PROFILE DROPDOWN MANAGER ── */
function initProfileDropdown() {
  const trigger = document.getElementById('profile-trigger');
  const dropdown = document.getElementById('profile-dropdown');

  if (trigger && dropdown) {
    trigger.addEventListener('click', (e) => {
      e.stopPropagation();
      dropdown.classList.toggle('show');
    });

    document.addEventListener('click', (e) => {
      if (!trigger.contains(e.target) && !dropdown.contains(e.target)) {
        dropdown.classList.remove('show');
      }
    });
  }
}

/* ── GOOGLE AUTHENTICATION INITIATION SPINNER ── */
function handleGoogleLogin(button) {
  const originalContent = button.innerHTML;
  
  // Disable button and inject modern loading spinner
  button.style.pointerEvents = 'none';
  button.style.opacity = '0.7';
  button.innerHTML = `
    <svg class="animate-spin" style="width:20px;height:20px;margin-right:10px;animation: spin 1s linear infinite;" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <circle cx="12" cy="12" r="10" stroke="#cbd5e1" stroke-width="4" style="opacity:0.25;"></circle>
      <path fill="#0f172a" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
    </svg>
    Connecting securely...
  `;

  const spinnerWrapper = document.getElementById('loading-wrapper');
  if (spinnerWrapper) {
    spinnerWrapper.style.display = 'flex';
  }

  // Redirect to backend OAuth route
  setTimeout(() => {
    window.location.href = '/auth/google';
  }, 800);
}

/* ── LOAD SESSION PROFILE FROM SERVER ── */
function loadUserProfile() {
  fetch('/api/user/profile')
    .then((response) => {
      if (response.status === 401) {
        throw new Error('Unauthorized');
      }
      return response.json();
    })
    .then((data) => {
      if (data.success && data.user) {
        renderDashboardData(data.user);
      } else {
        window.location.href = '/login.html';
      }
    })
    .catch((err) => {
      console.warn('Authentication status: Unverified session, redirecting...');
      window.location.href = '/login.html';
    });
}

/* ── RENDER DATA ON DASHBOARD SCREEN ── */
function renderDashboardData(user) {
  // Populate Navbars and Headers
  const avatarElements = document.querySelectorAll('.google-avatar');
  avatarElements.forEach((img) => {
    img.src = user.avatar || 'https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?auto=format&fit=crop&w=150&h=150&q=80';
  });

  const usernameElements = document.querySelectorAll('.user-display-name');
  usernameElements.forEach((el) => {
    el.textContent = user.name;
  });

  const dropdownEmail = document.getElementById('dropdown-email');
  if (dropdownEmail) dropdownEmail.textContent = user.email;

  // Render role badges
  const roleBadge = document.getElementById('user-role-badge');
  if (roleBadge) {
    roleBadge.textContent = user.role;
    roleBadge.className = `role-pill role-${user.role.toLowerCase()}`;
  }

  // Render profile panel rows
  const profileRowsMap = {
    'profile-id': user.id,
    'profile-google-id': user.googleId,
    'profile-name': user.name,
    'profile-email': user.email,
    'profile-role': user.role,
    'profile-created-at': new Date(user.createdAt).toLocaleString(),
    'profile-last-login': new Date(user.lastLogin).toLocaleString()
  };

  for (const [id, value] of Object.entries(profileRowsMap)) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
  }

  // Greet user
  const welcomeText = document.getElementById('welcome-greet');
  if (welcomeText) {
    const hours = new Date().getHours();
    let greet = 'Good evening';
    if (hours < 12) greet = 'Good morning';
    else if (hours < 18) greet = 'Good afternoon';
    
    welcomeText.textContent = `${greet}, ${user.name.split(' ')[0]}!`;
  }
}

/* ── READ URL QUERY PARAMETERS FOR NOTIFICATIONS ── */
function checkUrlParams() {
  const urlParams = new URLSearchParams(window.location.search);
  
  if (urlParams.get('logout') === 'success') {
    showToast('Session terminated successfully.', 'success');
  }
  if (urlParams.get('error') === 'oauth_failed') {
    showToast('Failed to verify Google account, try again.', 'danger');
  }
  if (urlParams.get('mode') === 'sandbox') {
    showToast('Logged in via Developer Sandbox Mode.', 'warning');
  }
  if (urlParams.get('error') === 'sandbox_failed') {
    showToast('Failed to authenticate sandbox profile.', 'danger');
  }
}

/* ── FLOATING TOAST NOTIFIER ── */
function showToast(message, type = 'success') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  
  let icon = '<i class="bi bi-check-circle-fill"></i>';
  if (type === 'danger') icon = '<i class="bi bi-exclamation-triangle-fill"></i>';
  if (type === 'warning') icon = '<i class="bi bi-exclamation-circle-fill"></i>';

  toast.innerHTML = `${icon} <span>${message}</span>`;
  container.appendChild(toast);

  // Remove toast dynamically after 4s
  setTimeout(() => {
    toast.style.animation = 'slideIn 0.3s ease reverse both';
    setTimeout(() => {
      toast.remove();
    }, 300);
  }, 4000);
}
