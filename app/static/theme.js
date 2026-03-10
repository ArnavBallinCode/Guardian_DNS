/* ── Guardian DNS — Shared Theme JS ── */

(function () {
  // Read saved preference or default to 'dark'
  const stored = localStorage.getItem('guardian_theme') || 'dark';
  document.documentElement.setAttribute('data-theme', stored);

  window.toggleTheme = function () {
    const current = document.documentElement.getAttribute('data-theme') || 'dark';
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('guardian_theme', next);
    document.querySelectorAll('.theme-toggle').forEach(btn => {
      btn.textContent = next === 'dark' ? '☀️' : '🌙';
    });
  };

  document.addEventListener('DOMContentLoaded', function () {
    const theme = document.documentElement.getAttribute('data-theme') || 'dark';
    document.querySelectorAll('.theme-toggle').forEach(btn => {
      btn.textContent = theme === 'dark' ? '☀️' : '🌙';
    });
  });

  // ── Auth guard helper ──
  window.guardianAuth = {
    getToken: function () { return localStorage.getItem('guardian_token') || ''; },
    getUser: function () {
      try { return JSON.parse(localStorage.getItem('guardian_user') || '{}'); } catch (e) { return {}; }
    },
    headers: function () {
      return { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + this.getToken() };
    },
    signout: function () {
      fetch('/auth/signout', { method: 'POST', headers: this.headers() }).finally(function () {
        localStorage.removeItem('guardian_token');
        localStorage.removeItem('guardian_user');
        window.location.href = '/ui/login';
      });
    },
    // Check auth and redirect if not authenticated or wrong role.
    // Page body is hidden until auth is confirmed to prevent flicker.
    requireRole: function (requiredRole) {
      var token = this.getToken();
      if (!token) {
        window.location.replace('/ui/login?next=' + encodeURIComponent(window.location.pathname));
        return;
      }
      fetch('/auth/me', { headers: this.headers() })
        .then(function (res) {
          if (!res.ok) throw new Error('unauthorized');
          return res.json();
        })
        .then(function (data) {
          if (requiredRole && data.role !== requiredRole) {
            // Wrong role — redirect to login with a message
            window.location.replace('/ui/login?error=wrong_role&next=' + encodeURIComponent(window.location.pathname));
            return;
          }
          localStorage.setItem('guardian_user', JSON.stringify(data));
          // Show the page now that auth is confirmed
          document.body.classList.add('auth-ready');
          if (window._onAuthReady) window._onAuthReady(data);
        })
        .catch(function () {
          localStorage.removeItem('guardian_token');
          localStorage.removeItem('guardian_user');
          window.location.replace('/ui/login?next=' + encodeURIComponent(window.location.pathname));
        });
    }
  };
})();
