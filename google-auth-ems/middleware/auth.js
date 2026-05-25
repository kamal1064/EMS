module.exports = {
  // Guard middleware to ensure request is from an authenticated session
  ensureAuth: function(req, res, next) {
    if (req.isAuthenticated()) {
      return next();
    }
    // If it's an AJAX/API call, respond with 401, otherwise redirect to login page
    if (req.originalUrl.startsWith('/api/')) {
      return res.status(401).json({ success: false, message: 'Unauthorized session.' });
    }
    res.redirect('/login.html');
  },

  // Guard middleware to ensure already authenticated users are fast-tracked past the login screen
  ensureGuest: function(req, res, next) {
    if (!req.isAuthenticated()) {
      return next();
    }
    res.redirect('/dashboard.html');
  }
};
