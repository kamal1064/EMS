const express = require('express');
const passport = require('passport');
const router = express.Router();

// @desc    Authenticate with Google OAuth
// @route   GET /auth/google
router.get(
  '/google',
  (req, res, next) => {
    const clientId = process.env.GOOGLE_CLIENT_ID;
    const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
    
    // Check if Google credentials are missing or still set to placeholder template values
    const hasGoogleCreds = clientId && 
                           clientId !== 'your-google-client-id.apps.googleusercontent.com' &&
                           clientId.trim() !== '' &&
                           clientSecret &&
                           clientSecret !== 'GOCSPX-your-google-client-secret' &&
                           clientSecret.trim() !== '';

    if (!hasGoogleCreds) {
      console.log('⚠️ GOOGLE OAUTH KEYS NOT SET: Activating Local Developer Sandbox Mode...');
      return next();
    }
    passport.authenticate('google', { scope: ['profile', 'email'] })(req, res, next);
  },
  async (req, res) => {
    // Dynamic fallback sandbox mock user login bypass
    try {
      const User = require('../models/User');
      let user = await User.findOne({ googleId: 'sandbox_developer_mock_id' });
      if (!user) {
        user = await User.create({
          googleId: 'sandbox_developer_mock_id',
          name: 'Developer Sandbox',
          email: 'sandbox.dev@company.com',
          avatar: 'https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?auto=format&fit=crop&w=150&h=150&q=80',
          role: 'Admin',
          lastLogin: new Date()
        });
      } else {
        user.lastLogin = new Date();
        await user.save();
      }
      
      req.login(user, (err) => {
        if (err) return res.redirect('/login.html?error=sandbox_failed');
        res.redirect('/dashboard.html?mode=sandbox');
      });
    } catch (err) {
      console.error('Sandbox login bypass error:', err);
      res.redirect('/login.html?error=sandbox_failed');
    }
  }
);

// @desc    Google OAuth Callback
// @route   GET /auth/google/callback
router.get(
  '/google/callback',
  passport.authenticate('google', { failureRedirect: '/login.html?error=oauth_failed' }),
  (req, res) => {
    // Successful authentication, redirect to dashboard.
    res.redirect('/dashboard.html');
  }
);

// @desc    Logout User
// @route   GET /auth/logout
router.get('/logout', (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    
    // Destroy the session in store
    req.session.destroy((destroyErr) => {
      if (destroyErr) {
        console.error('Session Destruction Error:', destroyErr);
      }
      // Clear session cookie
      res.clearCookie('connect.sid');
      // Redirect to login page
      res.redirect('/login.html?logout=success');
    });
  });
});

module.exports = router;
