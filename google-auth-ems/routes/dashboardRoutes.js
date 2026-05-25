const express = require('express');
const router = express.Router();
const { ensureAuth } = require('../middleware/auth');
const authController = require('../controllers/authController');

// @desc    Get logged in user profile details
// @route   GET /api/user/profile
router.get('/user/profile', ensureAuth, authController.getUserProfile);

module.exports = router;
