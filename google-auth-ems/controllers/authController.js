// Controller to fetch serialized profile details for the front-end dashboard
exports.getUserProfile = (req, res) => {
  if (!req.user) {
    return res.status(401).json({ success: false, message: 'Unauthorized session.' });
  }

  // Pick only necessary parameters to return to client
  res.json({
    success: true,
    user: {
      id: req.user._id,
      googleId: req.user.googleId,
      name: req.user.name,
      email: req.user.email,
      avatar: req.user.avatar,
      role: req.user.role,
      lastLogin: req.user.lastLogin,
      createdAt: req.user.createdAt
    }
  });
};
