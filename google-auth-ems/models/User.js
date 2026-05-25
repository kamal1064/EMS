const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  googleId: {
    type: String,
    required: true,
    unique: true
  },
  name: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true,
    unique: true
  },
  avatar: {
    type: String
  },
  role: {
    type: String,
    enum: ['Admin', 'Employee'],
    default: 'Employee'
  },
  lastLogin: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true // Auto-adds createdAt and updatedAt fields
});

module.exports = mongoose.model('User', UserSchema);
