const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true
  },
  password: {
    type: String,
    required: true
  },
  loginAttempts: {
    type: Number,
    default: 0
  },
  lastLoginAttempt: {
    type: Date,
    default: null
  },
  lockedUntil: {
    type: Date,
    default: null
  },
  role:{
    type: String,
    default: 'visitor'
  }
});

module.exports = mongoose.model('User', userSchema);
