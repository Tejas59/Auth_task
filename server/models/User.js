const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true, 
  },
  password: {
    type: String,
    required: true,
  },
  loginAttempts: {
    type: Number,
    default: 0,
  },
  lastLoginAttempt: {
    type: Date,
    default: null,
  },
  lockedUntil: {
    type: Date,
    default: null,
  },
  role: {
    type: String,
    default: 'visitor',
  },
});


userSchema.pre('save', async function (next) {
  if (this.isModified('password')) {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
  }
  next();
});

userSchema.statics.updateLoginAttemptsAndCheckLock = async function (email, password) {
  try {
    const now = new Date();
    const lockoutThreshold = 3; 
    const lockoutPeriod = 24 * 60 * 60 * 1000;

    const user = await this.findOne({ email });

    if (!user) {
     
      return null; 
    }

   
    const isMatch = await bcrypt.compare(password, user.password);
    if (isMatch) {
      user.loginAttempts = 0;
      user.lockedUntil = null;
      await user.save();
      return user; 
    }

    user.loginAttempts = user.loginAttempts + 1; 
    user.lastLoginAttempt = now;

    if (user.loginAttempts >= lockoutThreshold) {
      const twelveHoursAgo = now.getTime() - (12 * 60 * 60 * 1000); 

      
      if (user.lastLoginAttempt.getTime() > twelveHoursAgo) {
        user.lockedUntil = new Date(now.getTime() + lockoutPeriod); 
      }
    }

    await user.save();

    if (user.lockedUntil) {
     
      return { status: 'locked', message: 'Account is locked due to multiple failed attempts.' };
    } else {
     
      return { status: 'failed', message: 'Incorrect password.' };
    }
  } catch (err) {
    console.error("Error updating login attempts:", err);
    throw err; 
  }
};

module.exports = mongoose.model('User', userSchema);
