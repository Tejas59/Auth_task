const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const UserModel = require("./models/User.js");

const app = express();

app.use(express.json());

app.use(cors({
  origin: ["http://localhost:5173"],
  methods: ["GET", "POST"],
  credentials: true,
}));

app.use(cookieParser());

mongoose
  .connect("mongodb://127.0.0.1:27017/auth_mern", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

app.post("/register", (req, res) => {
  const { name, email, password } = req.body;

  console.log("Received registration request:", { name, email, password });

  bcrypt
    .hash(password, 10)
    .then((hash) => {
      console.log("Generated hash:", hash);
      UserModel.create({ name, email, password: hash })
        .then((user) => {
          console.log("User registered successfully:", user);
          res.json("success");
        })
        .catch((err) => {
          console.error("Error registering user:", err);
          res.status(500).json({ error: "Error registering user" });
        });
    })
    .catch((err) => {
      console.error("Error hashing password:", err);
      res.status(500).json({ error: "Error hashing password" });
    });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await UserModel.findOne({ email: email });

    if (user) {
      const isMatch = await bcrypt.compare(password, user.password);

      if (isMatch) {
        const token = jwt.sign({ email: user.email, role: user.role }, "jwt-secret-key", { expiresIn: '1d' });
        res.cookie('token', token);
        return res.json({ status: "success", role: user.role, name: user.name });
      } else {
        await updateLoginAttempts(email);
        const isLocked = await checkAccountLock(email);
        if (isLocked) {
          console.error("Account is locked:", user.email);
          return res.json({ status: "locked", message: "Account is locked due to multiple failed attempts.", lockedUntil: user.lockedUntil });
        } else {
          console.log("Account is not locked:", user.email);
          return res.json({ status: "failed", message: "Incorrect password." });
        }
      }
    } else {
      return res.json({ status: "failed", message: "No account found with that email." });
    }
  } catch (err) {
    console.error("Error logging in:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

const updateLoginAttempts = async (email) => {
  try {
    const now = new Date();
    const twelveHoursAgo = now.getTime() - (12 * 60 * 60 * 1000); // Calculate 12 hours in milliseconds

    const user = await UserModel.findOneAndUpdate(
      { email },
      {
        $inc: { loginAttempts: 1 },
        $set: { lastLoginAttempt: now },
      },
      { new: true } 
    );

    if (user.loginAttempts > 5 && user.lastLoginAttempt.getTime() > twelveHoursAgo) {
      await UserModel.findOneAndUpdate({ email }, { lockedUntil: new Date(now.getTime() + (24 * 60 * 60 * 1000)) }); // Lock for 24 hours
    }
  } catch (err) {
    console.error("Error updating login attempts:", err);
  }
};


    
const checkAccountLock = async (email) => {
    try {
      const now = new Date();
      const user = await UserModel.findOne({ email });
  
      if (user && user.lockedUntil) {
        return user.lockedUntil.getTime() > now.getTime(); 
      } else if (user && user.loginAttempts >= 5 && user.lastLoginAttempt) {
        const twelveHoursAgo = now.getTime() - (12 * 60 * 60 * 1000); 
        return user.lastLoginAttempt.getTime() > twelveHoursAgo; 
      } else {
        return false; 
      }
    } catch (err) {
      console.error("Error checking account lock:", err);
      return false; 
    }
  };
    
    
    const PORT = process.env.PORT || 3001;
    app.listen(PORT, () => {
      console.log(`Server is running on port ${PORT}`);
    });
    