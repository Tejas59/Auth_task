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
    origin:["http://localhost:5173"],
    methods:["GET", "post"],
    credentials: true
}));

app.use(cookieParser());

mongoose
  .connect("mongodb://127.0.0.1:27017/auth_two", {
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

app.post("/login", (req, res) => {
  const { email, password } = req.body;
  UserModel.findOne({ email: email }).then((user) => {
    if (user) {
      if (user.lockedUntil && user.lockedUntil > Date.now()) {
        // Account is locked
        const remainingTime = new Date(user.lockedUntil - Date.now());
        return res.status(403).json({
          message: `Account is locked. Please try again after ${remainingTime.getHours()} hours, ${remainingTime.getMinutes()} minutes, and ${remainingTime.getSeconds()} seconds.`,
        });
      }
      bcrypt.compare(password, user.password, (err, response) => {
        if (response) {
          UserModel.findOneAndUpdate({ email }, { loginAttempts: 0 })
            .then(() => {
              const token = jwt.sign(
                { email: user.email, role: user.role },
                "jwt-secret-key",
                { expiresIn: "1d" }
              );
              res.cookie("token", token);
              return res.json({
                status: "success",
                role: user.role,
                name: user.name,
              });
            })
            .catch((err) => {
              console.error("Error updating login attempts:", err);
              return res.status(500).json({
                error: "Internal server error",
              });
            });
        } else {
          UserModel.findOneAndUpdate(
            { email },
            { $inc: { loginAttempts: 1 }, lastLoginAttempt: Date.now() },
            { new: true }
          )
            .then((updatedUser) => {
              if (updatedUser.loginAttempts >= 5) {
                const lockExpiry = new Date(
                  Date.now() + 24 * 60 * 60 * 1000
                ); 
                UserModel.findOneAndUpdate(
                  { email },
                  { lockedUntil: lockExpiry }
                )
                  .then(() => {
                    return res.status(403).json({
                      message: "Account locked, please try again later.",
                    });
                  })
                  .catch((err) => {
                    console.error("Error locking account:", err);
                    return res.status(500).json({
                      error: "Internal server error",
                    });
                  });
              } else {
                return res.json("The password is incorrect");
              }
            })
            .catch((err) => {
              console.error("Error updating login attempts:", err);
              return res.status(500).json({
                error: "Internal server error",
              });
            });
        }
      });
    } else {
      return res.json("No record existed");
    }
  });
});

  
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
