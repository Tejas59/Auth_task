import React, { useState, useEffect } from 'react';
import axios from "axios";
import { Link, useNavigate } from "react-router-dom";

const Login = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const navigate = useNavigate();

  const [loginAttempts, setLoginAttempts] = useState(0); 
  const [isAccountLocked, setIsAccountLocked] = useState(false);
  const [lockedUntil, setLockedUntil] = useState(null); 
  const [loginError, setLoginError] = useState(null); // State to store login error message

  useEffect(() => {
    const storedLockedUntil = localStorage.getItem('lockedUntil');
    if (storedLockedUntil) {
      const now = new Date();
      const lockExpiry = new Date(storedLockedUntil);
      if (now < lockExpiry) {
        setIsAccountLocked(true);
        setLockedUntil(lockExpiry);
      }
    }
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (isAccountLocked) {
      const now = new Date();
      if (now >= lockedUntil) {
        setIsAccountLocked(false);
        setLockedUntil(null);
        setLoginAttempts(0); // Reset attempts after lock expiry
      } else {
        alert("Your account is locked due to multiple failed login attempts. Please try again later.");
        return;
      }
    }

    setLoginAttempts(loginAttempts + 1); // Increment login attempts

    try {
      const { data } = await axios.post("http://localhost:3001/", {
        email,
        password,
      });

      if (data.status === "success") {
        localStorage.setItem('name', data.name);
        navigate('/home');
      } else if (data.status === "locked") {
        setIsAccountLocked(true);
        setLockedUntil(new Date(data.lockedUntil)); 
        alert("Your account is locked due to multiple failed login attempts. Please try again later.");
      } else {
        // Display error message for incorrect password
        setLoginError("Incorrect email or password. Please try again.");
        console.log("Login failed:", data.message); 
      }
    } catch (err) {
      // Handle 403 Forbidden error
      if (err.response && err.response.status === 403) {
        setLoginError("Your account is locked due to multiple failed login attempts. Please try again later.");
      } else {
        setLoginError("An unexpected error occurred. Please try again later.");
      }
      console.error("Error logging in:", err);
    }
  };

  return (
    <div className="d-flex justify-content-center align-items-center bg-info vh-100">
      <div className="bg-white p-3 rounded w-25">
        <h2>Login</h2>
        {isAccountLocked && ( // Display alert only if account is locked
          <div className="alert alert-danger" role="alert">
            Your account is locked. Please try again later.
          </div>
        )}
        {loginError && ( // Display login error message
          <div className="alert alert-danger" role="alert">
            {loginError}
          </div>
        )}
        <form onSubmit={handleSubmit}>
          <div className="mb-3">
            <label htmlFor="email"><strong>E-mail</strong></label>
            <input
              type="email"
              placeholder="Enter Email"
              autoComplete="off"
              name="email"
              className="form-control rounded-0"
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>
          <div className="mb-3">
            <label htmlFor="email"><strong>Password</strong></label>
            <input
              type="password"
              placeholder="Enter Password"
              autoComplete="off"
              name="password"
              className="form-control rounded-0"
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          <button type="submit" className="btn btn-success w-100 rounded-0">Login</button>
          <p>Don't have an account</p>
          <Link to='/register' className="btn btn-light w-100 rounded-0">Register</Link>
        </form>
      </div>
    </div>
  );
};

export default Login;
