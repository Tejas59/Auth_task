import React, { useState } from 'react';
import "bootstrap/dist/css/bootstrap.min.css";
import axios from "axios";
import { Link, useNavigate } from "react-router-dom";

const Login = () => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const navigate = useNavigate();

    const handleSubmit = (e) => {
        e.preventDefault();
        axios.post("http://localhost:3001/login", { email, password })
            .then((res) => {
                if (res.data.status === "success") {
                    localStorage.setItem('name', res.data.name); // Store the user's name in localStorage
                    navigate('/'); // Redirect to the home page
                }
            })
            .catch((err) => console.log(err));
    };

    return (
        <div className="d-flex justify-content-center align-items-center bg-secondary vh-100">
            <div className="bg-white p-3 rounded w-25">
                <h2>Login</h2>
                <form onSubmit={handleSubmit}>
                    <div className="mb-3">
                        <label htmlFor="email"><strong>E-mail</strong></label>
                        <input type="email" placeholder="Enter Email" autoComplete="off" name="email" className="form-control rounded-0" onChange={(e) => setEmail(e.target.value)} />
                    </div>
                    <div className="mb-3">
                        <label htmlFor="email"><strong>Password</strong></label>
                        <input type="password" placeholder="Enter Password" autoComplete="off" name="password" className="form-control rounded-0" onChange={(e) => setPassword(e.target.value)} />
                    </div>
                    <button type="submit" className="btn btn-success w-100 rounded-0">Login</button>
                    <p>Don't have an account</p>
                    <Link to='/register' className="btn btn-light w-100 rounded-0">Register</Link>
                </form>
            </div>
        </div>
    )
}

export default Login;
