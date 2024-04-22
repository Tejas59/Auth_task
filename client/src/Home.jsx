import React from 'react';

const Home = () => {
    const name = localStorage.getItem('name');

    return (
        <div>
            <h2>Welcome, {name}</h2>
        </div>
    );
};

export default Home;
