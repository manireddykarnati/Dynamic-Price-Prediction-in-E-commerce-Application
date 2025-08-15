const mysql = require('mysql2');
require('dotenv').config();



const db = mysql.createConnection({
    host: process.env.DB_HOST || '127.0.0.1',

    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASS || 'mani@2004',
    database: process.env.DB_NAME || 'ecommerce_db'
});

db.connect((err) => {
    if (err) {
        console.error('Database connection failed:', err);
        return;
    }
    console.log('Connected to MySQL database');
});

module.exports = db;