const express = require('express');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const multer = require('multer');
const path = require('path');
const db = require('./db');

dotenv.config(); // Load environment variables

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

global.otpStorage = {}; // Temporary OTP storage (Consider DB in production)

// ✅ Authentication Middleware
const verifyToken = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ message: 'Access Denied' });

    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET || 'SECRET_KEY');
        req.user = verified;
        next();
    } catch (err) {
        res.status(403).json({ message: 'Invalid Token' });
    }
};

// ✅ Multer Configuration for File Uploads
const storage = multer.diskStorage({
    destination: './uploads/',
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage });

// ✅ User Registration
app.post('/register', async(req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'All fields are required' });

    db.query("SELECT * FROM users WHERE email = ?", [email], async(err, results) => {
        if (err) return res.status(500).json({ message: 'Database error' });

        if (results.length > 0) return res.status(409).json({ message: 'User already exists' });

        const hashedPassword = await bcrypt.hash(password, 10);
        db.query("INSERT INTO users (email, password) VALUES (?, ?)", [email, hashedPassword], (err) => {
            if (err) return res.status(500).json({ message: 'Database error' });
            res.status(201).json({ message: 'User registered successfully' });
        });
    });
});

// ✅ User Login
app.post('/login', async(req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'All fields are required' });

    db.query("SELECT * FROM users WHERE email = ?", [email], async(err, results) => {
        if (err) return res.status(500).json({ message: 'Database error' });

        if (results.length === 0) return res.status(401).json({ message: 'Invalid credentials' });

        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

        const token = jwt.sign({ userId: user.id, email: user.email }, process.env.JWT_SECRET || 'SECRET_KEY', { expiresIn: '1h' });
        res.json({ success: true, token, redirect: '/home.html' });
    });
});

// ✅ Admin Login
app.post('/admin/login', async(req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'All fields are required' });

    db.query("SELECT * FROM admin WHERE email = ?", [email], async(err, results) => {
        if (err) return res.status(500).json({ message: 'Database error' });

        if (results.length === 0) return res.status(401).json({ message: 'Invalid credentials' });

        const admin = results[0];
        const isMatch = await bcrypt.compare(password, admin.password);
        if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

        const token = jwt.sign({ adminId: admin.id, email: admin.email }, process.env.JWT_SECRET || 'SECRET_KEY', { expiresIn: '1h' });
        res.json({ success: true, token, redirect: '/admin-dashboard.html' });
    });
});

// ✅ Forgot Password (Admin)
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

app.post('/admin/forgot-password', async(req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: 'Email is required' });

    db.query("SELECT * FROM admin WHERE email = ?", [email], async(err, results) => {
        if (err) return res.status(500).json({ message: 'Database error' });

        if (results.length === 0) return res.status(404).json({ message: 'Admin not found' });

        const otp = Math.floor(100000 + Math.random() * 900000);
        global.otpStorage[email] = { otp, expiresAt: Date.now() + 600000 };

        try {
            await transporter.sendMail({
                from: process.env.EMAIL_USER,
                to: email,
                subject: "Password Reset OTP",
                text: `Your OTP is ${otp}. It is valid for 10 minutes.`
            });
            res.json({ success: true, message: 'OTP sent to your email' });
        } catch (error) {
            res.status(500).json({ message: 'Failed to send OTP' });
        }
    });
});

// ✅ OTP Verification
app.post('/admin/verify-otp', (req, res) => {
    const { email, otp } = req.body;
    if (!global.otpStorage[email] || global.otpStorage[email].otp != otp) {
        return res.status(400).json({ message: 'OTP expired or invalid' });
    }

    delete global.otpStorage[email];
    res.status(200).json({ success: true, message: 'OTP Verified' });
});

// ✅ Reset Password
app.post('/admin/reset-password', async(req, res) => {
    const { email, newPassword } = req.body;
    if (!email || !newPassword) return res.status(400).json({ message: 'All fields are required' });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    db.query("UPDATE admin SET password = ? WHERE email = ?", [hashedPassword, email], (err) => {
        if (err) return res.status(500).json({ message: 'Database error' });
        res.json({ success: true, message: 'Password updated successfully' });
    });
});

// ✅ Global Error Handling
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Internal Server Error' });
});

// ✅ Start Server only if NOT in test environment
if (process.env.NODE_ENV !== 'test') {
    const PORT = process.env.PORT || 5500;
    app.listen(PORT, () => {
        console.log(`🚀 Server running on port ${PORT}`);
    });
}

module.exports = app;