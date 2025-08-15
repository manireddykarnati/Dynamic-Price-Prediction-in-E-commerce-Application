const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./db'); // Database connection file
const nodemailer = require('nodemailer');
const multer = require('multer');
const path = require('path');

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static('uploads')); // Serve images
app.use(express.static(path.join(__dirname, '../frontend')));

const otpStorage = new Map(); // Using Map instead of plain object

// 🔹 Setup Nodemailer
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// 🔹 Utility function for OTP generation
const generateOTP = () => Math.floor(100000 + Math.random() * 900000);

// 🔹 Secure Token Generation
const generateToken = (user) => {
    return jwt.sign({ userId: user.id, email: user.email },
        process.env.JWT_SECRET, { expiresIn: '1h' }
    );
};

// ----------------------
// ✅ User Registration
// ----------------------
app.post("/register", async(req, res) => {
    const { firstname, lastname, email, password } = req.body;
    if (!firstname || !lastname || !email || !password)
        return res.status(400).json({ message: "All fields are required" });

    try {
        const [existingUser] = await db.promise().query("SELECT * FROM users WHERE email = ?", [email]);

        if (existingUser.length > 0)
            return res.status(400).json({ message: "User already exists" });

        const hashedPassword = await bcrypt.hash(password, 10);
        await db.promise().query(
            "INSERT INTO users (email, password, firstname, lastname) VALUES (?, ?, ?, ?)", [email, hashedPassword, firstname, lastname]
        );
        res.json({ success: true, message: "User registered successfully" });
    } catch (error) {
        console.error("❌ Registration error:", error);
        res.status(500).json({ message: "Server error" });
    }
});

// ----------------------
// ✅ User & Admin Login
// ----------------------
const loginHandler = async(req, res, table) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "All fields are required" });

    try {
        const [results] = await db.promise().query(`SELECT * FROM ${table} WHERE email = ?`, [email]);

        if (results.length === 0)
            return res.status(401).json({ message: "Invalid credentials" });

        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) return res.status(401).json({ message: "Invalid credentials" });

        const token = generateToken(user);
        res.json({ success: true, token, redirect: '/home.html' });
    } catch (error) {
        console.error("❌ Login error:", error);
        res.status(500).json({ message: "Server error" });
    }
};

app.post('/login', (req, res) => loginHandler(req, res, "users"));
app.post('/admin/login', (req, res) => loginHandler(req, res, "admin"));

// ----------------------
// ✅ Forgot Password & OTP (User & Admin)
// ----------------------
const sendOTP = async(req, res, table) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: "Email is required" });

    try {
        const [results] = await db.promise().query(`SELECT * FROM ${table} WHERE email = ?`, [email]);

        if (results.length === 0)
            return res.status(404).json({ message: "User not found" });

        const otp = generateOTP();
        otpStorage.set(email, otp);

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Password Reset OTP",
            text: `Your OTP is ${otp}. It is valid for 10 minutes.`,
        });

        res.json({ success: true, message: "OTP sent to your email" });
    } catch (error) {
        console.error("❌ OTP error:", error);
        res.status(500).json({ message: "Failed to send OTP" });
    }
};

app.post('/forgot-password', (req, res) => sendOTP(req, res, "users"));
app.post('/admin/forgot-password', (req, res) => sendOTP(req, res, "admin"));

// ✅ Verify OTP
app.post('/verify-otp', (req, res) => {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ message: "Email and OTP are required" });

    if (otpStorage.get(email) == otp) {
        otpStorage.delete(email);
        res.json({ success: true, message: "OTP Verified" });
    } else {
        res.status(400).json({ message: "Invalid OTP" });
    }
});

// ----------------------
// ✅ Reset Password (User & Admin)
// ----------------------
const resetPassword = async(req, res, table) => {
    const { email, newPassword } = req.body;
    if (!email || !newPassword) return res.status(400).json({ message: "All fields are required" });

    try {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await db.promise().query(`UPDATE ${table} SET password = ? WHERE email = ?`, [hashedPassword, email]);

        res.json({ success: true, message: "Password updated successfully" });
    } catch (error) {
        console.error("❌ Reset password error:", error);
        res.status(500).json({ message: "Server error" });
    }
};

app.post('/reset-password', (req, res) => resetPassword(req, res, "users"));
app.post('/admin/reset-password', (req, res) => resetPassword(req, res, "admin"));

// ----------------------
// ✅ Image Upload
// ----------------------
const storage = multer.diskStorage({
    destination: './uploads/',
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ storage });

// ----------------------
// ✅ Start Server
// ----------------------
const PORT = process.env.PORT || 5500;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));