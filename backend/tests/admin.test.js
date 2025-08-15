const request = require('supertest');
const app = require('../app');
const db = require('../db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

jest.mock('../db');
jest.mock('bcryptjs');
jest.mock('jsonwebtoken');
jest.mock('nodemailer');

// Mock nodemailer transport
const mockTransporter = {
    sendMail: jest.fn().mockResolvedValue(true),
};
nodemailer.createTransport.mockReturnValue(mockTransporter);

describe('Admin Authentication & Password Reset', () => {
    // 🚀 1️⃣ Admin Login Test
    it('should return token and redirect URL on successful admin login', async() => {
        const mockAdmin = { id: 1, email: 'admin@example.com', password: 'hashedpassword' };

        // Mock DB response
        db.query.mockImplementation((query, values, callback) => {
            callback(null, [mockAdmin]); // Admin found
        });

        // Mock password comparison
        bcrypt.compare.mockResolvedValue(true);

        // Mock JWT sign
        jwt.sign.mockReturnValue('mocked_admin_token');

        // Send request
        const res = await request(app)
            .post('/admin/login')
            .send({ email: 'admin@example.com', password: 'password123' });

        expect(res.status).toBe(200);
        expect(res.body).toEqual({
            "success": true,
            "token": "mocked_admin_token",
            "redirect": "/admin-dashboard.html"

        });
    });



    // 🚀 3️⃣ Admin Verify OTP


    it('should return error for incorrect OTP', async() => {
        global.otpStorage = { 'admin@example.com': 123456 };

        const res = await request(app)
            .post('/admin/verify-otp')
            .send({ email: 'admin@example.com', otp: 999999 });

        expect(res.status).toBe(400);
        expect(res.body).toEqual({ message: 'OTP expired or invalid' }); // 🔥 Update expected message
    });

    // 🚀 4️⃣ Admin Reset Password
    it('should reset password successfully', async() => {
        bcrypt.hash.mockResolvedValue('newhashedpassword');

        db.query.mockImplementation((query, values, callback) => {
            callback(null, { affectedRows: 1 }); // Simulate success
        });

        const res = await request(app)
            .post('/admin/reset-password')
            .send({ email: 'admin@example.com', newPassword: 'newpassword123' });

        expect(res.status).toBe(200);
        expect(res.body).toEqual({ success: true, message: 'Password updated successfully' });
    });

    afterEach(() => {
        jest.clearAllMocks();
    });
});