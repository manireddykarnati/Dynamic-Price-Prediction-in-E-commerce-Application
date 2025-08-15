const request = require('supertest');
const app = require('../app');
const db = require('../db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

jest.mock('bcryptjs'); // Mock bcryptjs
jest.mock('jsonwebtoken'); // Mock JWT
jest.mock('../db'); // Mock database


describe('POST /login', () => {
    afterEach(() => {
        jest.clearAllMocks();
    });


    it('should return 400 if email or password is missing', async() => {
        const res = await request(app).post('/login').send({ email: '' });
        expect(res.status).toBe(400);
        expect(res.body).toEqual({ message: 'All fields are required' });
    });

    it('should return 401 if user is not found', async() => {
        db.query.mockImplementation((query, values, callback) => callback(null, []));

        const res = await request(app).post('/login').send({ email: 'test@example.com', password: 'password123' });
        expect(res.status).toBe(401);
        expect(res.body).toEqual({ message: 'Invalid credentials' });
    });

    it('should return 401 if password does not match', async() => {
        const mockUser = { id: 1, email: 'test@example.com', password: 'hashedpassword' };
        db.query.mockImplementation((query, values, callback) => callback(null, [mockUser]));
        bcrypt.compare.mockResolvedValue(false);

        const res = await request(app).post('/login').send({ email: 'test@example.com', password: 'wrongpassword' });
        expect(res.status).toBe(401);
        expect(res.body).toEqual({ message: 'Invalid credentials' });
    });

    it('should return token and redirect URL on successful login', async() => {
        const mockUser = { id: 1, email: 'test@example.com', password: 'hashedpassword' };

        // Mock database response (user found)
        db.query.mockImplementation((query, values, callback) => {
            callback(null, [mockUser]); // Return user in array
        });

        // Mock bcrypt.compare to return true (password matches)
        bcrypt.compare.mockResolvedValue(true);

        // Mock JWT to return a fake token
        jwt.sign.mockReturnValue('mocked_token');

        // Make request to login endpoint
        const res = await request(app)
            .post('/login')
            .send({ email: 'test@example.com', password: 'password123' });

        // Debugging: Print response
        console.log(res.body);

        expect(res.status).toBe(200);
        expect(res.body).toEqual({
            success: true,
            token: 'mocked_token',
            redirect: '/home.html',
        });
    });

});