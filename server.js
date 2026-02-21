require('dotenv').config();
const express = require('express');
const nodemailer = require('nodemailer');
const cors = require('cors');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('./models/User');

const app = express();
app.use(cors());
app.use(express.json());

// Serve static files from the current directory
app.use(express.static(__dirname));

// Transporter setup
const transporter = nodemailer.createTransport({
    service: 'gmail', // Standard Gmail service
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'landingpage.html'));
});

// Explicit routes for other pages (optional but good for clean URLs if needed later)
app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'signup.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/api/send-verification', (req, res) => {
    res.send('This endpoint only accepts POST requests from the Abroadly signup page.');
});

// Full Signup Flow
app.post('/api/signup', async (req, res) => {
    const { email, name, password, role } = req.body;

    if (!email || !password || !name) {
        return res.status(400).json({ error: 'Name, email, and password are required' });
    }

    try {
        // 1. Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'Email is already registered' });
        }

        // 2. Hash Password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // 3. Save User Unverified
        const newUser = new User({
            name,
            email,
            password: hashedPassword,
            role: role || 'student',
            isVerified: false
        });
        await newUser.save();

        // 4. Generate Verification Token
        const token = jwt.sign(
            { userId: newUser._id },
            process.env.SESSION_SECRET || 'abroadly_secure_secret',
            { expiresIn: '1d' }
        );

        const verificationLink = `http://localhost:${process.env.PORT || 3000}/api/verify?token=${token}`;

        // 5. Send Email
        const mailOptions = {
            from: `"Abroadly Team" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Verify your Abroadly account',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #e5e7eb; border-radius: 8px; overflow: hidden;">
                    <div style="background-color: #0B0F19; padding: 20px; text-align: center;">
                        <h2 style="color: #F5C97A; margin: 0;">Abroadly</h2>
                    </div>
                    <div style="padding: 30px; background-color: #ffffff; color: #374151;">
                        <h3 style="color: #111827; font-size: 20px;">Welcome to Abroadly, ${name}!</h3>
                        <p style="font-size: 16px; line-height: 1.5;">
                            ${role === 'mentor'
                    ? 'We are excited to have you join as a mentor! Our team is reviewing your uploaded documents. Meanwhile, please verify your email address to secure your account.'
                    : 'You are one step closer to your international education journey! Please verify your email address to activate your account.'}
                        </p>
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="${verificationLink}" style="background-color: #F5C97A; color: #0B0F19; padding: 12px 24px; text-decoration: none; border-radius: 9999px; font-weight: bold; font-size: 16px; display: inline-block;">
                                Verify Email Address
                            </a>
                        </div>
                        <p style="font-size: 14px; color: #6b7280; text-align: center; margin-top: 30px;">
                            If you did not request this email, you can safely ignore it.
                        </p>
                    </div>
                    <div style="background-color: #f3f4f6; padding: 15px; text-align: center; font-size: 12px; color: #9ca3af;">
                        &copy; ${new Date().getFullYear()} Abroadly. All rights reserved.
                    </div>
                </div>
            `
        };

        await transporter.sendMail(mailOptions);
        console.log(`Verification email sent to ${email}`);
        res.status(201).json({ message: 'User created. Verification email sent successfully' });

    } catch (error) {
        console.error('Error during signup:', error);
        res.status(500).json({ error: 'Server error during signup' });
    }
});

// Verification Endpoint
app.get('/api/verify', async (req, res) => {
    const { token } = req.query;

    if (!token) {
        return res.status(400).send('Invalid or missing verification token.');
    }

    try {
        const decoded = jwt.verify(token, process.env.SESSION_SECRET || 'abroadly_secure_secret');
        const user = await User.findById(decoded.userId);

        if (!user) {
            return res.status(400).send('invalid verification link.');
        }

        user.isVerified = true;
        await user.save();

        // Redirect to login page upon success
        res.redirect('/login.html?verified=true');
    } catch (error) {
        console.error('Verification error:', error);
        res.status(400).send('Verification link expired or invalid.');
    }
});

// Resend Verification Email
app.post('/api/resend-verification', async (req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (user.isVerified) return res.status(400).json({ error: 'User is already verified' });

        const token = jwt.sign(
            { userId: user._id },
            process.env.SESSION_SECRET || 'abroadly_secure_secret',
            { expiresIn: '1d' }
        );
        const verificationLink = `http://localhost:${process.env.PORT || 3000}/api/verify?token=${token}`;

        const mailOptions = {
            from: `"Abroadly Team" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Verify your Abroadly account',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #e5e7eb; border-radius: 8px; overflow: hidden;">
                    <div style="background-color: #0B0F19; padding: 20px; text-align: center;">
                        <h2 style="color: #F5C97A; margin: 0;">Abroadly</h2>
                    </div>
                    <div style="padding: 30px; background-color: #ffffff; color: #374151;">
                        <h3 style="color: #111827; font-size: 20px;">Welcome to Abroadly, ${user.name}!</h3>
                        <p style="font-size: 16px; line-height: 1.5;">
                            Please verify your email address to secure your account.
                        </p>
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="${verificationLink}" style="background-color: #F5C97A; color: #0B0F19; padding: 12px 24px; text-decoration: none; border-radius: 9999px; font-weight: bold; font-size: 16px; display: inline-block;">
                                Verify Email Address
                            </a>
                        </div>
                    </div>
                </div>
            `
        };
        await transporter.sendMail(mailOptions);
        res.status(200).json({ message: 'Verification email resent' });
    } catch (error) {
        console.error('Error resending email:', error);
        res.status(500).json({ error: 'Failed to resend email' });
    }
});

// Login Endpoint
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    try {
        const user = await User.findOne({ email });

        // Error 1: Email not found
        if (!user) {
            return res.status(404).json({ error: 'Email not found in our records.' });
        }

        // Error 2: Incorrect Password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Incorrect password. Try again.' });
        }

        // Error 3: Not Verified
        if (!user.isVerified) {
            return res.status(403).json({ error: 'Please verify your email before logging in.' });
        }

        // Success
        const token = jwt.sign(
            { userId: user._id, role: user.role },
            process.env.SESSION_SECRET || 'abroadly_secure_secret',
            { expiresIn: '7d' }
        );

        res.status(200).json({
            message: 'Login successful',
            token,
            user: { name: user.name, email: user.email, role: user.role }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error during login' });
    }
});

// Forgot Password
app.post('/api/forgot-password', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ error: 'User with this email does not exist.' });
        }

        // Create a stateless unique token using a secret + user's current password hash. 
        // This makes the token invalid immediately once the password is changed.
        const secret = (process.env.SESSION_SECRET || 'abroadly_secure_secret') + user.password;
        const token = jwt.sign({ email: user.email, id: user._id }, secret, { expiresIn: '15m' });

        const resetLink = `http://localhost:${process.env.PORT || 3000}/reset-password.html?id=${user._id}&token=${token}`;

        const mailOptions = {
            from: `"Abroadly Security" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Password Reset Request - Abroadly',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #e5e7eb; border-radius: 8px; overflow: hidden;">
                    <div style="background-color: #0B0F19; padding: 20px; text-align: center;">
                        <h2 style="color: #F5C97A; margin: 0;">Abroadly</h2>
                    </div>
                    <div style="padding: 30px; background-color: #ffffff; color: #374151;">
                        <h3 style="color: #111827; font-size: 20px;">Reset Your Password</h3>
                        <p style="font-size: 16px; line-height: 1.5;">
                            We received a request to reset your password. Click the button below to choose a new one. This link expires in 15 minutes.
                        </p>
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="${resetLink}" style="background-color: #F5C97A; color: #0B0F19; padding: 12px 24px; text-decoration: none; border-radius: 9999px; font-weight: bold; font-size: 16px; display: inline-block;">
                                Reset Password
                            </a>
                        </div>
                        <p style="font-size: 14px; color: #6b7280; text-align: center; margin-top: 30px;">
                            If you did not request a password reset, you can safely ignore this email.
                        </p>
                    </div>
                </div>
            `
        };

        await transporter.sendMail(mailOptions);
        res.status(200).json({ message: 'Password reset link sent to your email.' });
    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({ error: 'Failed to process request.' });
    }
});

// Reset Password
app.post('/api/reset-password', async (req, res) => {
    const { id, token, password } = req.body;

    if (!id || !token || !password) {
        return res.status(400).json({ error: 'All fields are required.' });
    }

    try {
        const user = await User.findById(id);
        if (!user) return res.status(400).json({ error: 'Invalid user.' });

        const secret = (process.env.SESSION_SECRET || 'abroadly_secure_secret') + user.password;

        try {
            jwt.verify(token, secret);
        } catch (err) {
            return res.status(400).json({ error: 'Reset link has expired or is invalid.' });
        }

        // Hash new password
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);
        await user.save();

        res.status(200).json({ message: 'Password has been reset successfully.' });
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ error: 'Failed to reset password.' });
    }
});

// Admin - Get All Users (For testing/viewing only)
app.get('/api/users', async (req, res) => {
    try {
        const users = await User.find().select('-password').sort({ createdAt: -1 });
        res.status(200).json(users);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ error: 'Failed to fetch users.' });
    }
});

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/abroadly')
    .then(() => console.log('✅ Connected to MongoDB successfully'))
    .catch(err => console.error('❌ MongoDB connection error:', err));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
