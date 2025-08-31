import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/userModel.js';
import transporter from '../config/nodemailer.js';
import { EMAIL_VERIFY_TEMPLATE, PASSWORD_RESET_TEMPLATE } from '../config/emailTemplates.js';

// Register User
export const register = async (req, res) => {
    const { username, email, password } = req.body;

    if(!username || !email || !password) {
        return res.json({ success: false, message: 'Please provide all required fields' });
    }
    try{

        const existingUser = await userModel.findOne({email});
        if(existingUser) {
            return res.json({ success: false, message: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new userModel({
            username,
            email,
            password: hashedPassword,
        });
        await user.save();

        const token = jwt.sign(
            { id: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.cookie('token', token, {
            httpOnly: true,
            secure: false, // Always false for localhost (not https)
            sameSite: 'lax', // 'lax' is safest for localhost cross-origin
            maxAge: 7 * 24 * 60 * 60 * 1000   // 7 days in milliseconds
        });

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Welcome to Simple - MERN Stack App',
            text: `Very warm welcome to our Simple - MERN Stack website. Your account has been created with email id: ${email}`
        }
        await transporter.sendMail(mailOptions);

        return res.json({ success: true, message: 'User registered successfully' });

    } catch (error) {
        //console.error(error);
        res.json({ success: false, message: 'Server error' });
    }
}



// Login User
export const login = async (req, res) => {
    const { email, password } = req.body;

    if(!email || !password) {
        return res.json({ success: false, message: 'Please provide all required fields' });
    }

    try {
        const user = await userModel.findOne({ email });
        if(!user) {
            return res.json({ success: false, message: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if(!isMatch) {
            return res.json({ success: false, message: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { id: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.cookie('token', token, {
            httpOnly: true,
            secure: false, // Always false for localhost (not https)
            sameSite: 'lax', // 'lax' is safest for localhost cross-origin
            maxAge: 7 * 24 * 60 * 60 * 1000   // 7 days in milliseconds
        });

        return res.json({ success: true, message: 'Logged in successfully' });

    } catch (error) {
        //console.error(error);
        res.json({ success: false, message: 'Server error' });
    }
}


// Logout User
export const logout = async (req, res) => { 
    try{
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        });

        return res.json({ success: true, message: 'Logged out successfully' });
    
    } catch (error) {
        //console.error(error);
        res.json({ success: false, message: 'Server error' });
    }
}



// Send Verification OTP to User Email
export const sendVerifyOtp = async (req, res) => {
    try {
        /*const {userId} = req.body;*/
        //console.log(userId);

        const user = await userModel.findById(req.userId);
        if (!user) {
            return res.json({ success: false, message: 'User not found' });
        }
        if(user.isVerified) {
            return res.json({ success: false, message: 'Account already verified' });
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));
        user.verifyOtp = otp;
        user.verifyOtpExpireAt = Date.now() + 24 * 60 * 60 * 1000; // 1 Day from now
        await user.save();


        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account Verification OTP',
            //text: `Your OTP for Simple - MERN Stack website account verification is ${otp}. It is valid for 1 day.`,
            html: EMAIL_VERIFY_TEMPLATE.replace('{{otp}}', otp).replace('{{email}}', user.email)
        }
        await transporter.sendMail(mailOptions);

        res.json({ success: true, message: 'Verification OTP sent to your email' });


    } catch (error) {
        //console.error(error);
        res.json({ success: false, message: 'Server error..' });
    }
}



// Verify User Email with OTP
export const verifyEmail = async (req, res) => {
    const { otp } = req.body;

    if(!req.userId || !otp) {
        return res.json({ success: false, message: 'Missing Details' });
    }
    try {
        const user = await userModel.findById(req.userId);

        if(!user) {
            return res.json({ success: false, message: 'User not found' });
        }

        
        if(user.verifyOtp === '' || user.verifyOtp !== otp) {
            return res.json({ success: false, message: 'Invalid OTP' });
        }
        
        if(user.verifyOtpExpireAt < Date.now()) {
            return res.json({ success: false, message: 'OTP expired' });
        }
        
        // if(user.isVerified) {
        //     return res.json({ success: false, message: 'Account already verified' });
        // }

        user.isVerified = true;
        user.verifyOtp = '';
        user.verifyOtpExpireAt = 0;
        
        await user.save();

        res.json({ success: true, message: 'Email account verified successfully' });

    } catch (error) {
        //console.error(error);
        res.json({ success: false, message: 'Server error' });
    }
}


// Check if User is Authenticated
export const isAuthenticated = async (req, res) => {
    try {
        return res.json({ success: true, message: 'User is authenticated' });

    } catch (error) {
        //console.error(error);
        res.json({ success: false, message: 'Server error' });
    }
}

// Set Password Reset OTP
export const sendResetOtp = async (req, res) => {
    const {email} = req.body;

    if(!email){
        return res.json({ success: false, message: 'Please provide email' });
    }

    try{
        const user = await userModel.findOne({email});
        if(!user){
            return res.json({ success: false, message: 'User not found' });
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));

        user.resetOtp = otp;
        user.resetOtpExpireAt = Date.now() + 15 * 60 * 1000; // 15 minutes from now
        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Password Reset OTP',
            //text: `Your OTP for Simple - MERN Stack website password reset is ${otp}. It is valid for 15 minutes.`,
            html: PASSWORD_RESET_TEMPLATE.replace('{{otp}}', otp).replace('{{email}}', user.email)
        }
        await transporter.sendMail(mailOptions);

        return res.json({ success: true, message: 'Password reset OTP sent to your email' });


    } catch (error) {
        //console.error(error);
        res.json({ success: false, message: 'Server error' });
    }
}

// Reset Password
export const resetPassword = async (req, res) => {
    const { email, otp, newPassword } = req.body;

    if(!email || !otp || !newPassword) {
        return res.json({ success: false, message: 'Please provide all required fields' });
    }

    try {
        const user = await userModel.findOne({email});

        if(!user) {
            return res.json({ success: false, message: 'User not found' });
        }

        if(user.resetOtp === '' || user.resetOtp !== otp) {
            return res.json({ success: false, message: 'Invalid OTP' });
        }

        if(user.resetOtpExpireAt < Date.now()) {
            return res.json({ success: false, message: 'OTP expired' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        user.resetOtp = '';
        user.resetOtpExpireAt = 0;
        await user.save();

        return res.json({ success: true, message: 'Password has been reset successfully' });

    } catch (error) {
        //console.error(error);
        res.json({ success: false, message: 'Server error' });
    }
}