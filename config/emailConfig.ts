import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
dotenv.config();

const transporter = nodemailer.createTransport({
 service:"gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

transporter.verify((error, success) => {
    if (error) {
      console.error('SMTP Configuration Error:', error);
    } else {
      console.log('SMTP is configured properly and ready to send emails.');
    }
  });
  

const sendEmail = async (to: string, subject: string, html: string) => {
  await transporter.sendMail({
    from: `"Your Bookstore" <${process.env.EMAIL_USER}>`,
    to,
    subject,
    html,
  });
};

export const sendVerificationEmail = async (to: string, token: string) => {
  const verificationUrl = `${process.env.FRONTEND_URL}/verify-email/${token}`;
  const html = `
    <h1>Welcome to Your Bookstore!</h1>
    <p>Thank you for registering. Please click the link below to verify your email address:</p>
    <a href="${verificationUrl}">Verify Email</a>
    <p>If you didn't request this, please ignore this email.</p>
  `;
  await sendEmail(to, 'Verify Your Email', html);
};

export const sendPasswordResetEmail = async (to: string, token: string) => {
  const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${token}`;
  const html = `
    <h1>Reset Your Password</h1>
    <p>You have requested to reset your password. Click the link below to set a new password:</p>
    <a href="${resetUrl}">Reset Password</a>
    <p>If you didn't request this, please ignore this email and your password will remain unchanged.</p>
  `;
  await sendEmail(to, 'Reset Your Password', html);
};