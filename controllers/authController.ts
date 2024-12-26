import { Request, Response } from 'express';
import User, { IUser } from '../models/User';
import crypto from 'crypto';
import { sendVerificationEmail, sendPasswordResetEmail } from '../config/emailConfig';
import { response } from '../utils/responseHandler';
import { generateToken } from '../utils/generateToken'; 

export const register = async (req: Request, res: Response) => {
  try {
    const { name, email, password,agreeTerms } = req.body;
    const existingUser = await User.findOne({ email });
    console.log(existingUser)
    if (existingUser) {
      return response(res, 400, 'User already exists');
    }

    const verificationToken = crypto.randomBytes(20).toString('hex');
    const user = new User({ name, email, password,agreeTerms, verificationToken });
    await user.save();

   const result= await sendVerificationEmail(user.email, verificationToken);
   console.log(result);

   return response(res, 201, 'Registration successful. Please check your email to verify your account.');
  } catch (error) {
    console.log(error);
    return response(res, 500, 'An error occurred during registration. Please try again.');
  }
};

export const verifyEmail = async (req: Request, res: Response) => {
  try {
    const { token } = req.params;
    const user = await User.findOne({ verificationToken: token });
    if (!user) {
      return response(res, 400, 'Invalid or expired verification token');
    }

    user.isVerified = true;
    user.verificationToken = undefined;

    const accessToken = generateToken(user);
    res.cookie('access_token', accessToken, {
      httpOnly: true,
      sameSite:'strict',
      maxAge:24*60*60*1000
    });
    
    await user.save();

    return  response(res, 200, 'Email verified successfully. You can now log in to your account.');
  } catch (error) {
    return  response(res, 500, 'An error occurred while verifying your email. Please try again.');
  }
};

export const login = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email }) as IUser;
    if (!user || !(await user.comparePassword(password))) {
      return response(res, 401, 'Invalid email or password');
    }

    if (!user.isVerified) {
      return response(res, 401, 'Please verify your email before logging in. Check your inbox for the verification link.');
    }
    // Use the generateToken function
    const accessToken = generateToken(user);
    // Set the token in the cookie
    res.cookie('access_token', accessToken, {
      httpOnly: true,
      sameSite:'strict',
      maxAge:24*60*60*1000
    });
    
    return response(res, 200, 'Login successful', {  user: { id: user._id, name: user.name, email: user.email } });
  } catch (error) {
    return  response(res, 500, 'An error occurred during login. Please try again.');
  }
};


export const forgotPassword = async (req: Request, res: Response) => {
  try {
    const { email } = req.body;
    console.log(email);
    const user = await User.findOne({ email });
    console.log('this is user',user)
    if (!user) {
      return response(res, 404, 'No account found with this email address');
    }

    const resetToken = crypto.randomBytes(20).toString('hex');
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = new Date(Date.now() + 3600000); // 1 hour
    await user.save();

    await sendPasswordResetEmail(user.email, resetToken);

    return response(res, 200, 'A password reset link has been sent to your email address');
  } catch (error) {
    console.log(error)
    return response(res, 500, 'An error occurred while processing your request. Please try again.');
  }
};

export const resetPassword = async (req: Request, res: Response) => {
  try {

    const { token } = req.params;
    const {  newPassword } = req.body;
    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      return response(res, 400, 'Invalid or expired password reset token');
    }

    user.password = newPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

   return response(res, 200, 'Your password has been successfully reset. You can now log in with your new password.');
  } catch (error) {
    return response(res, 500, 'An error occurred while resetting your password. Please try again.');
  }
};


export const logout = async (_: Request, res: Response) => {
  try {
    // Clear the access token cookie
    res.clearCookie("access_token", {
      httpOnly: true,
      sameSite: "strict",
    });
    return response(res, 200, "Successfully logged out.");
  } catch (error) {
    console.error("Logout Error:", error);
    return response(res, 500, "An error occurred while processing your request. Please try again.");
  }
};


export const checkUserAuth = async (req: Request, res: Response) =>{
  try {
    const userId = req?.id; 
    if (!userId) {
      return response(res, 400, 'Unauthenticated! Please login before accessing the data');
    }
    const user = await User.findById(userId).select('-password -verificationToken -resetPasswordToken -resetPasswordExpires');
    console.log(user)
    if (!user) {
      return response(res, 403, 'User not found');
    }
    return response(res, 201, 'User retrieved and allowed to use bookkart', user);
  } catch (error) {
    return response(res, 500, 'Internal server error', error);
  }
};
