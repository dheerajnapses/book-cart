import express from 'express';
import dotenv from 'dotenv';
import  cors from 'cors';
import authRoutes from './routes/authRoute';
import productRoutes from './routes/productRoute';
import cartRoutes from './routes/cartRoute';
import wishlistRoutes from './routes/wishListRoute';
import orderRoutes from './routes/orderRoute';
import addressRoute from './routes/addressRoute';
import userRoute from './routes/userRoute';
import connectDB from './config/dbConfig';
import passport from './controllers/strategy/google.strategy';
import cookieParser from "cookie-parser";
dotenv.config();

const app = express();

// Middleware
const corsOptions = {
    origin:process.env.FRONTEND_URL,
    credentials: true,
}
app.use(cors(corsOptions));
app.use(express.json());
app.use(passport.initialize())
app.use(cookieParser());

// Connect to MongoDB
connectDB()


// Routes
app.use('/api/auth', authRoutes);
app.use('/api/products', productRoutes);
app.use('/api/cart', cartRoutes);
app.use('/api/wishlist', wishlistRoutes);
app.use('/api/orders', orderRoutes);
app.use('/api/address', addressRoute);
app.use('/api/users', userRoute);

const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

export default app;