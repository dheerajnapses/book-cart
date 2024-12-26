import { Request, Response } from 'express';
import Wishlist from '../models/wishList';
import Product from '../models/Products';
import { response } from '../utils/responseHandler';

export const addToWishlist = async (req: Request, res: Response) => {
  try {
    const userId = req?.id; 
    const { productId } = req.body;
  
    const product = await Product.findById(productId);
    if (!product) {
      return response(res, 404, 'Product not found');
    }

    let wishlist = await Wishlist.findOne({ user: userId });
    if (!wishlist) {
      wishlist = new Wishlist({ user: userId, products: [] });
    }

    if (!wishlist.products.includes(productId)) {
      wishlist.products.push(productId);
      await wishlist.save();
    }
    return response(res, 200, 'Product added to wishlist', wishlist);
  } catch (error) {
    return response(res, 500, 'Error adding product to wishlist');
  }
};

export const removeFromWishlist = async (req: Request, res: Response) => {
  try {
    const userId = req?.id; 
    const { productId } = req.params;

    const wishlist = await Wishlist.findOne({ user: userId });
    if (!wishlist) {
      return response(res, 404, 'Wishlist not found');
    }

    wishlist.products = wishlist.products.filter(id => id.toString() !== productId);
    await wishlist.save();

    return response(res, 200, 'Product removed from wishlist', wishlist);
  } catch (error) {
    return response(res, 500, 'Error removing product from wishlist');
  }
};

export const getWishlist = async (req: Request, res: Response) => {
  try {
    const userId = req?.id; 
    console.log(userId)
    const wishlist = await Wishlist.findOne({ user: userId }).populate('products');
    console.log(wishlist)
    if (!wishlist) {
      return response(res, 404, 'Wishlist not found');
    }
    response(res, 200, 'Wishlist fetched successfully', wishlist);
  } catch (error) {
    response(res, 500, 'Error fetching wishlist');
  }
};