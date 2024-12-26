import { Request, Response } from "express";
import Cart, { ICartItem } from "../models/cartItems";
import Product from "../models/Products";
import { response } from "../utils/responseHandler";

export const addToCart = async (req: Request, res: Response) => {
  try {
    const userId = req?.id; 
    const { productId, quantity } = req.body;

    const product = await Product.findById(productId);
    if (!product) {
      return response(res, 404, "Product not found");
    }

    if (product.seller.toString() === userId) {
      return response(res, 400, "You cannot add your own product to the cart");
    }  

    let cart = await Cart.findOne({ user: userId });
    if (!cart) {
      cart = new Cart({ user: userId, items: [] });
    }

    const existingItem = cart.items.find(
      (item) => item.product.toString() === productId
    );
    if (existingItem) {
      existingItem.quantity += quantity;
    } else {
      const newItem = {
        product: productId,
        quantity: quantity,
      };

      cart.items.push(newItem as ICartItem);
    }

    await cart.save();
    response(res, 200, "Item added to cart", cart);
  } catch (error) {
    response(res, 500, "Error adding item to cart");
  }
};

export const removeFromCart = async (req: Request, res: Response) => {
  try {
    const userId = req?.id; 
    const { productId } = req.params;

    const cart = await Cart.findOne({ user: userId });
    if (!cart) {
      return response(res, 404, "Cart not found");
    }

    cart.items = cart.items.filter(
      (item) => item.product.toString() !== productId
    );
    await cart.save();

    response(res, 200, "Item removed from cart", cart);
  } catch (error) {
    response(res, 500, "Error removing item from cart");
  }
};

export const getCart = async (req: Request, res: Response) => {
  try {
    const userId = req.params.userId;
    console.log(userId)
    const cart = await Cart.findOne({ user: userId }).populate("items.product");
    if (!cart) {
      return response(res, 200, "Cart is empty", { items: [] });
    }
    response(res, 200, "Cart fetched successfully", cart);
  } catch (error) {
    console.error("Error fetching cart:", error);
    response(res, 500, "Error fetching cart");
  }
};