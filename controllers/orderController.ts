import { Request, Response } from 'express';
import Order from '../models/ProductOrder';
import Cart from '../models/cartItems';
import Razorpay from 'razorpay';
import dotenv from 'dotenv'
import { response } from '../utils/responseHandler';
import crypto from 'crypto';
dotenv.config();

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID as string,
  key_secret: process.env.RAZORPAY_KEY_SECRET as string,
});

export const createOrUpdateOrder = async (req: Request, res: Response) => {
  try {
    const userId = req?.id;
    const {orderId, shippingAddress, paymentMethod, totalAmount, paymentDetails } = req.body;

    const cart = await Cart.findOne({ user: userId }).populate('items.product');
    if (!cart || cart.items.length === 0) {
      return response(res, 400, 'Cart is empty');
    }
     
    let order = await Order.findOne({ _id: orderId });
    
    if (order) {
      // Update existing order
      order.shippingAddress = shippingAddress || order.shippingAddress;
      order.paymentMethod = paymentMethod || order.paymentMethod;
      order.totalAmount = totalAmount || order.totalAmount;
      if (paymentDetails) {
        order.paymentDetails = paymentDetails;
        order.paymentStatus = 'completed';
        order.status = 'processing';
      }
    } else {
      // Create new order
      order = new Order({
        user: userId,
        items: cart.items,
        totalAmount,
        shippingAddress,
        paymentMethod,
        paymentDetails,
        paymentStatus: paymentDetails ? 'completed' : 'pending',
      });
    }

    await order.save();

    if (paymentDetails) {
      // Remove cart items after successful payment
      await Cart.findOneAndUpdate(
        { user: userId },
        { $set: { items: [] } }
      );
    }

    response(res, 201, 'Order created/updated successfully', order);
  } catch (error) {
    console.error(error);
    response(res, 500, 'Error creating/updating order');
  }
};


export const getOrderById = async (req: Request, res: Response) => {
  try {
    const order = await Order.findById(req.params.id)
    .populate('user', 'name email').populate('shippingAddress')
    .populate({
      path: 'items.product',
      model: 'Product', 
    });
    if (!order) {
      return response(res, 404, 'Order not found');
    }
    response(res, 200, 'Order fetched successfully', order);
  } catch (error) {
    response(res, 500, 'Error fetching order');
  }
};

export const getUserOrders = async (req: Request, res: Response) => {
  try {
    const userId = req?.id; 
    const orders = await Order.find({ user: userId }).sort({ createdAt: -1 })
      .populate('user', 'name email').populate('shippingAddress')
      .populate({
        path: 'items.product',
        model: 'Product', 
      })
      console.log(orders)
    response(res, 200, 'Orders fetched successfully', orders);
  } catch (error) {
    response(res, 500, 'Error fetching orders');
  }
};

export const createPaymentWithRazorpay = async (req: Request, res: Response) => {
  try {
    const { orderId } = req.body;
    const order = await Order.findById(orderId);
    if (!order) {
      return response(res, 404, 'Order not found');
    }
     
    const razorpayOrder = await razorpay.orders.create({
      amount: Math.round(order.totalAmount * 100), 
      currency: 'INR',
      receipt: order._id.toString(),
    });
    response(res, 200, 'Razorpay order created', { order: razorpayOrder });
  } catch (error) {
    console.error('Error creating Razorpay order:', error);
    response(res, 500, 'Error creating Razorpay order');
  }
};

export const handleRazorpayWebhook = async (req: Request, res: Response) => {
  const secret = process.env.RAZORPAY_WEBHOOK_SECRET as string;

  const shasum = crypto.createHmac('sha256', secret);
  shasum.update(JSON.stringify(req.body));
  const digest = shasum.digest('hex');

  if (digest === req.headers['x-razorpay-signature']) {
    const paymentId = req.body.payload.payment.entity.id;
    const orderId = req.body.payload.payment.entity.order_id;

    await Order.findOneAndUpdate(
      { 'paymentDetails.razorpay_order_id': orderId },
      {
        paymentStatus: 'completed',
        status: 'processing',
        'paymentDetails.razorpay_payment_id': paymentId,
      }
    );

    response(res, 200, 'Webhook processed successfully');
  } else {
    response(res, 400, 'Invalid signature');
  }
};

