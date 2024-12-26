import express from 'express';
import * as orderController from '../controllers/orderController';
import { authenticateUser } from '../middleware/authMiddleware';

const router = express.Router();

router.post('/', authenticateUser, orderController.createOrUpdateOrder);
router.get('/', authenticateUser, orderController.getUserOrders);
router.get('/:id', authenticateUser, orderController.getOrderById);
router.post('/payment-razorpay', authenticateUser, orderController.createPaymentWithRazorpay);
router.post('/razorpay-webhook',orderController.handleRazorpayWebhook);

export default router;