import express from 'express';
import * as cartController from '../controllers/cartController';
import { authenticateUser } from '../middleware/authMiddleware';

const router = express.Router();

router.get('/:userId', authenticateUser, cartController.getCart);
router.post('/add', authenticateUser, cartController.addToCart);
router.delete('/remove/:productId', authenticateUser, cartController.removeFromCart);

export default router;