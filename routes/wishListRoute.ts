import express from 'express';
import * as wishlistController from '../controllers/wishListController';
import { authenticateUser } from '../middleware/authMiddleware';

const router = express.Router();

router.get('/', authenticateUser, wishlistController.getWishlist);
router.post('/add', authenticateUser, wishlistController.addToWishlist);
router.delete('/remove/:productId', authenticateUser, wishlistController.removeFromWishlist);

export default router;