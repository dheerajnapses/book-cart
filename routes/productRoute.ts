import express from 'express';
import multer from 'multer';
import * as productController from '../controllers/productController';
import { authenticateUser } from '../middleware/authMiddleware';
import { multerMiddleware } from '../config/cloudnaryConfig';

const router = express.Router();

router.get('/', productController.getAllProducts);
router.get('/:id', productController.getProductById);
router.post('/', authenticateUser, multerMiddleware, productController.createProduct);
router.delete('/seller/:productId', authenticateUser, productController.deleteProduct);
router.get('/seller/:sellerId', authenticateUser,productController.getProductsBySeller)

export default router;