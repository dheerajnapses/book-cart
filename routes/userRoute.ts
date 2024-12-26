import express from 'express';
import * as userController from '../controllers/userController';
import { authenticateUser } from '../middleware/authMiddleware';

const router = express.Router();

router.put("/profile/update/:userId", authenticateUser, userController.editUserProfile);

export default router;