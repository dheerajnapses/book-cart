import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { response } from '../utils/responseHandler';

declare global {
  namespace Express {
    interface Request {
      id: string;
    }
  }
}

const authenticateUser = async (req: Request, res: Response, next: NextFunction) => {
  const token = req.cookies.access_token;
  
  if (!token) {
    return response(res, 401, 'Not authorized, no token');
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as jwt.JwtPayload;

    if (!decoded) {
      return response(res, 401, 'Not authorized, user not found');
    }

    req.id = decoded.userId;
    next();
  } catch (error) {
    return response(res, 401, 'Not authorized, token failed');
  }
};

export { authenticateUser };

