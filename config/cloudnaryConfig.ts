import multer from 'multer';
import { v2 as cloudinary, UploadApiOptions, UploadApiResponse } from 'cloudinary';
import dotenv from 'dotenv';
import { RequestHandler } from 'express';

dotenv.config();

cloudinary.config({
    cloud_name: process.env.CLOUDINART_NAME as string,
    api_key: process.env.CLOUDINART_API_KEY as string,
    api_secret: process.env.CLOUDINART_API_SECRET as string,
});

// Custom interface for file with path
interface CustomFile extends Express.Multer.File {
    path: string;
}

// Function to upload a single file to Cloudinary
const uploadFileToCloudinary = (file: CustomFile): Promise<UploadApiResponse> => {
    const options: UploadApiOptions = {
        resource_type: 'image',
    };

    return new Promise((resolve, reject) => {
        cloudinary.uploader.upload(file.path, options, (error, result) => {
            if (error) {
                return reject(error);
            }
            resolve(result as UploadApiResponse);
        });
    });
};

// Multer middleware for handling multiple file uploads
const multerMiddleware: RequestHandler = multer({ dest: 'uploads/' }).array('images', 4); 

export { multerMiddleware, uploadFileToCloudinary };
