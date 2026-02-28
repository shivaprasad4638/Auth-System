import multer from 'multer';
import { AppError } from '../utils/AppError';

// Configure Multer to use memory storage
const storage = multer.memoryStorage();

// File filter to explicitly allow only specific image formats
const fileFilter = (req: any, file: Express.Multer.File, cb: multer.FileFilterCallback) => {
    const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/webp'];

    if (allowedMimeTypes.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new AppError('Invalid file type. Only JPEG, PNG, and WebP are allowed.', 400));
    }
};

// Create Multer instance
export const upload = multer({
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024, // 5 MB ceiling limit
    },
    fileFilter: fileFilter,
});
