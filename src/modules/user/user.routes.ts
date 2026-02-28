import { Router } from 'express';
import { UserController } from './user.controller';
import { authenticate } from '../../middleware/auth.middleware';
import { upload } from '../../middleware/upload.middleware';

const router = Router();

// Require authentication for all user routes
router.use(authenticate);

// Avatar routes
router.patch('/avatar/regenerate', UserController.regenerateAvatar);
router.patch('/avatar/style', UserController.updateAvatarStyle);

export default router;
