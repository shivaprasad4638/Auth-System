import { Request, Response } from 'express';
import { supabase } from '../../config/supabase';
import prisma from '../../config/prisma';
import { AppError } from '../../utils/AppError';
import { catchAsync } from '../../utils/catchAsync';
import { AuthRequest } from '../../middleware/auth.middleware';
import path from 'path';
import crypto from 'crypto';
export class UserController {
    static uploadAvatar = catchAsync(async (req: AuthRequest, res: Response) => {
        throw new AppError('Avatar upload is temporarily disabled. Currently using automatic DiceBear avatars.', 403);
        /*
        // Original implementation preserved for future use
        if (!req.user) throw new AppError('Unauthorized', 401);
        ...
        */
    });

    static selectAvatar = catchAsync(async (req: AuthRequest, res: Response) => {
        throw new AppError('Avatar selection is temporarily disabled. Currently using automatic DiceBear avatars.', 403);
    });

    static getAvatarUrl = catchAsync(async (req: AuthRequest, res: Response) => {
        throw new AppError('Avatar URL fetch is temporarily disabled. Currently using automatic DiceBear avatars.', 403);
    });

    static regenerateAvatar = catchAsync(async (req: AuthRequest, res: Response) => {
        if (!req.user) throw new AppError('Unauthorized', 401);
        const userId = req.user.sub;

        const newSeed = crypto.randomUUID();

        // Update the user with the new seed, ignoring typescript warnings from missing Prisma generation
        const updatedUser = await prisma.user.update({
            where: { id: userId },
            data: { avatarSeed: newSeed } as any,
            select: { id: true, email: true, avatarSeed: true, avatarStyle: true } as any,
        });

        res.status(200).json({
            message: 'Avatar regenerated successfully',
            user: updatedUser,
        });
    });

    static updateAvatarStyle = catchAsync(async (req: AuthRequest, res: Response) => {
        if (!req.user) throw new AppError('Unauthorized', 401);
        const userId = req.user.sub;
        const { style } = req.body;

        const allowedStyles = ["avataaars", "bottts", "pixel-art", "lorelei", "initials", "adventurer"];

        if (!style || !allowedStyles.includes(style)) {
            throw new AppError('Invalid avatar style provided.', 400);
        }

        const updatedUser = await prisma.user.update({
            where: { id: userId },
            data: { avatarStyle: style } as any,
            select: { id: true, email: true, avatarSeed: true, avatarStyle: true } as any,
        });

        res.status(200).json({
            message: 'Avatar style updated successfully',
            user: updatedUser,
        });
    });
}
