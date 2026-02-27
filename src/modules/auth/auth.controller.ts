import { Request, Response } from "express";
import { AuthService } from "./auth.service";
import { AuthRequest } from "../../middleware/auth.middleware";
import { catchAsync } from "../../utils/catchAsync";
import { AppError } from "../../utils/AppError";

export class AuthController {
    static register = catchAsync(async (req: Request, res: Response) => {
        const { email, password, phoneNumber } = req.body;

        const { user, accessToken, refreshToken } = await AuthService.register(
            email,
            password,
            phoneNumber,
            (req.headers["user-agent"] as string) || undefined,
            req.ip
        );

        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

        res.status(201).json({
            message: "User created",
            accessToken,
            user: {
                id: user.id,
                email: user.email,
                phoneNumber: user.phoneNumber,
                isVerified: (user as any).isVerified,
                role: (user as any).role
            },
        });
    });

    static login = catchAsync(async (req: Request, res: Response) => {
        const { email, password } = req.body;

        const tokens = await AuthService.login(
            email,
            password,
            (req.headers["user-agent"] as string) || undefined,
            req.ip
        );

        res.cookie("refreshToken", tokens.refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

        res.status(200).json({
            accessToken: tokens.accessToken,
            user: tokens.user
        });
    });

    static sendOtp = catchAsync(async (req: Request, res: Response) => {
        const { phoneNumber } = req.body;
        const result = await AuthService.sendOtp(phoneNumber);
        res.status(200).json(result);
    });

    static verifyOtp = catchAsync(async (req: Request, res: Response) => {
        const { phoneNumber, otp } = req.body;

        const tokens = await AuthService.verifyOtp(
            phoneNumber,
            otp,
            (req.headers["user-agent"] as string) || undefined,
            req.ip
        );

        res.cookie("refreshToken", tokens.refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        res.status(200).json({
            accessToken: tokens.accessToken,
            user: tokens.user
        });
    });

    static refresh = catchAsync(async (req: Request, res: Response) => {
        const refreshToken = req.cookies?.refreshToken || req.body.refreshToken;

        if (!refreshToken) {
            throw new AppError("Refresh token is missing", 401);
        }

        const tokens = await AuthService.refresh(refreshToken);

        res.cookie("refreshToken", tokens.refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        res.status(200).json({
            accessToken: tokens.accessToken,
            user: tokens.user
        });
    });

    static getSessions = catchAsync(async (req: AuthRequest, res: Response) => {
        if (!req.user) throw new AppError("Unauthorized", 401);

        const sessions = await AuthService.getSessions(req.user.sub);

        res.status(200).json(sessions);
    });

    static logout = catchAsync(async (req: AuthRequest, res: Response) => {
        if (!req.user) throw new AppError("Unauthorized", 401);

        const sessionId = req.body.sessionId || req.user.sid;

        await AuthService.logout(sessionId);

        res.clearCookie("refreshToken", {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict"
        });

        res.status(200).json({ message: "Logged out successfully" });
    });

    // Alias for getSessions to match user request
    static sessions = AuthController.getSessions;

    static revokeSession = catchAsync(async (req: AuthRequest, res: Response) => {
        if (!req.user) throw new AppError("Unauthorized", 401);
        const sessionId = req.params.id as string;
        // Pass both sessionId and userId to the service
        await AuthService.revokeSession(sessionId, req.user.sub);
        res.json({ message: "Session revoked" });
    });

    static revokeAllSessions = catchAsync(async (req: AuthRequest, res: Response) => {
        if (!req.user) throw new AppError("Unauthorized", 401);
        const userId = req.user.sub;

        await AuthService.revokeAllSessions(userId);

        res.json({ message: "All sessions revoked" });
    });
}
