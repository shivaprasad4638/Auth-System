import { Request, Response } from "express";
import { AuthService } from "./auth.service";
import { AuthRequest } from "../../middleware/auth.middleware";

export class AuthController {

    static async register(req: Request, res: Response) {
        try {
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
                    isVerified: (user as any).isVerified
                },
            });
        } catch (err: any) {
            res.status(400).json({ message: err.message });
        }
    }

    static async login(req: Request, res: Response) {
        try {
            const { email, password } = req.body;

            const tokens = await AuthService.login(
                email,
                password,
                (req.headers["user-agent"] as string) || undefined,
                req.ip
            );

            res.cookie("refreshToken", tokens.refreshToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production", // true in production
                sameSite: "strict",
                maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
            });

            res.status(200).json({ accessToken: tokens.accessToken });
        } catch (err: any) {
            res.status(400).json({ message: err.message });
        }
    }

    static async sendOtp(req: Request, res: Response) {
        try {
            const { phoneNumber } = req.body;
            const result = await AuthService.sendOtp(phoneNumber);
            res.status(200).json(result);
        } catch (err: any) {
            res.status(400).json({ message: err.message });
        }
    }

    static async verifyOtp(req: Request, res: Response) {
        try {
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

            res.status(200).json({ accessToken: tokens.accessToken });
        } catch (err: any) {
            res.status(400).json({ message: err.message });
        }
    }

    static async refresh(req: Request, res: Response) {
        try {
            const refreshToken = req.cookies?.refreshToken || req.body.refreshToken;

            if (!refreshToken) {
                return res.status(401).json({ message: "Refresh token is missing" });
            }

            const tokens = await AuthService.refresh(refreshToken);

            res.cookie("refreshToken", tokens.refreshToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
                sameSite: "strict",
                maxAge: 7 * 24 * 60 * 60 * 1000
            });

            res.status(200).json({ accessToken: tokens.accessToken });
        } catch (err: any) {
            res.status(401).json({ message: err.message });
        }
    }

    static async getSessions(req: AuthRequest, res: Response) {
        try {
            if (!req.user) return res.status(401).json({ message: "Unauthorized" });

            const sessions = await AuthService.getSessions(req.user.sub);

            res.status(200).json(sessions);
        } catch (err: any) {
            res.status(500).json({ message: err.message });
        }
    }

    static async logout(req: AuthRequest, res: Response) {
        try {
            if (!req.user) return res.status(401).json({ message: "Unauthorized" });

            const sessionId = req.body.sessionId || req.user.sid;

            await AuthService.logout(sessionId);

            res.clearCookie("refreshToken", {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
                sameSite: "strict"
            });

            res.status(200).json({ message: "Logged out successfully" });
        } catch (err: any) {
            res.status(500).json({ message: err.message });
        }
    }

    // Alias for getSessions to match user request
    static async sessions(req: AuthRequest, res: Response) {
        return AuthController.getSessions(req, res);
    }


    static async revokeSession(req: AuthRequest, res: Response) {
        try {
            if (!req.user) return res.status(401).json({ message: "Unauthorized" });
            const sessionId = req.params.id as string;
            // Pass both sessionId and userId to the service
            await AuthService.revokeSession(sessionId, req.user.sub);
            return res.json({ message: "Session revoked" });
        } catch (error: any) {
            return res.status(400).json({ message: error.message });
        }
    }

    static async revokeAllSessions(req: AuthRequest, res: Response) {
        try {
            // Fix: req.user is possibly undefined, so check it (already checked in middleware but good specifically for TS)
            if (!req.user) return res.status(401).json({ message: "Unauthorized" });
            const userId = req.user.sub;

            await AuthService.revokeAllSessions(userId);

            return res.json({ message: "All sessions revoked" });
        } catch (error: any) {
            return res.status(400).json({ message: error.message });
        }
    }
}
