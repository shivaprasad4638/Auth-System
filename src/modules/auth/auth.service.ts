import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import prisma from "../../config/prisma";
import { v4 as uuidv4 } from "uuid";
import { AppError } from "../../utils/AppError";

const ACCESS_TOKEN_EXPIRES = "15m";
const REFRESH_TOKEN_EXPIRES_DAYS = 7;

export class AuthService {

    static async register(email: string, password: string, phoneNumber?: string, userAgent?: string, ip?: string) {
        // Validate Email
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!email.trim() || !emailRegex.test(email.trim())) {
            throw new AppError("Invalid email format", 400);
        }

        // Validate Password (8+ characters, 1 uppercase, 1 number, 1 special character)
        const passwordRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        if (!passwordRegex.test(password)) {
            throw new AppError("Password must be at least 8 characters long, contain 1 uppercase letter, 1 number, and 1 special character", 400);
        }

        const normalizedPhone = phoneNumber?.trim();

        const existingUser = await prisma.user.findFirst({
            where: {
                OR: [
                    { email },
                    normalizedPhone ? { phoneNumber: normalizedPhone } : undefined
                ].filter(Boolean) as any
            },
        });

        if (existingUser) {
            throw new AppError("User already exists", 409);
        }

        const passwordHash = await bcrypt.hash(password, 12);

        const user = await prisma.user.create({
            data: {
                email: email.trim(),
                passwordHash,
                phoneNumber: normalizedPhone,
                avatarSeed: email.trim(),
            },
        });

        const sessionId = uuidv4();

        const refreshToken = jwt.sign(
            { sub: user.id, sid: sessionId, role: (user as any).role, email: user.email },
            process.env.REFRESH_TOKEN_SECRET!,
            { expiresIn: `${REFRESH_TOKEN_EXPIRES_DAYS}d` }
        );

        const accessToken = jwt.sign(
            { sub: user.id, sid: sessionId, role: (user as any).role, email: user.email },
            process.env.ACCESS_TOKEN_SECRET!,
            { expiresIn: ACCESS_TOKEN_EXPIRES }
        );

        const tokenHash = await bcrypt.hash(refreshToken, 10);

        await prisma.session.create({
            data: {
                id: sessionId,
                userId: user.id,
                tokenHash,
                userAgent,
                ip,
                expiresAt: new Date(
                    Date.now() + REFRESH_TOKEN_EXPIRES_DAYS * 24 * 60 * 60 * 1000
                ),
            },
        });

        return { user, accessToken, refreshToken };
    }

    static async login(email: string, password: string, userAgent?: string, ip?: string) {
        const user = await prisma.user.findUnique({
            where: { email },
        });

        if (!user) throw new AppError("Invalid credentials", 401);

        if (user.lockedUntil && user.lockedUntil > new Date()) {
            throw new AppError("Account temporarily locked due to too many failed attempts.", 403);
        }

        const validPassword = await bcrypt.compare(password, user.passwordHash || "");

        if (!validPassword) {
            const nextFailedAttempts = user.failedAttempts + 1;
            const lockedUntil = nextFailedAttempts >= 5 ? new Date(Date.now() + 15 * 60 * 1000) : null;

            await prisma.user.update({
                where: { id: user.id },
                data: {
                    failedAttempts: nextFailedAttempts,
                    lockedUntil: lockedUntil
                },
            });

            if (lockedUntil) {
                throw new AppError("Account temporarily locked due to too many failed attempts.", 403);
            } else {
                throw new AppError("Invalid credentials", 401);
            }
        }

        // reset failed attempts
        await prisma.user.update({
            where: { id: user.id },
            data: { failedAttempts: 0, lockedUntil: null },
        });

        const sessionId = uuidv4();

        const refreshToken = jwt.sign(
            { sub: user.id, sid: sessionId, role: (user as any).role, email: user.email },
            process.env.REFRESH_TOKEN_SECRET!,
            { expiresIn: `${REFRESH_TOKEN_EXPIRES_DAYS}d` }
        );

        const accessToken = jwt.sign(
            { sub: user.id, sid: sessionId, role: (user as any).role, email: user.email },
            process.env.ACCESS_TOKEN_SECRET!,
            { expiresIn: ACCESS_TOKEN_EXPIRES }
        );

        const tokenHash = await bcrypt.hash(refreshToken, 10);

        await prisma.session.create({
            data: {
                id: sessionId,
                userId: user.id,
                tokenHash,
                userAgent,
                ip,
                expiresAt: new Date(
                    Date.now() + REFRESH_TOKEN_EXPIRES_DAYS * 24 * 60 * 60 * 1000
                ),
            },
        });

        return {
            accessToken,
            refreshToken,
            user: { id: user.id, email: user.email, role: (user as any).role, avatarSeed: (user as any).avatarSeed || user.email, avatarStyle: (user as any).avatarStyle }
        };
    }

    static async sendOtp(phoneNumber: string) {

        const normalizedPhone = phoneNumber.trim();

        const user = await prisma.user.findUnique({
            where: { phoneNumber: normalizedPhone },
        });

        console.log("Searching for phone:", normalizedPhone);
        console.log("User found:", user);

        if (!user) {
            throw new AppError("User not found", 404);
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000);

        await prisma.user.update({
            where: { id: user.id },
            data: {
                otp,
                otpExpiresAt,
            },
        });

        console.log(`OTP for ${normalizedPhone}: ${otp}`);

        return { message: "OTP sent successfully" };
    }

    static async verifyOtp(
        phoneNumber: string,
        otp: string,
        userAgent?: string,
        ip?: string
    ) {

        const normalizedPhone = phoneNumber.trim();

        const user = await prisma.user.findUnique({
            where: { phoneNumber: normalizedPhone },
        });

        if (!user || !user.otp || !user.otpExpiresAt) {
            throw new AppError("Invalid OTP", 401);
        }

        if (new Date() > user.otpExpiresAt) {
            throw new AppError("OTP expired", 401);
        }

        if (user.otp !== otp) {
            throw new AppError("Invalid OTP", 401);
        }

        await prisma.user.update({
            where: { id: user.id },
            data: {
                otp: null,
                otpExpiresAt: null,
            },
        });

        const sessionId = uuidv4();

        const refreshToken = jwt.sign(
            { sub: user.id, sid: sessionId, role: (user as any).role, email: user.email },
            process.env.REFRESH_TOKEN_SECRET!,
            { expiresIn: `${REFRESH_TOKEN_EXPIRES_DAYS}d` }
        );

        const accessToken = jwt.sign(
            { sub: user.id, sid: sessionId, role: (user as any).role, email: user.email },
            process.env.ACCESS_TOKEN_SECRET!,
            { expiresIn: ACCESS_TOKEN_EXPIRES }
        );

        const tokenHash = await bcrypt.hash(refreshToken, 10);

        await prisma.session.create({
            data: {
                id: sessionId,
                userId: user.id,
                tokenHash,
                userAgent,
                ip,
                expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
            },
        });

        return {
            accessToken,
            refreshToken,
            user: { id: user.id, email: user.email, role: (user as any).role, avatarSeed: (user as any).avatarSeed || user.email, avatarStyle: (user as any).avatarStyle }
        };
    }

    static async refresh(refreshToken: string) {
        let payload: any;
        try {
            payload = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET!);
        } catch (error) {
            throw new AppError("Invalid refresh token", 401);
        }

        const session = await prisma.session.findUnique({
            where: { id: payload.sid },
            include: { user: true }
        });

        if (!session) {
            throw new AppError("Invalid session", 401);
        }

        if (session.revokedAt) {
            // SECURITY WARNING: Token Reuse Detected!
            // This indicates a stolen refresh token is being used.
            // We must instantly revoke ALL active sessions for this user (Token Family Revocation).
            await prisma.session.updateMany({
                where: { userId: session.userId, revokedAt: null },
                data: { revokedAt: new Date() }
            });
            throw new AppError("Session revoked due to token reuse detection.", 401);
        }

        const tokenValid = await bcrypt.compare(refreshToken, session.tokenHash);

        if (!tokenValid) {
            await prisma.session.update({
                where: { id: session.id },
                data: { revokedAt: new Date() }
            });
            throw new AppError("Invalid refresh token", 401);
        }

        // Revoke old session
        await prisma.session.update({
            where: { id: session.id },
            data: { revokedAt: new Date() },
        });

        // Create new session ID
        const newSessionId = uuidv4();

        // Generate new tokens
        // payload.sub is usually the userId string
        const newRefreshToken = jwt.sign(
            { sub: payload.sub, sid: newSessionId, role: payload.role, email: payload.email },
            process.env.REFRESH_TOKEN_SECRET!,
            { expiresIn: `${REFRESH_TOKEN_EXPIRES_DAYS}d` }
        );

        const newAccessToken = jwt.sign(
            { sub: payload.sub, sid: newSessionId, role: payload.role, email: payload.email },
            process.env.ACCESS_TOKEN_SECRET!,
            { expiresIn: ACCESS_TOKEN_EXPIRES }
        );

        const newTokenHash = await bcrypt.hash(newRefreshToken, 10);

        // Create new session row
        await prisma.session.create({
            data: {
                id: newSessionId,
                userId: session.userId, // Use existing session userId for safety
                tokenHash: newTokenHash,
                userAgent: session.userAgent,
                ip: session.ip,
                expiresAt: new Date(
                    Date.now() + REFRESH_TOKEN_EXPIRES_DAYS * 24 * 60 * 60 * 1000
                ),
            },
        });

        return {
            accessToken: newAccessToken,
            refreshToken: newRefreshToken,
            user: { id: payload.sub, email: payload.email, role: payload.role, avatarSeed: session.user?.avatarSeed || payload.email, avatarStyle: (session.user as any)?.avatarStyle }
        };
    }

    static async getSessions(userId: string) {
        const sessions = await prisma.session.findMany({
            where: { userId },
            orderBy: { createdAt: "desc" },
        });

        return sessions.map((session) => ({
            id: session.id,
            userAgent: session.userAgent,
            ip: session.ip,
            createdAt: session.createdAt,
            expiresAt: session.expiresAt,
            revokedAt: session.revokedAt,
            isCurrent: false, // Controller can determine this if needed, or pass current sessionId here
        }));
    }

    static async revokeSession(sessionId: string, userId: string) {
        const session = await prisma.session.findUnique({
            where: { id: sessionId },
        });

        if (!session || session.userId !== userId) {
            throw new AppError("Session not found or unauthorized", 404);
        }

        await prisma.session.update({
            where: { id: sessionId },
            data: { revokedAt: new Date() },
        });

        return { message: "Session revoked" };
    }

    static async revokeAllSessions(userId: string) {
        await prisma.session.updateMany({
            where: { userId, revokedAt: null },
            data: { revokedAt: new Date() },
        });

        return { message: "All sessions revoked" };
    }

    static async logout(sessionId: string) {
        await prisma.session.update({
            where: { id: sessionId },
            data: { revokedAt: new Date() },
        });
    }
}
