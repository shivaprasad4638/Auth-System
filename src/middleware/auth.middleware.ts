import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

export interface AuthRequest extends Request {
    user?: { sub: string; sid: string };
}

export function authenticate(
    req: AuthRequest,
    res: Response,
    next: NextFunction
) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ message: "Unauthorized" });
    }

    const token = authHeader.split(" ")[1];

    try {
        const payload = jwt.verify(
            token,
            process.env.ACCESS_TOKEN_SECRET!
        ) as { sub: string; sid: string };

        req.user = payload;
        next();
    } catch (error) {
        console.error("Auth Middleware Error:", error);
        return res.status(401).json({ message: "Invalid token" });
    }
}
