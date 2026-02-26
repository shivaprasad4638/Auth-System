import { Response, NextFunction } from "express";
import { AuthRequest } from "./auth.middleware";

export function authorize(allowedRoles: string[]) {
    return (req: AuthRequest, res: Response, next: NextFunction) => {
        if (!req.user) {
            return res.status(401).json({ message: "Unauthorized - User not found in request" });
        }

        if (!allowedRoles.includes((req.user as any).role)) {
            return res.status(403).json({ message: "Forbidden - Insufficient permissions" });
        }

        next();
    };
}
