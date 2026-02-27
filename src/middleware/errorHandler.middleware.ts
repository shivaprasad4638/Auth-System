import { Request, Response, NextFunction } from "express";

export const globalErrorHandler = (
    err: any,
    req: Request,
    res: Response,
    next: NextFunction
) => {
    const statusCode = err.statusCode || err.status || 500;
    const message = err.message || "Internal Server Error";

    // Optionally log the full error in development
    if (process.env.NODE_ENV !== "production") {
        console.error("Global Error Handler:", err);
    }

    res.status(statusCode).json({
        success: false,
        message: message,
        stack: process.env.NODE_ENV === "production" ? undefined : err.stack,
    });
};
