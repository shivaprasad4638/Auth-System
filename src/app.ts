import express from "express";
import cors from "cors";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import authRoutes from "./modules/auth/auth.routes";

const app = express();

/**
 * Security Middlewares
 */
app.use(helmet());

app.set("trust proxy", 1); // important if behind proxy (like Render, Vercel, etc.)

app.use(
    cors({
        origin: "http://localhost:5173",
        credentials: true,
    })
);

app.use(express.json());
app.use(cookieParser());

/**
 * Routes
 */
app.use("/api/auth", authRoutes);

app.get("/health", (req, res) => {
    res.status(200).json({ message: "Auth system running" });
});

/**
 * 404 Handler
 */
app.use((req, res) => {
    res.status(404).json({ message: "Route not found" });
});

/**
 * Global Error Handler
 */
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
    console.error(err);

    res.status(500).json({
        message: "Internal server error",
    });
});
export default app;
