import express, { Request, Response, NextFunction } from "express"
import cors from "cors"
import helmet from "helmet"
import cookieParser from "cookie-parser"
import authRoutes from "./modules/auth/auth.routes"
import userRoutes from "./modules/user/user.routes"
import { globalErrorHandler } from "./middleware/errorHandler.middleware"

const app = express()

// Trust reverse proxy (Render, Railway, Heroku, etc.)
app.set("trust proxy", 1)

// Security headers
app.use(helmet())

// Configure CORS — use CORS_ORIGIN env var in production
app.use(cors({
    origin: process.env.CORS_ORIGIN || "http://localhost:5173",
    credentials: true,
}))

app.use(express.json())
app.use(cookieParser())

// Health check endpoint (required by most hosting platforms)
app.get("/health", (req, res) => {
    res.status(200).json({ status: "ok", timestamp: new Date().toISOString() })
})

// Modular route definition
app.use("/api/users", userRoutes)
app.use("/api/auth", authRoutes)

app.use(globalErrorHandler as express.ErrorRequestHandler)

export default app