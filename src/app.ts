import express, { Request, Response, NextFunction } from "express"
import cors from "cors"
import cookieParser from "cookie-parser"
import authRoutes from "./modules/auth/auth.routes"
import { globalErrorHandler } from "./middleware/errorHandler.middleware"

const app = express()

// Configure CORS to accept credentials from the frontend
app.use(cors({
    origin: "http://localhost:5173",
    credentials: true,
}))
app.use(express.json())
app.use(cookieParser())

// Modular route definition
import userRoutes from "./modules/user/user.routes"
app.use("/api/users", userRoutes)
app.use("/api/auth", authRoutes)

app.use(globalErrorHandler as express.ErrorRequestHandler)

export default app