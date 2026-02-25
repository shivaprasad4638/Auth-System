import express, { Request, Response, NextFunction } from "express"
import cors from "cors"
import cookieParser from "cookie-parser"
import authRoutes from "./modules/auth/auth.routes"

const app = express()

// Configure CORS to accept credentials from the frontend
app.use(cors({
    origin: "http://localhost:5173",
    credentials: true,
}))
app.use(express.json())
app.use(cookieParser())

// Modular auth routes definition
app.use("/api/auth", authRoutes)

export default app