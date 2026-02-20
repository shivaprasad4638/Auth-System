import express, { Request, Response, NextFunction } from "express"
import cors from "cors"
import cookieParser from "cookie-parser"
import jwt from "jsonwebtoken"
import { supabase } from "./config/supabase"
import authRoutes from "./modules/auth/auth.routes"

const app = express()

app.use(cors())
app.use(express.json())
app.use(cookieParser())
app.use("/api/auth", authRoutes)

/**
 * 🔐 Middleware: Verify Access Token
 */
function authenticateToken(
    req: Request,
    res: Response,
    next: NextFunction
) {
    const authHeader = req.headers.authorization
    const token = authHeader?.split(" ")[1]

    if (!token) return res.sendStatus(401)

    jwt.verify(
        token,
        process.env.ACCESS_TOKEN_SECRET as string,
        (err, user) => {
            if (err) return res.sendStatus(403)
                ; (req as any).user = user
            next()
        }
    )
}

/**
 * 🔒 Protected Route
 */
app.get(
    "/protected",
    authenticateToken,
    (req: Request, res: Response) => {
        res.json({
            message: "Protected success",
            user: (req as any).user,
        })
    }
)

/**
 * 🔄 Refresh Token Route
 */
app.post("/refresh", async (req: Request, res: Response) => {
    const token = req.cookies.refreshToken

    if (!token) {
        return res.status(401).json({ message: "No refresh token" })
    }

    try {
        const decoded = jwt.verify(
            token,
            process.env.REFRESH_TOKEN_SECRET as string
        ) as any

        const { data, error } = await supabase
            .from("refresh_tokens")
            .select("*")
            .eq("token", token)
            .single()

        if (error || !data) {
            return res.status(403).json({ message: "Invalid refresh token" })
        }

        const newAccessToken = jwt.sign(
            { userId: decoded.userId },
            process.env.ACCESS_TOKEN_SECRET as string,
            { expiresIn: "15m" }
        )

        res.json({ accessToken: newAccessToken })
    } catch (err) {
        return res.status(403).json({ message: "Token invalid or expired" })
    }
})

/**
 * 🚪 Logout Route
 */
app.post("/logout", async (req: Request, res: Response) => {
    const token = req.cookies.refreshToken

    if (token) {
        await supabase
            .from("refresh_tokens")
            .delete()
            .eq("token", token)
    }

    res.clearCookie("refreshToken")

    res.json({ message: "Logged out successfully" })
})

export default app