import { Router } from "express";
import { AuthController } from "./auth.controller";
import { authenticate } from "../../middleware/auth.middleware";
import { authorize } from "../../middleware/rbac.middleware";
import { loginRateLimiter } from "../../middleware/rateLimit.middleware";

const router = Router();

router.post("/register", AuthController.register);
router.post("/login", loginRateLimiter, AuthController.login);
router.post("/refresh", AuthController.refresh);
router.post("/logout", authenticate, AuthController.logout);

router.get("/sessions", authenticate, AuthController.sessions);
router.delete("/sessions/:id", authenticate, AuthController.revokeSession);
router.delete("/sessions", authenticate, AuthController.revokeAllSessions);

// 👇 TEST ROUTES
router.get("/protected", (req, res) => {
    res.json({ message: "Protected working" })
})

router.get("/profile", authenticate, (req, res) => {
    res.json({ message: "Profile access granted", user: (req as any).user });
});

// RBAC Testing
router.get("/user/dashboard", authenticate, authorize(["user", "admin", "superadmin"]), (req, res) => {
    res.json({ message: "User Dashboard access granted", user: (req as any).user });
});

router.get("/admin/dashboard", authenticate, authorize(["admin", "superadmin"]), (req, res) => {
    res.json({ message: "Admin Dashboard access granted", user: (req as any).user });
});

router.get("/superadmin/dashboard", authenticate, authorize(["superadmin"]), (req, res) => {
    res.json({ message: "Superadmin Dashboard access granted", user: (req as any).user });
});

router.post("/send-otp", AuthController.sendOtp);
router.post("/verify-otp", AuthController.verifyOtp);

export default router;
