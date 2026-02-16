import { Router } from "express";
import { AuthController } from "./auth.controller";
import { authenticate } from "../../middleware/auth.middleware";

const router = Router();

router.post("/register", AuthController.register);
router.post("/login", AuthController.login);
router.post("/refresh", AuthController.refresh);
router.post("/logout", authenticate, AuthController.logout);

router.get("/sessions", authenticate, AuthController.sessions);
router.delete("/sessions/:id", authenticate, AuthController.revokeSession);
router.delete("/sessions", authenticate, AuthController.revokeAllSessions);

router.post("/send-otp", AuthController.sendOtp);
router.post("/verify-otp", AuthController.verifyOtp);

export default router;
