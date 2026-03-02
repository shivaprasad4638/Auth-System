import rateLimit from "express-rate-limit";

// Limit login attempts to 10 per 15 minutes
export const loginRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // Limit each IP to 10 requests per windowMs
    message: { message: "Too many login attempts, please try again after 15 minutes." },
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

// Limit 2FA attempts to 5 per 5 minutes
export const twoFaRateLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 5, // Limit each IP to 5 requests per windowMs
    message: { message: "Too many 2FA code attempts, please try again after 5 minutes." },
    standardHeaders: true,
    legacyHeaders: false,
});
