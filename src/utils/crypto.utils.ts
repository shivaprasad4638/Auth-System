import crypto from "crypto";

const ALGORITHM = "aes-256-cbc";

if (!process.env.ENCRYPTION_KEY) {
    throw new Error("FATAL ERROR: ENCRYPTION_KEY is not defined in the environment variables. Cannot start server.");
}

// Must be exactly 32 bytes (256 bits)
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

// Ensure the key is exactly 32 bytes
const getKey = () => {
    return crypto.scryptSync(ENCRYPTION_KEY, 'salt', 32);
};

export const encrypt = (text: string): string => {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(ALGORITHM, getKey(), iv);
    let encrypted = cipher.update(text, "utf8", "hex");
    encrypted += cipher.final("hex");
    return `${iv.toString("hex")}:${encrypted}`;
};

export const decrypt = (text: string): string => {
    const textParts = text.split(":");
    const iv = Buffer.from(textParts.shift() as string, "hex");
    const encryptedText = Buffer.from(textParts.join(":"), "hex");
    const decipher = crypto.createDecipheriv(ALGORITHM, getKey(), iv);
    let decrypted = decipher.update(encryptedText.toString("hex"), "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
};
