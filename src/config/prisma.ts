import { PrismaClient } from "@prisma/client";
import "dotenv/config"; // Ensure env vars are loaded

console.log("Prisma initializing...");
console.log("DATABASE_URL defined:", !!process.env.DATABASE_URL);
if (process.env.DATABASE_URL) {
    console.log("DATABASE_URL host:", process.env.DATABASE_URL.split('@')[1]); // Log safe part of URL
}
const prismaClientSingleton = () => {
    return new PrismaClient({
        log: ['query', 'info', 'warn', 'error'],
    });
};

declare global {
    var prisma: undefined | ReturnType<typeof prismaClientSingleton>;
}

const prisma = globalThis.prisma ?? prismaClientSingleton();

if (process.env.NODE_ENV !== "production") globalThis.prisma = prisma;

export default prisma;
