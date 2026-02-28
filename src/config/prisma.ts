import { PrismaClient } from "@prisma/client";
import "dotenv/config"; // Ensure env vars are loaded

const prismaClientSingleton = () => {
    return new PrismaClient({
        log: process.env.NODE_ENV === "production"
            ? ['warn', 'error']
            : ['query', 'info', 'warn', 'error'],
    });
};

declare global {
    var prisma: undefined | ReturnType<typeof prismaClientSingleton>;
}

const prisma = globalThis.prisma ?? prismaClientSingleton();

if (process.env.NODE_ENV !== "production") globalThis.prisma = prisma;

export default prisma;
