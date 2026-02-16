import { PrismaClient } from "@prisma/client";
import "dotenv/config";

const prisma = new PrismaClient({
    log: ['query', 'info', 'warn', 'error'],
});

async function main() {
    console.log("Testing database connection...");
    console.log("URL:", process.env.DATABASE_URL?.replace(/:[^:@]*@/, ":****@")); // Hide password
    try {
        await prisma.$connect();
        console.log("Successfully connected!");
        const count = await prisma.user.count();
        console.log(`User count: ${count}`);
    } catch (e) {
        console.error("Connection failed:", e);
    } finally {
        await prisma.$disconnect();
    }
}

main();
