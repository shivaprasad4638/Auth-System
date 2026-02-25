import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function main() {
    try {
        console.log("Starting manual migration...");
        await prisma.$executeRawUnsafe('ALTER TABLE "User" ADD COLUMN "isVerified" BOOLEAN NOT NULL DEFAULT false;');
        console.log("Migration complete!");
    } catch (e: any) {
        if (e.message.includes('already exists')) {
            console.log("Column isVerified already exists. Continuing...");
        } else {
            console.error("Migration failed:", e);
        }
    } finally {
        await prisma.$disconnect();
    }
}

main();
