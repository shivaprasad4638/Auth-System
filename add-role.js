const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function main() {
    try {
        await prisma.$executeRawUnsafe('ALTER TABLE "User" ADD COLUMN "role" TEXT NOT NULL DEFAULT \'user\'');
        console.log('Role column added successfully.');
    } catch (e) {
        console.error('Error adding role column:', e);
    } finally {
        await prisma.$disconnect();
    }
}

main();
