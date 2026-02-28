import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
    console.log("Migrating old users to have an avatarSeed...");

    // Perform raw SQL update as prisma updateMany cannot reference other columns
    const result = await prisma.$executeRawUnsafe(`
        UPDATE "User"
        SET "avatarSeed" = email
        WHERE "avatarSeed" IS NULL;
    `);

    console.log(`Successfully migrated ${result} users.`);
}

main()
    .catch((e) => {
        console.error(e);
        process.exit(1);
    })
    .finally(async () => {
        await prisma.$disconnect();
    });
