import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function main() {
    const email = "test@example.com";
    const user = await prisma.user.findUnique({
        where: { email }
    });

    if (user) {
        console.log("User:", user.email);
        console.log("2FA Enabled:", (user as any).twoFactorEnabled);
        console.log("2FA Secret exists:", !!(user as any).twoFactorSecret);
    } else {
        console.log("User not found!");
    }
}

main()
    .catch(e => {
        console.error(e)
        process.exit(1)
    })
    .finally(async () => {
        await prisma.$disconnect()
    })
