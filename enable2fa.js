const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function main() {
    console.log('Connecting to database...');
    try {
        const user = await prisma.user.update({
            where: { email: 'test@example.com' },
            data: {
                twoFactorEnabled: true,
                twoFactorSecret: '6dd80a71f0084f702758f1f547c8f2ba:204439c656365b321a41add0c7a5256e26ac2c67e812d35eb14afde63f15fe6f610afcc2529ee0e7bb113ec4e477d9c6bed60144f866415fe881d77a28ebbd3bd8aeeabf3ca126'
            }
        });
        console.log('Successfully updated test@example.com:');
        console.log('twoFactorEnabled:', user.twoFactorEnabled);
    } catch (error) {
        console.error('Failed to update user:', error);
    } finally {
        await prisma.$disconnect();
    }
}

main();
