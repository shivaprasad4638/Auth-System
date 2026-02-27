import app from "./app";
import { PrismaClient } from "@prisma/client";
import dotenv from "dotenv";

dotenv.config();

// Override the env var manually just in case .env loading is weird
process.env.DATABASE_URL = "postgresql://postgres.zwspqcaxuirvqbscuqjj:Shivu%4046388@aws-0-ap-south-1.pooler.supabase.com:6543/postgres";
console.log("Using Database URL:", process.env.DATABASE_URL);

const prisma = new PrismaClient({
    datasources: {
        db: {
            url: process.env.DATABASE_URL
        }
    }
});
const PORT = 5001;
const BASE_URL = `http://localhost:${PORT}/api/auth`;

async function runTests() {
    const server = app.listen(PORT, async () => {
        console.log(`Test server running on port ${PORT}...`);
        try {
            // Clean up old test data by email
            await prisma.$executeRaw`DELETE FROM "User" WHERE email IN ('user@test.com', 'admin@test.com', 'superadmin@test.com')`;

            // 1. Register users via API
            console.log("\n--- Registering Users ---");
            const roles = ['user', 'admin', 'superadmin'];
            for (const role of roles) {
                const res = await fetch(`${BASE_URL}/register`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: `${role}@test.com`, password: 'Password123!' })
                });
                const data = await res.json();
                if (!res.ok) {
                    console.error(`Register ${role} failed:`, data);
                } else {
                    console.log(`Registered ${role}@test.com`);
                }

                // Update role in DB using safe API/raw SQL if it works, Prisma direct object is broken due to schema sync issue
                try {
                    await prisma.$executeRawUnsafe(`UPDATE "User" SET role = '${role}' WHERE email = '${role}@test.com'`);
                } catch (e) {
                    console.error(`Could not set role for ${role}, skipping manual update`);
                }
            }

            // 2. Login to get tokens
            const tokens: Record<string, string> = {};
            for (const role of roles) {
                const res = await fetch(`${BASE_URL}/login`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: `${role}@test.com`, password: 'Password123!' })
                });
                const data = await res.json();
                tokens[role] = data.accessToken;
            }

            // 3. Test RBAC endpoints
            console.log("\n--- Testing RBAC Endpoints ---");
            const endpoints = [
                { path: '/user/dashboard', allowed: ['user', 'admin', 'superadmin'] },
                { path: '/admin/dashboard', allowed: ['admin', 'superadmin'] },
                { path: '/superadmin/dashboard', allowed: ['superadmin'] }
            ];

            for (const ep of endpoints) {
                console.log(`\nEndpoint: ${ep.path}`);
                for (const role of roles) {
                    const res = await fetch(`${BASE_URL}${ep.path}`, {
                        headers: { 'Authorization': `Bearer ${tokens[role]}` }
                    });
                    const status = res.status;
                    const expectedStatus = ep.allowed.includes(role) ? 200 : 403;
                    const pass = status === expectedStatus;
                    console.log(`  [${role}] -> Expected: ${expectedStatus}, Got: ${status} | ${pass ? '✅ PASS' : '❌ FAIL'}`);
                }
            }

            // 4. Test Global Error Handler
            console.log("\n--- Testing Global Error Handler ---");
            const errRes = await fetch(`${BASE_URL}/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: 'nonexistent@test.com', password: 'WrongPassword123!' })
            });
            const errData = await errRes.json();
            const errPass = errRes.status === 401 && errData.success === false && errData.message === "Invalid credentials";
            console.log(`  Global Error format test | ${errPass ? '✅ PASS' : '❌ FAIL'}`);
            if (!errPass) console.log("    Response:", errData);

            // Clean up
            await prisma.$executeRaw`DELETE FROM "User" WHERE email IN ('user@test.com', 'admin@test.com', 'superadmin@test.com')`;
            console.log("\nCleanup done.");
        } catch (err) {
            console.error("Test error:", err);
        } finally {
            server.close();
            await prisma.$disconnect();
        }
    });
}

runTests();
