const fs = require('fs');
const BASE_URL = 'http://localhost:5000/api/auth';

function log(msg) {
    fs.appendFileSync('api-test.log', msg + '\n');
}

async function runApiTests() {
    log("--- Starting API Tests without Prisma ---");

    try {
        // 1. Register superadmin
        log("Registering superadmin...");
        const regRes = await fetch(`${BASE_URL}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: `api_superadmin${Date.now()}@test.com`, password: 'Password123!' })
        });
        const regData = await regRes.json();
        log(`Register status: ${regRes.status} | Data: ${JSON.stringify(regData)}`);

        // 2. Login to get token
        log("Logging in...");
        const loginRes = await fetch(`${BASE_URL}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: regData.user?.email || `api_superadmin@test.com`, password: 'Password123!' })
        });
        const loginData = await loginRes.json();
        const token = loginData.accessToken;
        log(`Login status: ${loginRes.status}, Has token: ${!!token}`);

        // 3. Test RBAC endpoints - Since API registration defaults to 'user' role
        log("\nTesting Endpoints as bare 'user':");

        const eps = [
            '/user/dashboard',
            '/admin/dashboard',
            '/superadmin/dashboard'
        ];

        for (const ep of eps) {
            const res = await fetch(`${BASE_URL}${ep}`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            log(`GET ${ep} -> Status: ${res.status}`);
        }

        // 4. Test Global Error Handler
        log("\nTesting Global Error Handler (Invalid login):");
        const errRes = await fetch(`${BASE_URL}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: 'nonexistent@test.com', password: 'WrongPassword123!' })
        });
        const errData = await errRes.json();
        log(`Status mapping: ${errRes.status} | Data: ${JSON.stringify(errData)}`);

        // 5. Cleanup session (logout)
        await fetch(`${BASE_URL}/logout`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        log("Finished API tests.");

    } catch (e) {
        log(`Error: ${e.message}`);
    }
}

// clear log
fs.writeFileSync('api-test.log', '');
runApiTests();
