const BASE_URL = 'http://localhost:5000/api';

async function runTests() {
    console.log("=== Parallel Refresh Race Condition Test ===");
    try {
        // 1. Login to get initial tokens
        const loginRes = await fetch(`${BASE_URL}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: "test@example.com", password: "Password123!" })
        });

        const cookies = loginRes.headers.get('set-cookie');
        if (!cookies) throw new Error("No cookies returned from login");
        const refreshTokenCookie = cookies.split(',').find((c: string) => c.includes('refreshToken='));
        if (!refreshTokenCookie) throw new Error("No refresh token cookie found");

        const cookieVal = refreshTokenCookie.split(';')[0];
        console.log("✅ Logged in successfully. Firing simultaneous refresh requests...");

        // 2. Fire two refresh requests at the exact same time
        const req1 = fetch(`${BASE_URL}/auth/refresh`, { method: 'POST', headers: { 'Cookie': cookieVal } });
        const req2 = fetch(`${BASE_URL}/auth/refresh`, { method: 'POST', headers: { 'Cookie': cookieVal } });

        const results = await Promise.allSettled([req1, req2]);

        let successes = 0;
        let failures = 0;

        for (const res of results) {
            if (res.status === 'fulfilled' && res.value.ok) {
                successes++;
            } else {
                failures++;
            }
        }

        console.log(`Results: ${successes} succeeded, ${failures} failed.`);

        if (successes > 1) {
            console.log("❌ VULNERABILITY: Race Condition! Both simultaneous requests succeeded!");
        } else if (successes === 1 && failures === 1) {
            console.log("✅ Protected: Only one refresh request succeeded. Race condition mitigated.");
        } else {
            console.log("⚠️ Unexpected result: both failed.");
        }

    } catch (e: any) {
        console.error("Test setup failed:", e.message);
    }
}

runTests();
