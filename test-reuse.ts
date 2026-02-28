const BASE_URL = 'http://localhost:5000/api';

async function delay(ms: number) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function runTests() {
    console.log("=== Refresh Token Reuse Attack Test ===");
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
        console.log("✅ Logged in successfully. Got initial refresh token.");

        // 2. Refresh the token (Rotation)
        const refresh1Res = await fetch(`${BASE_URL}/auth/refresh`, {
            method: 'POST',
            headers: { 'Cookie': cookieVal }
        });
        const cookies2 = refresh1Res.headers.get('set-cookie');
        const refreshTokenCookie2 = cookies2?.split(',').find((c: string) => c.includes('refreshToken='));
        const cookieVal2 = refreshTokenCookie2?.split(';')[0] || '';

        console.log("✅ First refresh successful. Token rotated.");

        // 3. Attempt to reuse the FIRST refresh token
        console.log("Attempting to reuse the first (consumed) refresh token...");
        const reuseRes = await fetch(`${BASE_URL}/auth/refresh`, {
            method: 'POST',
            headers: { 'Cookie': cookieVal }
        });

        if (reuseRes.ok) {
            console.log("❌ VULNERABILITY: Reused refresh token was accepted!");
        } else if (reuseRes.status === 401) {
            console.log("✅ Protected: Reused refresh token was rejected with 401.");
        } else {
            console.log("⚠️ Unexpected status:", reuseRes.status);
        }

        // 4. Verify the SECOND refresh token is now revoked (Token Family revocation)
        console.log("Verifying if the associated Token Family was revoked...");
        await delay(500); // Give backend a moment
        const familyRes = await fetch(`${BASE_URL}/auth/refresh`, {
            method: 'POST',
            headers: { 'Cookie': cookieVal2 }
        });

        if (familyRes.ok) {
            console.log("❌ VULNERABILITY: Second refresh token is still valid. Token Family was not revoked.");
        } else if (familyRes.status === 401) {
            console.log("✅ Protected: Second refresh token was also rejected! Token Family Revocation is working!");
        } else {
            console.log("⚠️ Unexpected status:", familyRes.status);
        }

    } catch (e: any) {
        console.error("Test failed to execute:", e.message);
    }
}

runTests();
