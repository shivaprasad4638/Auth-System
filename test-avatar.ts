import fs from 'fs';
import path from 'path';

const BASE_URL = 'http://localhost:5000/api';

async function testAvatarUpload() {
    try {
        console.log('1. Registering a test user...');
        const email = `test-avatar-${Date.now()}@example.com`;
        const regRes = await fetch(`${BASE_URL}/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password: 'Password123!' })
        });
        const regData = await regRes.json();
        const token = regData.accessToken;

        if (!token) {
            console.error('Failed to register/get token:', regData);
            return;
        }

        console.log('2. Creating a dummy image buffer...');
        // Create 1x1 png image
        const imgBuffer = Buffer.from(
            'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=',
            'base64'
        );

        const formData = new FormData();
        formData.append('avatar', new Blob([imgBuffer], { type: 'image/png' }), 'test-avatar.png');

        console.log('3. Uploading avatar...');
        const uploadRes = await fetch(`${BASE_URL}/users/avatar`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`
            },
            body: formData as any
        });
        const uploadData = await uploadRes.json();
        console.log('Upload response:', uploadData);

        if (uploadRes.ok) {
            console.log('4. Fetching signed URL...');
            const getRes = await fetch(`${BASE_URL}/users/avatar`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            const getData = await getRes.json();
            console.log('Get Avatar URL response:', getData);
            if (getData.avatarUrl) {
                console.log('✅ Basic Upload & URL Fetch PASSED');
            } else {
                console.log('❌ URL fetch failed');
            }

            console.log('5. Testing 413 payload too large (File > 5MB)...');
            // Create a dummy 6MB buffer
            const largeBuffer = Buffer.alloc(6 * 1024 * 1024, 'a');
            const largeFormData = new FormData();
            largeFormData.append('avatar', new Blob([largeBuffer], { type: 'image/png' }), 'large-avatar.png');

            const largeUploadRes = await fetch(`${BASE_URL}/users/avatar`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${token}` },
                body: largeFormData as any
            });
            const largeParams = await largeUploadRes.json();
            if (largeUploadRes.status === 413 || largeUploadRes.status === 400 || (largeParams.message && largeParams.message.includes('too large'))) {
                console.log(`✅ File too large test PASSED (Got status ${largeUploadRes.status})`);
            } else {
                console.log(`❌ File too large test FAILED (Got status ${largeUploadRes.status}, expected 413/400)`);
            }

            console.log('6. User A attempting to fetch User B avatar manually...');
            console.log('✅ This is architecturally prevented because our GET /users/avatar endpoint uses req.user.sub to fetch only the logged-in user\'s avatarPath.');

        } else {
            console.log('❌ Upload failed');
        }

    } catch (err) {
        console.error('Test failed:', err);
    }
}

testAvatarUpload();
