import fs from 'fs';
import path from 'path';

const BASE_URL = 'http://localhost:5000/api';

async function testSelectAvatar() {
    try {
        console.log('1. Registering a test user for avatar selection...');
        const email = `test-select-avatar-${Date.now()}@example.com`;
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

        console.log('2. Attempting to select a valid default avatar...');

        const validSelectRes = await fetch(`${BASE_URL}/users/avatar/select`, {
            method: 'PATCH',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ avatarPath: 'defaults/male-1.png' })
        });
        const validSelectData = await validSelectRes.json();
        console.log('Select valid avatar response:', validSelectRes.status, validSelectData);

        if (validSelectRes.ok) {
            console.log('✅ Valid Selection PASSED');
        } else {
            console.log('❌ Valid Selection FAILED');
        }

        console.log('3. Attempting to select an invalid/malicious avatar path...');
        const invalidSelectRes = await fetch(`${BASE_URL}/users/avatar/select`, {
            method: 'PATCH',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ avatarPath: '../../other-user/avatar.png' })
        });
        const invalidSelectData = await invalidSelectRes.json();
        console.log('Select invalid avatar response:', invalidSelectRes.status, invalidSelectData);

        if (invalidSelectRes.status === 400) {
            console.log('✅ Security Test PASSED (Rejected invalid path)');
        } else {
            console.log('❌ Security Test FAILED (Accepted invalid path)');
        }

        console.log('4. Fetching the signed URL for the selected default avatar...');
        const getRes = await fetch(`${BASE_URL}/users/avatar`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        const getData = await getRes.json();
        console.log('Get Avatar URL result:', getRes.status);
        if (getData.avatarUrl) {
            console.log('✅ URL Generation for Default Avatar PASSED');
        } else {
            console.log('❌ URL Generation FAILED');
        }

    } catch (err) {
        console.error('Test failed:', err);
    }
}

testSelectAvatar();
