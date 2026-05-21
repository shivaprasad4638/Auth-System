# 🔐 Secure Authentication System (JWT + TOTP 2FA)

A full-stack authentication system built from scratch to simulate production-level security architecture.

This project implements secure login flows, token management, and time-based two-factor authentication without relying on third-party auth providers.

---

## 🚀 Key Features

- Secure User Registration & Login
- Password Hashing using bcrypt
- JWT-based Access & Refresh Token System
- Role-Based Access Control (RBAC)
- Rate Limiting Middleware
- TOTP-Based Two-Factor Authentication (RFC 6238 compliant)
- Encrypted 2FA Secret Storage
- Secure Token Verification Middleware
- Prisma ORM with PostgreSQL (Supabase)

---

## 🔐 Authentication Architecture

1. User logs in with email & password
2. If 2FA enabled → backend returns `requiresTwoFactor`
3. User submits 6-digit OTP from authenticator app
4. Backend verifies OTP
5. JWT issued **only after successful OTP verification**

This ensures no token is generated before second-factor validation.

---

## 🛠 Tech Stack

### Backend
- Node.js
- Express
- Prisma ORM
- PostgreSQL (Supabase)
- JWT
- Speakeasy (TOTP)
- bcrypt

### Frontend
- React
- TypeScript
- Tailwind CSS

---

## 📦 Installation (Backend)

```bash
npm install
npx prisma migrate deploy
npm run dev
```

Create a `.env` file with:

```
DATABASE_URL=
JWT_SECRET=
ENCRYPTION_KEY=
```

---

## 🌐 Live Demo

Frontend: https://auth-dashboard-demo.vercel.app/  
Backend API: https://auth-system-q3fx.onrender.com

---

## 📌 Author
Shivaprasad Yadavannavar
