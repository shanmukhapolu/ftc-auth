# 30458 ID — Central Sign-in Portal

The Team 30458 identity portal. It uses Auth0 (or another OIDC provider) for authentication and maintains its own server-side application session.

## Current implementation

- Node.js 20+, Express, HTML/CSS/JavaScript.
- OpenID Connect Authorization Code flow with PKCE, state and nonce validation.
- `/` is the sign-in landing page when logged out and redirects signed-in users to `/dashboard`.
- `/dashboard` requires an authenticated session.
- `/auth/login` and `/auth/callback` handle OIDC sign-in; `POST /auth/logout` ends the local portal session.
- `/api/me` returns the signed-in user's basic profile.
- Optional Firestore profile metadata; it is disabled by default.

This app is an **OIDC relying party/client**, not an identity provider or OAuth authorization server. Auth0 verifies credentials. Do not store passwords or provider tokens in Firestore.

## Auth0 setup

Create an Auth0 **Regular Web Application**. In its Settings, configure these exact local URLs:

- Allowed Callback URLs: `http://localhost:3000/auth/callback`
- Allowed Logout URLs: `http://localhost:3000`
- Allowed Web Origins: `http://localhost:3000`

Use the Auth0 tenant domain shown in the dashboard as the issuer, with a trailing slash, for example `https://YOUR_TENANT.us.auth0.com/`.

## Local setup

1. Install Node.js 20 or newer.
2. Clone this repository.
3. Run `npm install`.
4. Copy `.env.example` to `.env`.
5. Fill in `OIDC_ISSUER`, `OIDC_CLIENT_ID`, and `OIDC_CLIENT_SECRET` from the Auth0 application's Basic Information.
6. Generate a separate random `SESSION_SECRET` with at least 32 characters. Do not use the Auth0 Client Secret as the session secret.
7. Run `npm run dev` and open `http://localhost:3000`.

Never commit `.env`, expose the Client Secret in browser JavaScript, or paste it into chats/issues.

## Domain plan

The portal itself is intended to live at **`auth.ftc30458.com`**. Its pages and routes stay on that one hostname. The Auth0 tenant domain is currently the OIDC issuer and may appear briefly during the hosted sign-in redirect. A custom Auth0 login domain is a separate DNS/routing decision; do not point `auth.ftc30458.com` at Auth0 while also expecting it to serve this Express portal unless a supported proxy/routing design has been configured.

When deploying the portal, update the Auth0 URLs to the production origin:
- Allowed Callback URLs: `https://auth.ftc30458.com/auth/callback`
- Allowed Logout URLs: `https://auth.ftc30458.com`
- Allowed Web Origins: `https://auth.ftc30458.com`

Set `APP_BASE_URL=https://auth.ftc30458.com` and `OIDC_REDIRECT_URI=https://auth.ftc30458.com/auth/callback` in the hosting provider's environment settings. Keep the local URLs too if local development will continue.

## Sessions and production readiness

The current Express MemoryStore is **development-only**. The server intentionally refuses to start with `NODE_ENV=production` until a persistent `express-session` store is implemented and configured. Do not remove this guard or enable MemoryStore in production. Before public deployment, add a maintained persistent store (for example Redis), HTTPS, secure cookies, secret-managed environment variables, monitoring, and operational backups.

Authentication is not authorization. A successful login must not automatically grant every team member access to every team tool. Add explicit team membership, roles, permissions, account provisioning, and audit logging before connecting real team data.

## SSO across team applications

Register Logging, Training, and future applications as separate OIDC clients with the same Auth0 tenant. Each app needs its own callback URL and its own session. Auth0's shared login session can provide SSO; do not copy cookies or tokens between applications. Do not migrate the existing Logging app's Firebase Authentication until the new flow has been tested and a deliberate account-migration plan is ready.

## Optional Firestore

Set `FIRESTORE_ENABLED=true`, configure `FIRESTORE_PROJECT_ID`, and provide Google Application Default Credentials to the server runtime. The server writes basic profile metadata keyed by a SHA-256 hash of issuer and subject. Never place service-account credentials in `public/` or browser code. Firestore Admin SDK bypasses Firestore Security Rules, so backend endpoints must enforce authorization themselves.

## Security notes

The implementation uses PKCE S256, state and nonce validation, exact redirect URI matching, an HttpOnly/SameSite session cookie, Helmet security headers, rate limiting, and a local-path-only post-login redirect. The portal is an early development starter, not a production-ready identity platform.
