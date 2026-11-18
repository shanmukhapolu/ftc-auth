# 30458 ID — Central Sign-in Portal

This repository contains the first implementation of the Team 30458 identity portal.

## Architecture: important distinction

This app is an **OpenID Connect relying party (client)**, not itself an OAuth authorization server or identity provider. The configured identity provider (for example Auth0) performs credential verification and issues OIDC tokens. This project starts sign-in, validates the OIDC response, and establishes its own server-side session.

For SSO, register each application (logging, training, future tools) as a separate client with the **same identity provider**. The provider's shared login session enables SSO. Each app validates its own callback and maintains its own session. Do not copy cookies or tokens between apps.

Suggested hosts:
- auth.ftc30458.com: this portal.
- log.ftc30458.com: logging app, separately registered OIDC client.
- training.ftc30458.com: training app, separately registered OIDC client.
- Optional provider-branded login hostname such as login.ftc30458.com, if supported and configured separately.

## Stack

Node.js 20+, Express, static HTML/CSS/JavaScript, OpenID Connect via openid-client (Authorization Code + PKCE), optional Firestore profile metadata.

Firestore is not required for OAuth. It stores only profile metadata in this starter, not passwords or OAuth tokens.

## Local setup

1. Install Node.js 20+.
2. Run npm install.
3. Copy .env.example to .env.
4. Create a confidential web application in your OIDC provider dashboard.
5. Configure issuer, client ID, client secret, redirect URI and a random session secret.
6. Add http://localhost:3000/auth/callback as an exact allowed callback URL.
7. Run npm run dev and visit http://localhost:3000.

For Auth0, the issuer is commonly https://TENANT.us.auth0.com/ (use the exact issuer shown by your provider).

## Optional Firestore

Set FIRESTORE_ENABLED=true, configure FIRESTORE_PROJECT_ID, and provide Google Application Default Credentials to the server runtime. The server writes a minimal profile keyed by SHA-256 of issuer|sub.

Never put service-account credentials in public/ or browser JavaScript. Firestore Admin SDK bypasses Firestore Security Rules; every server endpoint accessing private data must enforce authorization itself.

## Deployment warning

The default Express MemoryStore is for local development only. This app deliberately refuses production startup unless ALLOW_IN_MEMORY_SESSIONS=true is set. Do not set that flag for real deployment. Before production, configure a durable express-session store (for example Redis or a properly maintained Firestore-backed store), HTTPS, secure cookies, secret-manager environment variables, monitoring and logging.

This is a development starter, not a production-ready identity platform. Authentication is not authorization: login must not automatically grant access to every team application. Add team membership provisioning, app-specific roles, permissions and audit trails before connecting real user data.

## Security features

Authorization Code flow, PKCE S256, state and nonce validation, exact redirect URI, HttpOnly/SameSite session cookie, Secure cookie in production, Helmet headers/CSP, rate limiting, safe local-only return path. No passwords or provider tokens are written to Firestore.

## Next milestones

1. Choose/configure the OIDC provider.
2. Add persistent production session storage.
3. Build team-member provisioning, app registry, roles and permissions.
4. Register logging and training as separate OIDC clients.
5. Plan migration of existing Firebase Auth users without losing Firestore records.
