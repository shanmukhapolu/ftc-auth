# 30458 ID — Central Sign-in Portal

The Team 30458 central identity portal. Auth0 verifies the member's credentials; this service then issues a short-lived, one-time authorization code to the FTC documentation site. The documentation site exchanges that code for a Firebase custom token and signs into Firebase Authentication. Firestore remains the documentation database.

## Sign-in architecture

1. The member opens `https://log.ftc30458.com` and selects **Continue to 30458 ID**.
2. The browser redirects to `https://auth.ftc30458.com`.
3. Auth0 authenticates the member and returns them to this portal.
4. This portal requires a verified email and matches it against an active document in the documentation project's `users` collection.
5. The matching Firestore document ID is used as the Firebase UID. This preserves the existing UID and its Firestore ownership rules.
6. A 90-second, single-use authorization code protected by PKCE is sent to the documentation callback. The documentation site exchanges it server-to-server with this portal and signs in using Firebase `signInWithCustomToken`.

The browser never receives the Auth0 client secret or Firebase service-account credentials. Firebase custom tokens are returned only after an approved roster match. Never add a public sign-up route to this service.

## Required environment

Set these values in the central portal's hosting environment:

- `APP_BASE_URL=https://auth.ftc30458.com`
- `OIDC_REDIRECT_URI=https://auth.ftc30458.com/auth/callback`
- `FIRESTORE_ENABLED=true`
- `FIRESTORE_PROJECT_ID=ftcdocumentation-53b62`
- `FIRESTORE_TEAM_USERS_COLLECTION=users`
- `DOCS_OAUTH_CLIENT_ID=ftc30458-documentation`
- `DOCS_ORIGIN=https://log.ftc30458.com`
- `DOCS_REDIRECT_URI=https://log.ftc30458.com/auth-callback.html`
- A random `SESSION_SECRET` of at least 32 characters.
- Auth0 issuer, client ID, client secret, and scope `openid profile email`.

The portal needs Google Application Default Credentials for the same Firebase project. Locally, set `GOOGLE_APPLICATION_CREDENTIALS` to a service-account JSON file stored outside this repository. In production, attach a service account to the hosting runtime with permission to read the `users` roster, write the portal's Firestore collections, and mint Firebase custom tokens. Never commit or paste the JSON key.

Firestore collections used by this portal:
- `identityProfiles`: central portal profile metadata.
- `identitySessions`: persistent Express sessions in production.
- `identityOAuthCodes`: hashed, short-lived, one-time authorization-code records.

## Auth0 application settings

For the Auth0 Regular Web Application, configure:

- Allowed Callback URLs: `https://auth.ftc30458.com/auth/callback`
- Allowed Logout URLs: `https://auth.ftc30458.com`
- Allowed Web Origins: `https://auth.ftc30458.com`

Keep local callback URLs only if local portal testing is needed.

## Local development

1. Use Node.js 20 or newer.
2. Run `npm install`.
3. Copy `.env.example` to `.env`.
4. Set Auth0 credentials, a random session secret, Firestore project ID, and local Google Application Default Credentials.
5. Set `APP_BASE_URL` and the Auth0 callback URI to your local origin for local Auth0 testing. For the live documentation integration, the docs callback and origin must remain the exact production URLs above.
6. Run `npm run dev`.

Production uses a Firestore-backed Express session store. Development uses the in-memory session store. Authorization codes are stored in Firestore and are single-use.

## Important security behavior

- A user must have `email_verified: true` from Auth0.
- Their email must match exactly (case-insensitive) one active document in `users`.
- The Firestore document ID is used as the Firebase UID, so existing document ownership remains intact.
- Redirect URI and browser Origin are exact allowlists.
- The authorization flow uses PKCE S256, state, 90-second codes, and one-time atomic redemption.
- Firestore Admin SDK operations bypass Firestore Security Rules. The server therefore performs the team membership check before minting any Firebase token.
- Signing out of the documentation app signs out its Firebase session. The Auth0 browser session may remain active, allowing SSO on the next sign-in.

Do not expose the Firebase Admin service account, Auth0 client secret, session secret, or custom tokens in source control or browser logs.
