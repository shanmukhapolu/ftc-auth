import "dotenv/config";
import express from "express";
import session from "express-session";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as oidc from "openid-client";
import { applicationDefault, getApps, initializeApp } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import {
  findTeamMemberByEmail,
  getEditableProfile,
  getFirestoreClient,
  saveIdentityProfile,
  updateEditableProfile
} from "./src/firestore.js";
import { FirestoreSessionStore } from "./src/firestore-session-store.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const required = ["APP_BASE_URL", "SESSION_SECRET", "OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_REDIRECT_URI"];
for (const key of required) {
  if (!process.env[key]) {
    console.error(`Missing required environment variable: ${key}`);
    process.exit(1);
  }
}
if (process.env.SESSION_SECRET.length < 32) {
  console.error("SESSION_SECRET must be at least 32 characters.");
  process.exit(1);
}

const docsClientId = process.env.DOCS_OAUTH_CLIENT_ID || "ftc30458-documentation";
const docsRedirectUri = process.env.DOCS_REDIRECT_URI || "https://log.ftc30458.com/auth-callback.html";
const docsOrigin = process.env.DOCS_ORIGIN || new URL(docsRedirectUri).origin;
const app = express();
const production = process.env.NODE_ENV === "production";
const baseUrl = new URL(process.env.APP_BASE_URL);
app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"],
      formAction: ["'self'"]
    }
  },
  crossOriginEmbedderPolicy: false
}));
app.use(express.json({ limit: "20kb" }));

const firestore = getFirestoreClient();
if (production && !firestore) {
  console.error("Production requires FIRESTORE_ENABLED=true for durable sessions and one-time authorization codes.");
  process.exit(1);
}

app.use(session({
  name: "30458.sid",
  ...(production ? { store: new FirestoreSessionStore(firestore) } : {}),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    secure: production,
    sameSite: "lax",
    maxAge: 8 * 60 * 60 * 1000,
    path: "/"
  }
}));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: "draft-7",
  legacyHeaders: false
});
const profileLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: "draft-7",
  legacyHeaders: false
});
const oauthLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 60,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

let configPromise;
async function getConfig() {
  if (!configPromise) {
    configPromise = oidc.discovery(
      new URL(process.env.OIDC_ISSUER),
      process.env.OIDC_CLIENT_ID,
      process.env.OIDC_CLIENT_SECRET
    );
  }
  return configPromise;
}

function safeReturnPath(value) {
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//") || value.includes("\\")) return "/";
  return value;
}

function publicUser(user) {
  return {
    name: user.name || user.preferred_username || user.email || "30458 member",
    email: user.email || null,
    picture: user.picture || null,
    emailVerified: user.email_verified === true
  };
}

function requireSignIn(req, res, next) {
  if (!req.session.user) return res.redirect("/");
  next();
}

function getFirebaseAdminAuth() {
  const projectId = process.env.FIRESTORE_PROJECT_ID;
  const adminApp = getApps().find(item => item.name === "ftc30458-auth") ||
    initializeApp({
      credential: applicationDefault(),
      ...(projectId ? { projectId } : {})
    }, "ftc30458-auth");
  return getAuth(adminApp);
}

function hash(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function tokenCors(req, res) {
  if (req.headers.origin !== docsOrigin) return false;
  res.setHeader("Access-Control-Allow-Origin", docsOrigin);
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  return true;
}

app.get("/health", (_req, res) => res.json({ ok: true, service: "30458-id-portal" }));

app.get("/", (req, res) => {
  if (req.session.user) return res.redirect("/dashboard");
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/dashboard", requireSignIn, (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/auth/login", limiter, async (req, res, next) => {
  try {
    const config = await getConfig();
    const codeVerifier = oidc.randomPKCECodeVerifier();
    const codeChallenge = await oidc.calculatePKCECodeChallenge(codeVerifier);
    const state = oidc.randomState();
    const nonce = oidc.randomNonce();

    req.session.oidc = {
      codeVerifier,
      state,
      nonce,
      returnTo: safeReturnPath(req.query.returnTo)
    };

    const authorizationUrl = oidc.buildAuthorizationUrl(config, {
      redirect_uri: process.env.OIDC_REDIRECT_URI,
      response_type: "code",
      scope: process.env.OIDC_SCOPE || "openid profile email",
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      state,
      nonce
    });
    res.redirect(authorizationUrl.href);
  } catch (error) {
    next(error);
  }
});

app.get("/auth/callback", limiter, async (req, res, next) => {
  try {
    const transaction = req.session.oidc;
    if (!transaction) {
      return res.status(400).send("Your sign-in session expired. Return to the sign-in page and try again.");
    }

    const config = await getConfig();
    const tokens = await oidc.authorizationCodeGrant(
      config,
      new URL(req.originalUrl, baseUrl),
      {
        pkceCodeVerifier: transaction.codeVerifier,
        expectedState: transaction.state,
        expectedNonce: transaction.nonce
      }
    );

    const claims = tokens.claims();
    if (!claims?.sub || !claims?.iss) {
      return res.status(401).send("The identity provider did not return a valid identity.");
    }

    const identity = {
      issuer: claims.iss,
      sub: claims.sub,
      name: claims.name,
      preferred_username: claims.preferred_username,
      email: claims.email,
      email_verified: claims.email_verified,
      picture: claims.picture
    };
    const uid = hash(`${claims.iss}|${claims.sub}`);
    const pendingOAuth = req.session.pendingOAuth;

    req.session.regenerate(async error => {
      if (error) return next(error);
      try {
        req.session.user = { ...identity, uid };
        if (pendingOAuth) req.session.pendingOAuth = pendingOAuth;
        await saveIdentityProfile(uid, identity);
        const destination = safeReturnPath(transaction.returnTo);
        req.session.save(saveError => {
          if (saveError) return next(saveError);
          res.redirect(destination === "/" ? "/dashboard" : destination);
        });
      } catch (saveError) {
        next(saveError);
      }
    });
  } catch (error) {
    next(error);
  }
});

/** OAuth authorization endpoint used only by the FTC documentation site. */
app.get("/oauth/authorize", oauthLimiter, async (req, res, next) => {
  try {
    if (!firestore) {
      return res.status(503).send("Documentation sign-in is not configured yet. Enable Firestore on the central portal.");
    }
    const { client_id: clientId, redirect_uri: redirectUri, state, code_challenge: challenge, code_challenge_method: method } = req.query;
    if (
      clientId !== docsClientId ||
      redirectUri !== docsRedirectUri ||
      typeof state !== "string" || !/^[A-Za-z0-9._~-]{16,256}$/.test(state) ||
      typeof challenge !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(challenge) ||
      method !== "S256"
    ) {
      return res.status(400).send("Invalid documentation sign-in request.");
    }

    req.session.pendingOAuth = { clientId, redirectUri, state, challenge };
    if (!req.session.user) {
      return req.session.save(error => {
        if (error) return next(error);
        res.redirect("/auth/login?returnTo=%2Foauth%2Fcontinue");
      });
    }
    res.redirect("/oauth/continue");
  } catch (error) {
    next(error);
  }
});

app.get("/oauth/continue", requireSignIn, oauthLimiter, async (req, res, next) => {
  try {
    const pending = req.session.pendingOAuth;
    if (!pending || pending.clientId !== docsClientId || pending.redirectUri !== docsRedirectUri) {
      return res.status(400).send("The documentation sign-in request expired. Return to the documentation site and try again.");
    }
    delete req.session.pendingOAuth;

    const identity = req.session.user;
    if (!identity.email || identity.email_verified !== true) {
      return res.status(403).send("Your identity provider must provide a verified email address for team access.");
    }

    const member = await findTeamMemberByEmail(identity.email);
    if (!member || member.active === false) {
      return res.status(403).send("This account is not an active FTC 30458 documentation member. Ask a team administrator to add your email to the team roster.");
    }

    const code = crypto.randomBytes(32).toString("base64url");
    const codeId = hash(code);
    await firestore.collection(process.env.FIRESTORE_OAUTH_CODES_COLLECTION || "identityOAuthCodes").doc(codeId).create({
      clientId: pending.clientId,
      redirectUri: pending.redirectUri,
      challenge: pending.challenge,
      firebaseUid: member.uid,
      email: identity.email.toLowerCase(),
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 90 * 1000)
    });

    const callback = new URL(pending.redirectUri);
    callback.searchParams.set("code", code);
    callback.searchParams.set("state", pending.state);
    req.session.save(error => {
      if (error) return next(error);
      res.redirect(callback.href);
    });
  } catch (error) {
    next(error);
  }
});

app.options("/oauth/token", (req, res) => {
  if (!tokenCors(req, res)) return res.status(403).end();
  res.status(204).end();
});

app.post("/oauth/token", oauthLimiter, async (req, res, next) => {
  try {
    if (!tokenCors(req, res)) return res.status(403).json({ error: "Origin not allowed." });
    if (!firestore) return res.status(503).json({ error: "Documentation sign-in is not configured yet." });
    const { code, code_verifier: verifier, client_id: clientId, redirect_uri: redirectUri } = req.body || {};
    if (
      clientId !== docsClientId ||
      redirectUri !== docsRedirectUri ||
      typeof code !== "string" || code.length < 32 ||
      typeof verifier !== "string" || !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)
    ) {
      return res.status(400).json({ error: "Invalid authorization-code request." });
    }

    const codeRef = firestore.collection(process.env.FIRESTORE_OAUTH_CODES_COLLECTION || "identityOAuthCodes").doc(hash(code));
    let authorization = null;
    await firestore.runTransaction(async transaction => {
      const snapshot = await transaction.get(codeRef);
      if (!snapshot.exists) return;
      const data = snapshot.data();
      const expiresAt = data.expiresAt?.toDate?.() || new Date(data.expiresAt);
      const actualChallenge = crypto.createHash("sha256").update(verifier).digest("base64url");
      if (
        expiresAt <= new Date() ||
        data.clientId !== clientId ||
        data.redirectUri !== redirectUri ||
        data.challenge !== actualChallenge
      ) {
        return;
      }
      authorization = data;
      transaction.delete(codeRef);
    });

    if (!authorization) return res.status(400).json({ error: "The sign-in code is invalid, expired, or already used." });

    const customToken = await getFirebaseAdminAuth().createCustomToken(authorization.firebaseUid);
    res.setHeader("Cache-Control", "no-store");
    res.json({ firebaseToken: customToken });
  } catch (error) {
    next(error);
  }
});

app.post("/auth/logout", (req, res, next) => {
  req.session.destroy(error => {
    if (error) return next(error);
    res.clearCookie("30458.sid", { path: "/" });
    res.status(204).end();
  });
});

app.get("/api/me", async (req, res, next) => {
  try {
    if (!req.session.user) return res.status(401).json({ authenticated: false });
    const profile = await getEditableProfile(req.session.user.uid, req.session.user);
    res.json({
      authenticated: true,
      user: {
        ...publicUser(req.session.user),
        displayName: profile.displayName,
        bio: profile.bio,
        profileEditable: profile.editable
      }
    });
  } catch (error) {
    next(error);
  }
});

app.put("/api/me/profile", requireSignIn, profileLimiter, async (req, res, next) => {
  try {
    if (!req.is("application/json")) return res.status(415).json({ error: "Send profile updates as JSON." });
    const displayName = typeof req.body?.displayName === "string" ? req.body.displayName.trim() : "";
    const bio = typeof req.body?.bio === "string" ? req.body.bio.trim() : "";
    if (!displayName || displayName.length > 60) {
      return res.status(400).json({ error: "Display name must be between 1 and 60 characters." });
    }
    if (bio.length > 240) return res.status(400).json({ error: "Bio must be 240 characters or fewer." });
    await updateEditableProfile(req.session.user.uid, { displayName, bio });
    res.json({ ok: true, displayName, bio });
  } catch (error) {
    if (error?.code === "PROFILE_STORAGE_DISABLED") {
      return res.status(503).json({ error: "Profile editing is not enabled yet. The administrator needs to configure Firestore." });
    }
    next(error);
  }
});

app.use(express.static(path.join(__dirname, "public"), {
  index: false,
  etag: true,
  maxAge: production ? "1h" : 0
}));

app.use((error, _req, res, _next) => {
  console.error("Request failed:", error);
  if (error?.cause) console.error("Underlying cause:", error.cause);
  res.status(500).send("Something went wrong while processing your request. Check server logs.");
});

const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`30458 ID portal listening on ${baseUrl.origin} (port ${port})`));
