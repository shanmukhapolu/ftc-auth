import "dotenv/config";
import express from "express";
import session from "express-session";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as oidc from "openid-client";
import { saveIdentityProfile } from "./src/firestore.js";

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

const app = express();
const production = process.env.NODE_ENV === "production";
const baseUrl = new URL(process.env.APP_BASE_URL);
// This app is deployed behind one reverse proxy (GitHub Codespaces / hosting ingress).
// Trust only the immediately preceding proxy hop so forwarded client IPs work with rate limiting.
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

// express-session's default MemoryStore is suitable only for local development.
// Do not bypass this check in production: configure a durable session store first.
if (production) {
  console.error("Production startup blocked: configure a persistent express-session store before deployment.");
  process.exit(1);
}

app.use(session({
  name: "30458.sid",
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
  if (!req.session.user) {
    return res.redirect(`/auth/login?returnTo=${encodeURIComponent(req.originalUrl || "/dashboard")}`);
  }
  next();
}

app.get("/health", (_req, res) => res.json({ ok: true, service: "30458-id-portal" }));

// Smart homepage: signed-out visitors see sign-in; signed-in visitors go to dashboard.
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
    const uid = crypto.createHash("sha256").update(`${claims.iss}|${claims.sub}`).digest("hex");

    // Rotate the session identifier after successful authentication.
    req.session.regenerate(async (error) => {
      if (error) return next(error);
      try {
        req.session.user = { ...identity, uid };
        await saveIdentityProfile(uid, identity);
        const destination = safeReturnPath(transaction.returnTo);
        req.session.save((saveError) => {
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

app.post("/auth/logout", (req, res, next) => {
  req.session.destroy((error) => {
    if (error) return next(error);
    res.clearCookie("30458.sid", { path: "/" });
    res.status(204).end();
  });
});

app.get("/api/me", (req, res) => {
  if (!req.session.user) return res.status(401).json({ authenticated: false });
  res.json({ authenticated: true, user: publicUser(req.session.user) });
});

app.use(express.static(path.join(__dirname, "public"), {
  index: false,
  etag: true,
  maxAge: production ? "1h" : 0
}));

app.use((error, _req, res, _next) => {
  console.error("Request failed:", error?.message || "Unknown error");
  res.status(500).send("Something went wrong while processing your request. Please try again.");
});

const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`30458 ID portal listening on ${baseUrl.origin} (port ${port})`));
