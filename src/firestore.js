import { Firestore } from "@google-cloud/firestore";

let db;

export function getFirestoreClient() {
  if (process.env.FIRESTORE_ENABLED !== "true") return null;
  if (!db) {
    db = new Firestore({
      projectId: process.env.FIRESTORE_PROJECT_ID || undefined
    });
  }
  return db;
}

/** Look up an existing team account by verified email. The Firestore document ID
 * becomes the Firebase UID, preserving the documentation app's existing identity. */
export async function findTeamMemberByEmail(email) {
  const firestore = getFirestoreClient();
  if (!firestore) {
    const error = new Error("Firestore is required for team account verification.");
    error.code = "FIRESTORE_DISABLED";
    throw error;
  }

  const normalizedEmail = String(email || "").trim().toLowerCase();
  if (!normalizedEmail) return null;

  const collection = process.env.FIRESTORE_TEAM_USERS_COLLECTION || "users";
  // The team roster is small. A normalized comparison avoids case-sensitive
  // email mismatches in older profile documents.
  const snapshot = await firestore.collection(collection).get();
  const matches = snapshot.docs.filter(document =>
    String(document.data().email || "").trim().toLowerCase() === normalizedEmail
  );

  if (matches.length === 0) return null;
  if (matches.length > 1) {
    throw new Error("More than one team profile uses this email address. Resolve the duplicate before sign-in.");
  }

  const member = matches[0];
  return { ...member.data(), uid: member.id };
}

/** Stores profile metadata only. Never store passwords or provider tokens here. */
export async function saveIdentityProfile(uid, identity) {
  const firestore = getFirestoreClient();
  if (!firestore) return;

  const collection = process.env.FIRESTORE_USERS_COLLECTION || "identityProfiles";
  await firestore.collection(collection).doc(uid).set({
    uid,
    issuer: identity.issuer,
    subject: identity.sub,
    name: identity.name || null,
    preferredUsername: identity.preferred_username || null,
    email: identity.email || null,
    emailVerified: identity.email_verified === true,
    picture: identity.picture || null,
    lastLoginAt: new Date(),
    updatedAt: new Date()
  }, { merge: true });
}

export async function getEditableProfile(uid, identity) {
  const firestore = getFirestoreClient();
  const fallback = {
    displayName: identity.name || identity.preferred_username || identity.email || "30458 member",
    bio: ""
  };
  if (!firestore) return { ...fallback, editable: false };

  const collection = process.env.FIRESTORE_USERS_COLLECTION || "identityProfiles";
  const snapshot = await firestore.collection(collection).doc(uid).get();
  const data = snapshot.exists ? snapshot.data() : {};
  return {
    displayName: data.displayName || fallback.displayName,
    bio: data.bio || "",
    editable: true
  };
}

export async function updateEditableProfile(uid, updates) {
  const firestore = getFirestoreClient();
  if (!firestore) {
    const error = new Error("Profile storage is not enabled.");
    error.code = "PROFILE_STORAGE_DISABLED";
    throw error;
  }

  const collection = process.env.FIRESTORE_USERS_COLLECTION || "identityProfiles";
  await firestore.collection(collection).doc(uid).set({
    displayName: updates.displayName,
    bio: updates.bio,
    updatedAt: new Date()
  }, { merge: true });
}
