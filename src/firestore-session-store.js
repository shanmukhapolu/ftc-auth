import session from "express-session";

/** Small Firestore-backed express-session store for the central identity portal. */
export class FirestoreSessionStore extends session.Store {
  constructor(firestore) {
    super();
    this.collection = firestore.collection(
      process.env.FIRESTORE_SESSIONS_COLLECTION || "identitySessions"
    );
  }

  get(sid, callback) {
    this.collection.doc(sid).get()
      .then(async snapshot => {
        if (!snapshot.exists) return callback(null, null);
        const data = snapshot.data();
        const expiresAt = data.expiresAt?.toDate?.() || new Date(data.expiresAt);
        if (expiresAt <= new Date()) {
          await snapshot.ref.delete();
          return callback(null, null);
        }
        callback(null, JSON.parse(data.sessionJson));
      })
      .catch(callback);
  }

  set(sid, sess, callback = () => {}) {
    const maxAge = Number(sess.cookie?.maxAge) || 8 * 60 * 60 * 1000;
    const expiresAt = sess.cookie?.expires
      ? new Date(sess.cookie.expires)
      : new Date(Date.now() + maxAge);
    this.collection.doc(sid).set({
      sessionJson: JSON.stringify(sess),
      expiresAt,
      updatedAt: new Date()
    }).then(() => callback(null)).catch(callback);
  }

  touch(sid, sess, callback = () => {}) {
    const maxAge = Number(sess.cookie?.maxAge) || 8 * 60 * 60 * 1000;
    const expiresAt = sess.cookie?.expires
      ? new Date(sess.cookie.expires)
      : new Date(Date.now() + maxAge);
    this.collection.doc(sid).update({ expiresAt, updatedAt: new Date() })
      .then(() => callback(null)).catch(callback);
  }

  destroy(sid, callback = () => {}) {
    this.collection.doc(sid).delete()
      .then(() => callback(null)).catch(callback);
  }
}
