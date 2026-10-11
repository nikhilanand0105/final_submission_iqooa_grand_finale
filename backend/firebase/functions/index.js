'use strict';
/**
 * Saathi backend entry point: one HTTPS function ("api") that routes POST /<path> to domain.js.
 * Every request must carry a Firebase ID token (Authorization: Bearer ...), verified here with the Admin SDK.
 * Secrets: WEBRISK_API_KEY (Secret Manager). No secrets ship in either Android app.
 */
const { onRequest } = require('firebase-functions/v2/https');
const { defineSecret } = require('firebase-functions/params');
const { initializeApp } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');
const { getAuth } = require('firebase-admin/auth');
const { getMessaging } = require('firebase-admin/messaging');
const { handle } = require('./src/domain');
const { FirestoreStore } = require('./src/firestoreStore');
const { makeWebRisk } = require('./src/webrisk');

initializeApp();
const WEBRISK_API_KEY = defineSecret('WEBRISK_API_KEY');
const store = new FirestoreStore(getFirestore());

const notifier = {
  /** Sends a data+notification message to the recipient's registered Saathi Personal devices via FCM. */
  async send(tokens, data) {
    const res = await getMessaging().sendEachForMulticast({
      tokens,
      data: Object.fromEntries(Object.entries(data).map(([k, v]) => [k, String(v)])),
      notification: { title: 'Saathi: help request', body: `${data.senderDisplayName} asked you for help. Open Saathi Personal.` },
      android: { priority: 'high' },
    });
    return { successCount: res.successCount, failureCount: res.failureCount };
  },
};

exports.api = onRequest({ region: 'asia-south1', secrets: [WEBRISK_API_KEY], cors: false, maxInstances: 20 }, async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: { code: 'METHOD_NOT_ALLOWED', message: 'POST only' } });
  const header = req.get('Authorization') || '';
  const m = header.match(/^Bearer (.+)$/);
  if (!m) return res.status(401).json({ error: { code: 'UNAUTHENTICATED', message: 'Missing token' } });
  let decoded;
  try {
    decoded = await getAuth().verifyIdToken(m[1], true);
  } catch (e) {
    return res.status(401).json({ error: { code: 'UNAUTHENTICATED', message: 'Invalid token' } });
  }
  const ctx = { uid: decoded.uid, provider: decoded.firebase && decoded.firebase.sign_in_provider };
  const webRisk = makeWebRisk(WEBRISK_API_KEY.value());
  const out = await handle(req.path, ctx, req.body, { store, notifier, webRisk });
  res.status(out.http).json(out.body);
});
