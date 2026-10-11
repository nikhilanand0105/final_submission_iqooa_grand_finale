'use strict';
/**
 * Saathi family pairing + help request domain logic.
 * Pure functions over an injected store/notifier so they can be unit-tested without Firebase.
 * Every authorisation decision is made here, on the server; clients are never trusted for pairing state.
 */
const crypto = require('crypto');

const CODE_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; // Crockford base32 (no I, L, O, U)
const CODE_LENGTH = 8;
const CODE_TTL_MS = 10 * 60 * 1000;
const MAX_ACTIVE_CODES_PER_FAMILY = 3;
const REDEEM_ATTEMPTS_PER_HOUR = 10;
const HELP_REQUESTS_PER_HOUR = 10;
const REASONS = new Set(['someone_mean', 'pressure', 'shared_by_mistake', 'unsafe', 'something_else']);
const LOCATION_CHOICES = new Set(['not_shared', 'shared', 'permission_denied', 'unavailable']);

class ApiError extends Error {
  constructor(http, code, message) {
    super(message);
    this.http = http;
    this.code = code;
  }
}

const err = (http, code, message) => new ApiError(http, code, message);

function sha256(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

function newCode(randomBytes = crypto.randomBytes) {
  const bytes = randomBytes(CODE_LENGTH);
  let out = '';
  for (let i = 0; i < CODE_LENGTH; i++) out += CODE_ALPHABET[bytes[i] & 31]; // 256 % 32 == 0: unbiased
  return out;
}

function normalizeCode(raw) {
  if (typeof raw !== 'string') return null;
  let s = raw.toUpperCase().replace(/[\s-]/g, '').replace(/O/g, '0').replace(/[IL]/g, '1');
  if (s.length !== CODE_LENGTH) return null;
  for (const c of s) if (!CODE_ALPHABET.includes(c)) return null;
  return s;
}

function cleanName(v, field) {
  if (typeof v !== 'string') throw err(400, 'INVALID_ARGUMENT', `${field} is required`);
  const t = v.trim();
  if (!t || t.length > 40 || !/^[\p{L}\p{M}\p{N} .'-]+$/u.test(t)) throw err(400, 'INVALID_ARGUMENT', `${field} is not valid`);
  return t;
}

function requireAuth(ctx) {
  if (!ctx || !ctx.uid) throw err(401, 'UNAUTHENTICATED', 'Sign-in required');
}

/** Parents must use a real (non-anonymous) account in Saathi Personal. */
function requireParentAccount(ctx) {
  requireAuth(ctx);
  if (!ctx.provider || ctx.provider === 'anonymous') throw err(403, 'PARENT_ACCOUNT_REQUIRED', 'Adults must sign in with a full account');
}

async function rateLimit(tx, key, limit, now) {
  const hour = Math.floor(now / 3600000);
  const id = `${key}:${hour}`;
  const doc = await tx.get('rateLimits', id);
  const count = doc ? doc.count : 0;
  if (count >= limit) throw err(429, 'RATE_LIMITED', 'Too many attempts, try again later');
  await tx.set('rateLimits', id, { count: count + 1, expiresAt: (hour + 2) * 3600000 });
}

async function audit(tx, now, event, data) {
  await tx.set('audit', `${now}-${crypto.randomBytes(6).toString('hex')}`, { event, at: now, ...data });
}

async function memberOf(tx, familyId, uid) {
  return tx.get(`families/${familyId}/members`, uid);
}

async function activeParent(tx, familyId, uid) {
  const m = await memberOf(tx, familyId, uid);
  if (!m || m.role !== 'parent' || m.status !== 'active') throw err(403, 'NOT_AUTHORIZED', 'Not an adult in this family');
  return m;
}

// ------------------------------------------------------------------ parent (Saathi Personal)

async function createFamily(ctx, body, { store, now }) {
  requireParentAccount(ctx);
  const displayName = cleanName(body.displayName, 'displayName');
  const adultName = cleanName(body.adultDisplayName || 'Parent', 'adultDisplayName');
  return store.transaction(async (tx) => {
    const familyId = crypto.randomUUID();
    await tx.set('families', familyId, { displayName, createdBy: ctx.uid, createdAt: now });
    await tx.set(`families/${familyId}/members`, ctx.uid, { role: 'parent', displayName: adultName, status: 'active', joinedAt: now });
    await tx.set('userFamilies', ctx.uid, { familyId, role: 'parent' });
    await audit(tx, now, 'family_created', { familyId, by: ctx.uid });
    return { familyId };
  });
}

async function createPairingCode(ctx, body, { store, now, randomBytes }) {
  requireParentAccount(ctx);
  const familyId = body.familyId;
  if (typeof familyId !== 'string') throw err(400, 'INVALID_ARGUMENT', 'familyId is required');
  return store.transaction(async (tx) => {
    await activeParent(tx, familyId, ctx.uid);
    const live = (await tx.query('pairingCodes', [['familyId', familyId]])).filter((c) => !c.usedAt && c.expiresAt > now);
    if (live.length >= MAX_ACTIVE_CODES_PER_FAMILY) throw err(429, 'RATE_LIMITED', 'Too many active codes');
    const code = newCode(randomBytes);
    const expiresAt = now + CODE_TTL_MS;
    // Only a hash of the code is stored, so a database leak does not reveal usable codes.
    await tx.set('pairingCodes', sha256(code), { familyId, createdBy: ctx.uid, createdAt: now, expiresAt, usedAt: null, usedBy: null });
    await audit(tx, now, 'code_created', { familyId, by: ctx.uid, expiresAt });
    return { code: `${code.slice(0, 4)}-${code.slice(4)}`, expiresAt };
  });
}

async function confirmPairing(ctx, body, { store, now }) {
  requireParentAccount(ctx);
  return store.transaction(async (tx) => {
    const p = await tx.get('pairings', body.pairingId);
    if (!p) throw err(404, 'NOT_FOUND', 'No such pairing');
    await activeParent(tx, p.familyId, ctx.uid);
    if (p.status === 'revoked') throw err(409, 'PAIRING_REVOKED', 'Pairing was revoked');
    if (p.status !== 'active') {
      await tx.update('pairings', body.pairingId, { status: 'active', confirmedAt: now, confirmedBy: ctx.uid });
      await tx.update(`families/${p.familyId}/members`, p.childUid, { status: 'active' });
      await audit(tx, now, 'pairing_confirmed', { pairingId: body.pairingId, by: ctx.uid });
    }
    return { pairingId: body.pairingId, status: 'active' };
  });
}

async function registerDevice(ctx, body, { store, now }) {
  requireParentAccount(ctx);
  if (typeof body.token !== 'string' || body.token.length < 20 || body.token.length > 4096) throw err(400, 'INVALID_ARGUMENT', 'token is invalid');
  await store.transaction(async (tx) => {
    await tx.set(`devices/${ctx.uid}/tokens`, sha256(body.token), { token: body.token, updatedAt: now });
  });
  return { ok: true };
}

async function acknowledgeHelp(ctx, body, { store, now }) {
  requireParentAccount(ctx);
  return store.transaction(async (tx) => {
    const r = await tx.get('helpRequests', body.requestId);
    if (!r) throw err(404, 'NOT_FOUND', 'No such request');
    if (r.recipientUid !== ctx.uid) throw err(403, 'NOT_AUTHORIZED', 'Not the recipient of this request');
    if (r.status === 'cancelled') throw err(409, 'CANCELLED', 'The child cancelled this request');
    if (r.status !== 'acknowledged') {
      await tx.update('helpRequests', body.requestId, { status: 'acknowledged', acknowledgedAt: now, updatedAt: now });
    }
    return { requestId: body.requestId, status: 'acknowledged' };
  });
}

async function listHelpForRecipient(ctx, body, { store }) {
  requireParentAccount(ctx);
  const rows = await store.query('helpRequests', [['recipientUid', ctx.uid]]);
  return { requests: rows.map(publicHelp).sort((a, b) => b.createdAt - a.createdAt).slice(0, 50) };
}

/** Lists pairings (pending, active, revoked) of the calling adult's family so Personal can confirm or revoke them. */
async function listPairings(ctx, body, { store }) {
  requireParentAccount(ctx);
  return store.transaction(async (tx) => {
    const uf = await tx.get('userFamilies', ctx.uid);
    if (!uf || uf.role !== 'parent') return { pairings: [] };
    await activeParent(tx, uf.familyId, ctx.uid);
    const rows = await tx.query('pairings', [['familyId', uf.familyId]]);
    return {
      familyId: uf.familyId,
      pairings: rows.map((p) => ({ pairingId: p.id, childDisplayName: p.childDisplayName, status: p.status, createdAt: p.createdAt,
        confirmedAt: p.confirmedAt || null, revokedAt: p.revokedAt || null })).sort((a, b) => b.createdAt - a.createdAt),
    };
  });
}

// ------------------------------------------------------------------ child (Saathi Kids)

async function redeemPairingCode(ctx, body, { store, now }) {
  requireAuth(ctx);
  const code = normalizeCode(body.code);
  const childName = cleanName(body.childDisplayName, 'childDisplayName');
  // Counted in its own transaction so failed guesses still count toward the limit.
  await store.transaction((tx) => rateLimit(tx, `redeem:${ctx.uid}`, REDEEM_ATTEMPTS_PER_HOUR, now));
  if (!code) throw err(404, 'INVALID_CODE', 'Code not recognised');
  return store.transaction(async (tx) => {
    // Firestore transactions require all reads before any write.
    const existing = await tx.get('userFamilies', ctx.uid);
    if (existing) {
      const ep = existing.pairingId ? await tx.get('pairings', existing.pairingId) : null;
      if (existing.role === 'parent' || (ep && ep.status !== 'revoked')) throw err(409, 'ALREADY_PAIRED', 'Already in a family');
    }
    const key = sha256(code);
    const c = await tx.get('pairingCodes', key);
    if (!c) throw err(404, 'INVALID_CODE', 'Code not recognised');
    if (c.usedAt) throw err(409, 'CODE_USED', 'Code already used');
    if (c.expiresAt <= now) throw err(410, 'EXPIRED_CODE', 'Code expired');
    const fam = await tx.get('families', c.familyId);
    if (!fam) throw err(404, 'INVALID_CODE', 'Code not recognised');
    const pairingId = crypto.randomUUID();
    await tx.update('pairingCodes', key, { usedAt: now, usedBy: ctx.uid });
    await tx.set('pairings', pairingId, {
      familyId: c.familyId, childUid: ctx.uid, childDisplayName: childName, status: 'pending_parent_confirmation',
      createdAt: now, codeCreatedBy: c.createdBy,
    });
    await tx.set(`families/${c.familyId}/members`, ctx.uid, { role: 'child', displayName: childName, status: 'pending', joinedAt: now });
    await tx.set('userFamilies', ctx.uid, { familyId: c.familyId, role: 'child', pairingId });
    await audit(tx, now, 'code_redeemed', { familyId: c.familyId, pairingId, by: ctx.uid });
    return { status: 'pending_parent_confirmation', pairingId, familyDisplayName: fam.displayName, adults: [] };
  });
}

async function familyStatus(ctx, body, { store }) {
  requireAuth(ctx);
  return store.transaction(async (tx) => {
    const uf = await tx.get('userFamilies', ctx.uid);
    if (!uf || uf.role !== 'child' || !uf.pairingId) return { status: 'none' };
    const p = await tx.get('pairings', uf.pairingId);
    if (!p) return { status: 'none' };
    const fam = await tx.get('families', p.familyId);
    const out = { status: p.status, pairingId: uf.pairingId, familyDisplayName: fam ? fam.displayName : '' };
    if (p.status === 'active') {
      const members = await tx.query(`families/${p.familyId}/members`, []);
      const adults = [];
      for (const m of members) {
        if (m.role !== 'parent' || m.status !== 'active') continue;
        const tokens = await tx.query(`devices/${m.id}/tokens`, []);
        adults.push({ uid: m.id, displayName: m.displayName, canReceiveHelp: true, hasNotificationDevice: tokens.length > 0 });
      }
      out.adults = adults;
    } else {
      out.adults = [];
    }
    return out;
  });
}

async function revokePairing(ctx, body, { store, now }) {
  requireAuth(ctx);
  return store.transaction(async (tx) => {
    const p = await tx.get('pairings', body.pairingId);
    if (!p) throw err(404, 'NOT_FOUND', 'No such pairing');
    const isChild = p.childUid === ctx.uid;
    const parent = !isChild ? await memberOf(tx, p.familyId, ctx.uid) : null;
    if (!isChild && !(parent && parent.role === 'parent' && parent.status === 'active')) throw err(403, 'NOT_AUTHORIZED', 'Not allowed');
    if (p.status !== 'revoked') {
      await tx.update('pairings', body.pairingId, { status: 'revoked', revokedAt: now, revokedBy: ctx.uid });
      await tx.update(`families/${p.familyId}/members`, p.childUid, { status: 'revoked' });
      await audit(tx, now, 'pairing_revoked', { pairingId: body.pairingId, by: ctx.uid });
    }
    return { pairingId: body.pairingId, status: 'revoked' };
  });
}

function validLocation(loc) {
  if (loc == null) return null;
  const { lat, lng, accuracyM, capturedAt } = loc;
  const num = (x) => typeof x === 'number' && Number.isFinite(x);
  if (!num(lat) || !num(lng) || lat < -90 || lat > 90 || lng < -180 || lng > 180) throw err(400, 'INVALID_ARGUMENT', 'bad location');
  return { lat: Math.round(lat * 1000) / 1000, lng: Math.round(lng * 1000) / 1000,
    accuracyM: num(accuracyM) ? Math.max(accuracyM, 100) : null, capturedAt: num(capturedAt) ? capturedAt : null };
}

async function createHelpRequest(ctx, body, { store, now, notifier }) {
  requireAuth(ctx);
  const key = body.idempotencyKey;
  if (typeof key !== 'string' || !/^[0-9a-f-]{16,64}$/i.test(key)) throw err(400, 'INVALID_ARGUMENT', 'idempotencyKey is invalid');
  if (!REASONS.has(body.reason)) throw err(400, 'INVALID_ARGUMENT', 'reason is invalid');
  const choice = body.locationChoice || 'not_shared';
  if (!LOCATION_CHOICES.has(choice)) throw err(400, 'INVALID_ARGUMENT', 'locationChoice is invalid');
  const location = choice === 'shared' ? validLocation(body.location) : null;
  if (choice === 'shared' && !location) throw err(400, 'INVALID_ARGUMENT', 'location missing');
  let note = null;
  if (body.note != null) {
    if (typeof body.note !== 'string') throw err(400, 'INVALID_ARGUMENT', 'note is invalid');
    note = body.note.trim().slice(0, 280) || null;
  }
  const requestId = sha256(`${ctx.uid}:${key}`).slice(0, 32); // deterministic → idempotent

  const early = await store.get('helpRequests', requestId);
  if (early) return { ...publicHelp({ id: requestId, ...early }), deduplicated: true };
  await store.transaction((tx) => rateLimit(tx, `help:${ctx.uid}`, HELP_REQUESTS_PER_HOUR, now));
  const created = await store.transaction(async (tx) => {
    const dup = await tx.get('helpRequests', requestId);
    if (dup) return { dup };
    const uf = await tx.get('userFamilies', ctx.uid);
    if (!uf || uf.role !== 'child' || !uf.pairingId) throw err(403, 'NOT_PAIRED', 'Not paired');
    const p = await tx.get('pairings', uf.pairingId);
    if (!p) throw err(403, 'NOT_PAIRED', 'Not paired');
    if (p.status === 'revoked') throw err(403, 'PAIRING_REVOKED', 'Pairing revoked');
    if (p.status !== 'active') throw err(403, 'NOT_PAIRED', 'Pairing not confirmed');
    const rec = await memberOf(tx, p.familyId, body.recipientUid);
    if (!rec || rec.role !== 'parent' || rec.status !== 'active') throw err(403, 'RECIPIENT_NOT_AUTHORIZED', 'Recipient not allowed');
    const doc = {
      familyId: p.familyId, pairingId: uf.pairingId, senderUid: ctx.uid, senderDisplayName: p.childDisplayName,
      recipientUid: body.recipientUid, reason: body.reason, note, locationChoice: choice, location,
      idempotencyKey: key, status: 'accepted', createdAt: now, updatedAt: now, notification: null,
    };
    await tx.set('helpRequests', requestId, doc);
    return { doc };
  });
  if (created.dup) return { ...publicHelp({ id: requestId, ...created.dup }), deduplicated: true };

  // Notification happens after the request is safely stored. Its result is reported, not assumed.
  const tokens = (await store.query(`devices/${body.recipientUid}/tokens`, [])).map((t) => t.token);
  let status = 'accepted';
  let notification = { attemptedAt: now, sent: 0, failed: 0, recipientHasDevice: tokens.length > 0 };
  if (tokens.length > 0 && notifier) {
    try {
      const res = await notifier.send(tokens, { type: 'help_request', requestId, reason: body.reason, senderDisplayName: created.doc.senderDisplayName });
      notification.sent = res.successCount;
      notification.failed = res.failureCount;
      status = res.successCount > 0 ? 'notification_queued' : 'notification_failed';
    } catch (e) {
      status = 'notification_failed';
      notification.error = 'send_failed';
    }
  }
  await store.transaction(async (tx) => {
    const cur = await tx.get('helpRequests', requestId);
    if (cur && cur.status === 'accepted') await tx.update('helpRequests', requestId, { status, notification, updatedAt: now });
  });
  return { requestId, status, recipientHasDevice: tokens.length > 0, createdAt: now };
}

async function helpStatus(ctx, body, { store }) {
  requireAuth(ctx);
  const id = body.requestId || (typeof body.idempotencyKey === 'string' ? sha256(`${ctx.uid}:${body.idempotencyKey}`).slice(0, 32) : null);
  if (!id) throw err(400, 'INVALID_ARGUMENT', 'requestId or idempotencyKey required');
  const r = await store.get('helpRequests', id);
  if (!r) throw err(404, 'NOT_FOUND', 'No such request');
  if (r.senderUid !== ctx.uid && r.recipientUid !== ctx.uid) throw err(404, 'NOT_FOUND', 'No such request'); // don't reveal existence
  return publicHelp({ id, ...r });
}

async function cancelHelp(ctx, body, { store, now }) {
  requireAuth(ctx);
  const id = body.requestId || (typeof body.idempotencyKey === 'string' ? sha256(`${ctx.uid}:${body.idempotencyKey}`).slice(0, 32) : null);
  return store.transaction(async (tx) => {
    const r = id ? await tx.get('helpRequests', id) : null;
    if (!r || r.senderUid !== ctx.uid) throw err(404, 'NOT_FOUND', 'No such request');
    if (r.status === 'acknowledged') return publicHelp({ id, ...r });
    await tx.update('helpRequests', id, { status: 'cancelled', updatedAt: now });
    return publicHelp({ id, ...r, status: 'cancelled', updatedAt: now });
  });
}

function publicHelp(r) {
  return {
    requestId: r.id, status: r.status, reason: r.reason, recipientUid: r.recipientUid, senderDisplayName: r.senderDisplayName,
    note: r.note || null, locationChoice: r.locationChoice, location: r.location || null, createdAt: r.createdAt,
    updatedAt: r.updatedAt, acknowledgedAt: r.acknowledgedAt || null,
    recipientHasDevice: r.notification ? !!r.notification.recipientHasDevice : undefined,
  };
}

// ------------------------------------------------------------------ URL reputation proxy

async function checkUrl(ctx, body, { store, now, webRisk }) {
  requireAuth(ctx);
  if (typeof body.url !== 'string' || body.url.length > 2048 || !/^https?:\/\/[^\s?#@]+$/i.test(body.url)) {
    throw err(400, 'INVALID_ARGUMENT', 'url must be scheme://host/path without query, fragment or user-info');
  }
  await store.transaction((tx) => rateLimit(tx, `url:${ctx.uid}`, 120, now));
  if (!webRisk) throw err(503, 'NOT_CONFIGURED', 'Web Risk is not configured');
  const types = await webRisk.search(body.url); // throws on failure; never logged
  return types.length ? { result: 'THREAT_MATCH', threatTypes: types } : { result: 'NO_MATCH' };
}

const routes = {
  '/family/create': createFamily,
  '/pairing/createCode': createPairingCode,
  '/pairing/confirm': confirmPairing,
  '/pairing/list': listPairings,
  '/pairing/redeem': redeemPairingCode,
  '/pairing/revoke': revokePairing,
  '/family/status': familyStatus,
  '/device/registerToken': registerDevice,
  '/help/create': createHelpRequest,
  '/help/status': helpStatus,
  '/help/cancel': cancelHelp,
  '/help/acknowledge': acknowledgeHelp,
  '/help/listForRecipient': listHelpForRecipient,
  '/checkUrl': checkUrl,
};

/** Dispatches one request; returns {http, body}. Never leaks internal error details. */
async function handle(path, ctx, body, deps) {
  const fn = routes[path];
  if (!fn) return { http: 404, body: { error: { code: 'NOT_FOUND', message: 'Unknown endpoint' } } };
  try {
    const out = await fn(ctx, body && typeof body === 'object' ? body : {}, { now: Date.now(), ...deps });
    return { http: 200, body: out };
  } catch (e) {
    if (e instanceof ApiError) return { http: e.http, body: { error: { code: e.code, message: e.message } } };
    return { http: 500, body: { error: { code: 'INTERNAL', message: 'Internal error' } } };
  }
}

module.exports = { handle, routes, normalizeCode, newCode, sha256, ApiError, CODE_TTL_MS };
