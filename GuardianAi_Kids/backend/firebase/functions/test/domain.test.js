'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { handle, normalizeCode, newCode } = require('../src/domain');
const { MemoryStore } = require('../src/memoryStore');
const { makeWebRisk } = require('../src/webrisk');

const parent = { uid: 'parentA', provider: 'google.com' };
const parentB = { uid: 'parentB', provider: 'password' };
const child = { uid: 'childA', provider: 'anonymous' };
const child2 = { uid: 'childB', provider: 'anonymous' };

function env(extra = {}) {
  const store = new MemoryStore();
  const sent = [];
  const notifier = { async send(tokens, data) { sent.push({ tokens, data }); return { successCount: tokens.length, failureCount: 0 }; } };
  return { store, sent, deps: { store, notifier, ...extra } };
}

const call = (deps, path, ctx, body) => handle(path, ctx, body, deps);

async function pairedFamily(e) {
  const fam = await call(e.deps, '/family/create', parent, { displayName: 'Sharma family', adultDisplayName: 'Mum' });
  assert.equal(fam.http, 200);
  const code = await call(e.deps, '/pairing/createCode', parent, { familyId: fam.body.familyId });
  assert.equal(code.http, 200);
  const red = await call(e.deps, '/pairing/redeem', child, { code: code.body.code, childDisplayName: 'Riya' });
  assert.equal(red.http, 200);
  const conf = await call(e.deps, '/pairing/confirm', parent, { pairingId: red.body.pairingId });
  assert.equal(conf.http, 200);
  return { familyId: fam.body.familyId, pairingId: red.body.pairingId };
}

test('codes are well-formed, unbiased alphabet, and normalised', () => {
  for (let i = 0; i < 200; i++) assert.match(newCode(), /^[0-9A-HJKMNP-TV-Z]{8}$/);
  assert.equal(normalizeCode('ab12-cd34'), 'AB12CD34');
  assert.equal(normalizeCode('xyz'), null);
});

test('unauthenticated and anonymous-parent requests are refused', async () => {
  const e = env();
  assert.equal((await call(e.deps, '/family/status', null, {})).http, 401);
  const r = await call(e.deps, '/family/create', child, { displayName: 'x' });
  assert.equal(r.http, 403);
  assert.equal(r.body.error.code, 'PARENT_ACCOUNT_REQUIRED');
  assert.equal((await call(e.deps, '/nope', parent, {})).http, 404);
});

test('full pairing: pending until the adult confirms, then active', async () => {
  const e = env();
  const fam = await call(e.deps, '/family/create', parent, { displayName: 'Sharma family', adultDisplayName: 'Mum' });
  const code = await call(e.deps, '/pairing/createCode', parent, { familyId: fam.body.familyId });
  assert.match(code.body.code, /^[0-9A-Z]{4}-[0-9A-Z]{4}$/);
  // code stored only as a hash
  assert.ok(!JSON.stringify([...e.store.col('pairingCodes').entries()]).includes(code.body.code.replace('-', '')));
  const red = await call(e.deps, '/pairing/redeem', child, { code: code.body.code.toLowerCase(), childDisplayName: 'Riya' });
  assert.equal(red.body.status, 'pending_parent_confirmation');
  let st = await call(e.deps, '/family/status', child, {});
  assert.equal(st.body.status, 'pending_parent_confirmation');
  assert.deepEqual(st.body.adults, []);
  const pending = await call(e.deps, '/pairing/list', parent, {});
  assert.equal(pending.body.pairings.length, 1);
  assert.equal(pending.body.pairings[0].status, 'pending_parent_confirmation');
  assert.equal(pending.body.pairings[0].childDisplayName, 'Riya');
  assert.deepEqual((await call(e.deps, '/pairing/list', parentB, {})).body.pairings, [], 'other adults see nothing');
  await call(e.deps, '/pairing/confirm', parent, { pairingId: red.body.pairingId });
  st = await call(e.deps, '/family/status', child, {});
  assert.equal(st.body.status, 'active');
  assert.equal(st.body.adults.length, 1);
  assert.equal(st.body.adults[0].displayName, 'Mum');
  assert.equal(st.body.adults[0].hasNotificationDevice, false);
});

test('invalid, reused and expired codes', async () => {
  const e = env();
  const fam = await call(e.deps, '/family/create', parent, { displayName: 'F', adultDisplayName: 'Mum' });
  assert.equal((await call(e.deps, '/pairing/redeem', child, { code: 'ZZZZZZZZ', childDisplayName: 'R' })).body.error.code, 'INVALID_CODE');
  assert.equal((await call(e.deps, '/pairing/redeem', child, { code: '12', childDisplayName: 'R' })).body.error.code, 'INVALID_CODE');
  const code = await call(e.deps, '/pairing/createCode', parent, { familyId: fam.body.familyId });
  assert.equal((await call(e.deps, '/pairing/redeem', child, { code: code.body.code, childDisplayName: 'R' })).http, 200);
  const reuse = await call(e.deps, '/pairing/redeem', child2, { code: code.body.code, childDisplayName: 'S' });
  assert.equal(reuse.body.error.code, 'CODE_USED');
  const code2 = await call(e.deps, '/pairing/createCode', parent, { familyId: fam.body.familyId });
  const later = { ...e.deps };
  const realNow = Date.now;
  Date.now = () => realNow() + 11 * 60 * 1000;
  try {
    const exp = await handle('/pairing/redeem', child2, { code: code2.body.code, childDisplayName: 'S' }, later);
    assert.equal(exp.http, 410);
    assert.equal(exp.body.error.code, 'EXPIRED_CODE');
  } finally {
    Date.now = realNow;
  }
});

test('redeem attempts are rate limited even when they fail', async () => {
  const e = env();
  let last;
  for (let i = 0; i < 11; i++) last = await call(e.deps, '/pairing/redeem', child, { code: 'ZZZZZZZZ', childDisplayName: 'R' });
  assert.equal(last.http, 429);
  assert.equal(last.body.error.code, 'RATE_LIMITED');
});

test('wrong-family adults cannot create codes, confirm, or receive help', async () => {
  const e = env();
  const { familyId, pairingId } = await pairedFamily(e);
  await call(e.deps, '/family/create', parentB, { displayName: 'Other', adultDisplayName: 'Stranger' });
  assert.equal((await call(e.deps, '/pairing/createCode', parentB, { familyId })).body.error.code, 'NOT_AUTHORIZED');
  assert.equal((await call(e.deps, '/pairing/confirm', parentB, { pairingId })).body.error.code, 'NOT_AUTHORIZED');
  assert.equal((await call(e.deps, '/pairing/revoke', parentB, { pairingId })).body.error.code, 'NOT_AUTHORIZED');
  const h = await call(e.deps, '/help/create', child, { idempotencyKey: 'aaaaaaaaaaaaaaaaaaaa', recipientUid: 'parentB', reason: 'unsafe' });
  assert.equal(h.body.error.code, 'RECIPIENT_NOT_AUTHORIZED');
});

test('unpaired or pending children cannot send help requests', async () => {
  const e = env();
  const r = await call(e.deps, '/help/create', child2, { idempotencyKey: 'bbbbbbbbbbbbbbbbbbbb', recipientUid: 'parentA', reason: 'unsafe' });
  assert.equal(r.body.error.code, 'NOT_PAIRED');
  const fam = await call(e.deps, '/family/create', parent, { displayName: 'F', adultDisplayName: 'Mum' });
  const code = await call(e.deps, '/pairing/createCode', parent, { familyId: fam.body.familyId });
  await call(e.deps, '/pairing/redeem', child, { code: code.body.code, childDisplayName: 'R' });
  const p = await call(e.deps, '/help/create', child, { idempotencyKey: 'cccccccccccccccccccc', recipientUid: 'parentA', reason: 'unsafe' });
  assert.equal(p.body.error.code, 'NOT_PAIRED');
});

test('help request lifecycle: accepted -> queued -> acknowledged by recipient only', async () => {
  const e = env();
  await pairedFamily(e);
  const noDevice = await call(e.deps, '/help/create', child, { idempotencyKey: '11111111111111111111', recipientUid: 'parentA', reason: 'pressure' });
  assert.equal(noDevice.body.status, 'accepted');
  assert.equal(noDevice.body.recipientHasDevice, false);
  await call(e.deps, '/device/registerToken', parent, { token: 'fcm-token-for-parent-device-0001' });
  const h = await call(e.deps, '/help/create', child, { idempotencyKey: '22222222222222222222', recipientUid: 'parentA', reason: 'unsafe', note: 'please call' });
  assert.equal(h.body.status, 'notification_queued');
  assert.equal(e.sent.length, 1);
  assert.equal(e.sent[0].data.senderDisplayName, 'Riya');
  assert.ok(!('note' in e.sent[0].data), 'note is not pushed in the notification payload');
  assert.equal((await call(e.deps, '/help/acknowledge', child, { requestId: h.body.requestId })).http, 403); // anonymous
  assert.equal((await call(e.deps, '/help/acknowledge', parentB, { requestId: h.body.requestId })).body.error.code, 'NOT_AUTHORIZED');
  const ack = await call(e.deps, '/help/acknowledge', parent, { requestId: h.body.requestId });
  assert.equal(ack.body.status, 'acknowledged');
  const st = await call(e.deps, '/help/status', child, { requestId: h.body.requestId });
  assert.equal(st.body.status, 'acknowledged');
  assert.ok(st.body.acknowledgedAt);
  const list = await call(e.deps, '/help/listForRecipient', parent, {});
  assert.equal(list.body.requests.length, 2);
});

test('duplicate submissions are deduplicated by idempotency key', async () => {
  const e = env();
  await pairedFamily(e);
  await call(e.deps, '/device/registerToken', parent, { token: 'fcm-token-for-parent-device-0001' });
  const body = { idempotencyKey: '33333333333333333333', recipientUid: 'parentA', reason: 'unsafe' };
  const [a, b] = await Promise.all([call(e.deps, '/help/create', child, body), call(e.deps, '/help/create', child, body)]);
  assert.equal(a.body.requestId, b.body.requestId);
  assert.equal(e.sent.length, 1, 'only one notification for duplicate taps');
  const c = await call(e.deps, '/help/create', child, body);
  assert.equal(c.body.deduplicated, true);
  assert.equal(e.store.col('helpRequests').size, 1);
});

test('status lookup by idempotency key and hiding other users requests', async () => {
  const e = env();
  await pairedFamily(e);
  const h = await call(e.deps, '/help/create', child, { idempotencyKey: '44444444444444444444', recipientUid: 'parentA', reason: 'unsafe' });
  const byKey = await call(e.deps, '/help/status', child, { idempotencyKey: '44444444444444444444' });
  assert.equal(byKey.body.requestId, h.body.requestId);
  assert.equal((await call(e.deps, '/help/status', child2, { requestId: h.body.requestId })).http, 404);
  assert.equal((await call(e.deps, '/help/status', child, { idempotencyKey: '55555555555555555555' })).body.error.code, 'NOT_FOUND');
});

test('revoked pairing blocks help and is visible in status', async () => {
  const e = env();
  const { pairingId } = await pairedFamily(e);
  assert.equal((await call(e.deps, '/pairing/revoke', parent, { pairingId })).body.status, 'revoked');
  const st = await call(e.deps, '/family/status', child, {});
  assert.equal(st.body.status, 'revoked');
  const h = await call(e.deps, '/help/create', child, { idempotencyKey: '66666666666666666666', recipientUid: 'parentA', reason: 'unsafe' });
  assert.equal(h.body.error.code, 'PAIRING_REVOKED');
});

test('child can cancel before acknowledgement; notification failure is reported', async () => {
  const e = env();
  await pairedFamily(e);
  await call(e.deps, '/device/registerToken', parent, { token: 'fcm-token-for-parent-device-0001' });
  e.deps.notifier = { async send() { throw new Error('fcm down'); } };
  const h = await call(e.deps, '/help/create', child, { idempotencyKey: '77777777777777777777', recipientUid: 'parentA', reason: 'unsafe' });
  assert.equal(h.body.status, 'notification_failed');
  const c = await call(e.deps, '/help/cancel', child, { requestId: h.body.requestId });
  assert.equal(c.body.status, 'cancelled');
  assert.equal((await call(e.deps, '/help/acknowledge', parent, { requestId: h.body.requestId })).body.error.code, 'CANCELLED');
});

test('input validation and location minimisation', async () => {
  const e = env();
  await pairedFamily(e);
  const bad = [
    { idempotencyKey: 'x', recipientUid: 'parentA', reason: 'unsafe' },
    { idempotencyKey: '88888888888888888888', recipientUid: 'parentA', reason: 'nope' },
    { idempotencyKey: '88888888888888888888', recipientUid: 'parentA', reason: 'unsafe', locationChoice: 'shared' },
    { idempotencyKey: '88888888888888888888', recipientUid: 'parentA', reason: 'unsafe', locationChoice: 'shared', location: { lat: 200, lng: 0 } },
  ];
  for (const b of bad) assert.equal((await call(e.deps, '/help/create', child, b)).http, 400, JSON.stringify(b));
  const ok = await call(e.deps, '/help/create', child, { idempotencyKey: '99999999999999999999', recipientUid: 'parentA', reason: 'unsafe',
    locationChoice: 'shared', location: { lat: 28.613939, lng: 77.209023, accuracyM: 12, capturedAt: 1 } });
  const st = await call(e.deps, '/help/status', parent, { requestId: ok.body.requestId });
  assert.deepEqual(st.body.location, { lat: 28.614, lng: 77.209, accuracyM: 100, capturedAt: 1 });
  const notShared = await call(e.deps, '/help/create', child, { idempotencyKey: 'aaaaaaaaaaaaaaaaaaab', recipientUid: 'parentA', reason: 'unsafe',
    locationChoice: 'not_shared', location: { lat: 1, lng: 1 } });
  assert.equal((await call(e.deps, '/help/status', child, { requestId: notShared.body.requestId })).body.location, null);
});

test('checkUrl proxy: validation, not configured, match, no match, upstream failure', async () => {
  const e = env();
  assert.equal((await call(e.deps, '/checkUrl', child, { url: 'https://x.test/a?token=1' })).http, 400);
  assert.equal((await call(e.deps, '/checkUrl', child, { url: 'https://u:p@x.test/' })).http, 400);
  assert.equal((await call(e.deps, '/checkUrl', child, { url: 'https://x.test/' })).body.error.code, 'NOT_CONFIGURED');
  const fake = (status, body) => async (url) => {
    assert.ok(url.startsWith('https://webrisk.googleapis.com/v1/uris:search?threatTypes=MALWARE'));
    return { status, json: async () => body };
  };
  e.deps.webRisk = makeWebRisk('k', fake(200, { threat: { threatTypes: ['SOCIAL_ENGINEERING'], expireTime: 'x' } }));
  assert.deepEqual((await call(e.deps, '/checkUrl', child, { url: 'https://x.test/' })).body, { result: 'THREAT_MATCH', threatTypes: ['SOCIAL_ENGINEERING'] });
  e.deps.webRisk = makeWebRisk('k', fake(200, {}));
  assert.deepEqual((await call(e.deps, '/checkUrl', child, { url: 'https://x.test/' })).body, { result: 'NO_MATCH' });
  e.deps.webRisk = makeWebRisk('k', fake(403, {}));
  assert.equal((await call(e.deps, '/checkUrl', child, { url: 'https://x.test/' })).http, 500);
  e.deps.webRisk = makeWebRisk('k', fake(200, { threat: {} }));
  assert.equal((await call(e.deps, '/checkUrl', child, { url: 'https://x.test/' })).http, 500, 'malformed upstream is an error, never NO_MATCH');
  assert.equal(makeWebRisk(''), null);
});
