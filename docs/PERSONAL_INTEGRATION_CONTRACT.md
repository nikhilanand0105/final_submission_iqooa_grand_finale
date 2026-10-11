# Saathi Personal ⇄ Saathi Kids — integration contract (v1)

Saathi Kids and Saathi Personal are separate apps with separate identities. They never share local databases or
preferences. They talk only through the Saathi backend (`backend/firebase`, one HTTPS Cloud Function named `api`).
This document is what Saathi Personal must implement. Nothing in the Personal codebase was changed from this repo.

## Transport and authentication

- Base URL: `https://<region>-<project-id>.cloudfunctions.net/api` (region in `index.js`: `asia-south1`).
- Every call: `POST <base><path>`, `Content-Type: application/json`, `Authorization: Bearer <Firebase ID token>`.
- The server verifies the token with the Admin SDK (`verifyIdToken(token, checkRevoked=true)`).
- **Kids** signs in with Firebase **anonymous** auth (REST `accounts:signUp`); its uid is the child identity.
- **Personal** must sign in with a **non-anonymous** provider (Google, email/password or phone). Endpoints for adults
  reject anonymous tokens with `403 PARENT_ACCOUNT_REQUIRED`.
- Errors: non-200 status with `{"error":{"code":"<CODE>","message":"<text>"}}`. Messages are for logs, not for display.

## Pairing lifecycle

```
Personal: /family/create ──► /pairing/createCode ──(code shown to child, 10 min, single use)──►
Kids:     /pairing/redeem  ──► status "pending_parent_confirmation"
Personal: /pairing/confirm ──► status "active"          (either side) /pairing/revoke ──► "revoked"
```

Codes are 8 Crockford-base32 characters (shown `XXXX-XXXX`), generated with `crypto.randomBytes`. Only their SHA-256
is stored. A family can have at most 3 live codes, and redeem attempts are limited to 10 per child per hour, with
failed guesses counted. A child account can be in one active or pending pairing at a time.

### Endpoints for adults (Personal)

| Path | Body | 200 response | Errors |
|---|---|---|---|
| `/family/create` | `{displayName, adultDisplayName}` | `{familyId}` | `INVALID_ARGUMENT`, `PARENT_ACCOUNT_REQUIRED` |
| `/pairing/createCode` | `{familyId}` | `{code:"AB12-CD34", expiresAt}` | `NOT_AUTHORIZED` (not an active adult of that family), `RATE_LIMITED` |
| `/pairing/list` | `{}` | `{familyId, pairings:[{pairingId, childDisplayName, status, createdAt, confirmedAt, revokedAt}]}` | — |
| `/pairing/confirm` | `{pairingId}` | `{pairingId, status:"active"}` | `NOT_FOUND`, `NOT_AUTHORIZED`, `PAIRING_REVOKED` |
| `/pairing/revoke` | `{pairingId}` | `{pairingId, status:"revoked"}` | `NOT_FOUND`, `NOT_AUTHORIZED` |
| `/device/registerToken` | `{token}` (FCM registration token) | `{ok:true}` | `INVALID_ARGUMENT` |
| `/help/listForRecipient` | `{}` | `{requests:[HelpRequest…]}` (latest 50) | — |
| `/help/acknowledge` | `{requestId}` | `{requestId, status:"acknowledged"}` | `NOT_FOUND`, `NOT_AUTHORIZED` (not the recipient), `CANCELLED` |
| `/help/status` | `{requestId}` | `HelpRequest` | `NOT_FOUND` (also returned for requests that aren't yours) |

Personal shows pending pairings from `/pairing/list`. It must show the child's display name and ask the adult to
confirm only if they recognise the child.

### Endpoints for children (Kids)

| Path | Body | 200 response | Errors |
|---|---|---|---|
| `/pairing/redeem` | `{code, childDisplayName}` | `{status:"pending_parent_confirmation", pairingId, familyDisplayName, adults:[]}` | `INVALID_CODE` 404, `EXPIRED_CODE` 410, `CODE_USED` 409, `ALREADY_PAIRED` 409, `RATE_LIMITED` 429 |
| `/family/status` | `{}` | `{status:"none"\|"pending_parent_confirmation"\|"active"\|"revoked", pairingId, familyDisplayName, adults:[{uid, displayName, canReceiveHelp, hasNotificationDevice}]}` | — |
| `/pairing/revoke` | `{pairingId}` | `{status:"revoked"}` | — |
| `/help/create` | see below | `{requestId, status, recipientHasDevice}` | `NOT_PAIRED`, `PAIRING_REVOKED`, `RECIPIENT_NOT_AUTHORIZED` (403), `RATE_LIMITED`, `INVALID_ARGUMENT` |
| `/help/status` | `{requestId}` or `{idempotencyKey}` | `HelpRequest` | `NOT_FOUND` |
| `/help/cancel` | `{requestId}` or `{idempotencyKey}` | `HelpRequest` | `NOT_FOUND` |
| `/checkUrl` | `{url}` (scheme://host/path only) | `{result:"THREAT_MATCH", threatTypes:[…]}` or `{result:"NO_MATCH"}` | `NOT_CONFIGURED` 503, `INVALID_ARGUMENT`, `INTERNAL` 500 on Web Risk failure |

## Help requests

`/help/create` body:

```json
{ "idempotencyKey": "<uuid>", "recipientUid": "<adult uid>", "reason": "someone_mean|pressure|shared_by_mistake|unsafe|something_else",
  "note": "optional, ≤280 chars", "locationChoice": "not_shared|shared|permission_denied|unavailable",
  "location": { "lat": 0, "lng": 0, "accuracyM": 0, "capturedAt": 0 } }
```

- `requestId = sha256(childUid + ":" + idempotencyKey)[0:32]`. Resubmitting the same key returns the same request
  (`deduplicated: true`) and sends no second notification.
- The server checks: the sender has an **active** pairing, and the recipient is an **active adult of the same family**.
- `location` is stored only when `locationChoice` is `shared`. It is rounded to 3 decimals (about 110 m) and its
  accuracy is floored to 100 m.
- FCM notification payload (data + notification): `type=help_request`, `requestId`, `reason`, `senderDisplayName`.
  The note and location are **not** in the push. Personal must fetch them with `/help/status`.

`HelpRequest` object: `{requestId, status, reason, recipientUid, senderDisplayName, note, locationChoice, location,
createdAt, updatedAt, acknowledgedAt, recipientHasDevice}`.

Status meanings. Personal must display these honestly, and so does Kids:

| status | meaning |
|---|---|
| `accepted` | stored by the server; no notification sent (recipient has no registered device) |
| `notification_queued` | FCM accepted at least one message. **This doesn't mean a person saw it.** |
| `notification_failed` | stored, but every FCM send failed |
| `acknowledged` | the recipient pressed "I've seen this" in Personal (`/help/acknowledge`) |
| `cancelled` | the child cancelled before acknowledgement |

Personal requirements:
1. Register the FCM token after sign-in and whenever it changes (`/device/registerToken`).
2. On a `help_request` push, fetch details with `/help/status`. Show the reason, note and location only after the
   adult opens it.
3. Provide an explicit "I've seen this" button that calls `/help/acknowledge`. Never acknowledge automatically.
4. Never show a child's checks, messages or browsing. The backend has no endpoint that returns them.

## Data boundaries

Firestore rules deny all client access (`allow read, write: if false`), so every read and write goes through `api`,
which enforces family membership. Collections: `families/{id}`, `families/{id}/members/{uid}`, `userFamilies/{uid}`,
`pairingCodes/{sha256}`, `pairings/{id}`, `helpRequests/{id}`, `devices/{uid}/tokens/{sha256}`, `rateLimits/{key}`,
`audit/{id}`.

## Safety flags (Threats, Suicide/Self-harm)

Safety events and flag states raised by background notification checks stay **on the child's phone**. Saathi Kids
does not sync them to the backend or to Personal, and the backend has no endpoint for them. The only path to an
adult is a help request the child confirms (reason, optional note, optional approximate location). If an automatic
or opt-in flag-sharing feature is wanted later, it needs a separate, disclosed design with consent and minimal fields.
