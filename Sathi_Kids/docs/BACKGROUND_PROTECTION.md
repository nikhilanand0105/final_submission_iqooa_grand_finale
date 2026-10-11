# Saathi Kids — background protection, safety flags and Safe Browser

## What runs, and when

| Component | Android mechanism | Runs with the main screen closed? | Needs |
|---|---|---|---|
| Notification checks | `SaathiNotificationListener` (`NotificationListenerService`) | Yes — Android binds it after access is granted, and rebinds it after a reboot | One-time "Notification access" toggle (Settings → Background protection) |
| Analysis | `SafetyEventProcessor`: one worker thread, queue of 40 | Yes (inside the listener's process) | — |
| Safety alerts | `AlertDispatcher`: notification channels `saathi_threats`, `saathi_support`, `saathi_info` | Yes | `POST_NOTIFICATIONS` on Android 13+ |
| Gemma inference | `GemmaModelManager` (LiteRT-LM) | Yes. Loaded on demand; released after 10 idle minutes or under memory pressure | A `.litertlm` model file in app storage |
| Safe Browser | `SafeBrowserActivity` (WebView) | Only while it's open (it's a browser) | — |
| Other browsers (Chrome etc.) | — | **Not monitored** | — |

There is no foreground service, wake lock, polling loop, boot receiver or restart trick. Android keeps the listener
bound for as long as notification access is on. If the user force-stops the app or revokes access, monitoring stops,
and Settings shows this (the state is derived from `NotificationManager.isNotificationListenerAccessGranted` plus the
listener's connect/disconnect callbacks). OEM battery managers can also stop it. The status screen shows
"Interrupted", and the user can fix it by opening Saathi or toggling access off and on.

## The pipeline (shared by notifications, manual Check and Safe Browser)

`dev.saathi.safety.SafetyPipeline`:
1. normalise the text (≤10,000 chars; the model gets ≤1,500 chars);
2. if Gemma is **READY**, run it first with `ClassificationPrompt` (the content is passed as quoted, untrusted data);
3. `ClassificationParser` validates the reply against strict enums. Every evidence quote must actually occur in the
   text, and labels must be consistent. Prose claims like "100% safe" are rejected;
4. on model absence, timeout, error, rejection or an inconclusive answer → `RulesClassifier` (contextual rules for
   English, Hinglish and Hindi, plus the existing message analyzer for scams);
5. `SafetyGuard` keeps or escalates strong first-person self-harm statements and threat + demand combinations that the
   model missed. It sends "personal risk" claims on news or educational text to *needs review*. It never removes a concern;
6. `FlagEngine` decides the flag, its level, dedup (same source + app + text within 24 h updates the existing event,
   and alerts again only if the evidence escalates) and the alert kind;
7. the event is persisted (`safety_events`; flag level changes go to `flag_history`) and the alert is dispatched;
8. results produced without the model are re-checked once (same event, no duplicate alert) when the model becomes ready.
   That content is held **in memory only**.

Every event records its true analysis source: "On-device Gemma model", "Gemma + Saathi safety rules",
"Saathi safety rules (AI model not used)" or "Technical address checks".

## Two flags

- **Threats:** blackmail, threats to hurt someone, threats to expose photos or chats, coercion to pay or share
  OTPs/passwords, intimidation. Raised (ACTIVE) for HIGH severity with complete analysis. Weaker or uncertain cases go
  to NEEDS_REVIEW, with a low-priority notice.
- **Suicide/Self-harm:** first-person intent, ideation or help-seeking. News, prevention and school content never raise
  it. Ambiguous mentions go to NEEDS_REVIEW. Words on someone else's web page are not treated as the child's own
  statement; a search the child types is.
- A flag's level is the highest level among events not yet marked "I've looked at this" or "This wasn't a problem".
- Self-harm alerts use supportive wording, offer the trusted-adult help flow, and show Tele-MANAS **14416**
  (Government of India, free, 24×7) and **112**.

## Privacy and safeguarding (who sees what)

| Data | Where | Who can see it |
|---|---|---|
| Notification text | Memory only, while being analysed (and up to 20 items awaiting a model re-check) | Nobody; never written to disk or uploaded |
| Analysed content with no concern | Not stored (only counters) | — |
| Safety event (category, level, source, time, app name or host, ≤2 quotes of ≤80 chars, explanation) | App-private SQLite, 30-day retention, deletable in Settings | The person using the phone |
| Lock screen | Generic public version ("Open Saathi to see a safety note") | — |
| Saathi Personal (parent) | **Nothing is synced automatically.** The child can choose to send a help request (see the integration contract) | Only adults paired through the backend |

No cloud model, analytics, accessibility service, overlay, screen capture or VPN is used.

## Safe Browser

- Every main-frame navigation, **including server redirects**, goes through `shouldOverrideUrlLoading`. The URL is
  parsed and checked (structure, official-domain registry, optional Web Risk if the child allowed it) **before** it
  loads. Non-web schemes (`intent:`, `market:`, `file:`, `javascript:`) are refused.
- Search queries (Google, Bing, DuckDuckGo, Yahoo, YouTube) go through the pipeline as the child's own words.
- After a page loads, up to 4,000 characters of visible text are classified for age suitability (explicit content,
  gambling, violence, self-harm material) and self-harm context. The rules need repeated evidence.
- The system WebView's Google Safe Browsing is enabled, and its hits are recorded as "known harmful".
- Outcomes are distinct:
  - recognised official
  - suspected spoof (warn, can continue)
  - known harmful (block)
  - explicit content (block)
  - gambling or violence (warn)
  - self-harm (supportive screen with helplines)
  - unknown or unavailable (allowed, never labelled safe)
- No browsing history is saved. Only events (host name, never the full URL) are kept.

## Official-domain registry

`core/src/main/resources/dev/saathi/safety/official_domains_v1.json` (versioned, reviewed 2026-10-10) lists the
main domains of 30 commonly impersonated organisations (Indian banks, payments, platforms, social apps, games).
**Before release, re-verify it.** Indian banks are moving to the RBI `.bank.in` namespace, and new domains must be
added.

## Known limits

- Notifications only expose what the sending app puts in them. Saathi cannot see:
  - messages that produce no notification
  - redacted or "contents hidden" previews (counted as "text hidden by the app")
  - encrypted content not shown in the notification
  - anything the child types or sends
- Chrome and other browsers are not checked. A VPN-based DNS filter was **not implemented**. It could only see domain
  names, never pages or searches, and needs its own consent and threat-list source.
- Rules and models make mistakes in both directions:
  - **False negatives:** coded slang, images, voice notes, misspellings beyond the patterns.
  - **False positives:** dark jokes, game banter (mitigated, not eliminated), quoted song lyrics.
- No Gemma model is bundled; until one is installed, every result is labelled rules-based.

## Device test procedure (run on a phone or emulator — not executed in this environment)

```bash
./gradlew :app:installDebug
# 1. In the app: Settings → Background protection → Turn on notification checks → enable "Saathi Kids safety checks".
# 2. Allow notifications when asked (Android 13+).
# 3. Close Saathi (Home button). Post synthetic notifications from the shell:
adb shell cmd notification post -S bigtext -t "Unknown" threat1 "Send 5000 rupees or I will post your photos everywhere"
adb shell cmd notification post -S bigtext -t "Friend" sh1 "I want to die, nobody cares about me"
adb shell cmd notification post -S bigtext -t "News" news1 "Police said the student died by suicide; helpline numbers listed"
adb shell cmd notification post -S bigtext -t "Mum" ok1 "Dinner is ready"
# Expect: a "may be a threat" alert, a "Saathi is here for you" alert, no alert for news and dinner.
# Note: notifications posted by `cmd notification` come from the shell package (com.android.shell).
# 4. Lock/unlock; tap an alert → the event opens. Home shows both flags raised.
# 5. Re-post the same text → no second alert (dedupe). Post a stronger variant → one escalation alert.
# 6. Settings → turn off notification access → status shows "Off — notification access is needed".
# 7. Reboot with access on → status returns to "On" once Android rebinds the listener.
# 8. Airplane mode → notification checks still work (on-device); online link check reports "didn't finish".
# 9. Safe Browser: open https://www.hdfcbank.com (recognised official) and hdfcbank.com.verify-kyc.top (spoof warning).
# 10. With a model installed, Settings → AI model shows load time; Safety alert details show "On-device Gemma model".
adb logcat -s SaathiNotifListener SafetyEventProcessor GemmaModelManager
```
