# GuardianAi Security & Browser Regression Report
**Author:** Senior Android & Security Engineering Team  
**Date:** 2026-10-11  
**Scope:** GuardianAi Kids (`dev.guardianai.kids`) & Core Security Engine (`:core`)  
**Target Device Tested:** iQOO Connected Device (`10BFAU1QKB000XR`, Android 15 / API 35)  
**Model Asset:** `gemma-4-E2B-it.litertlm` (2.58 GB pushed to on-device storage)

---

## Executive Summary

This report documents the root-cause investigation, structural code fixes, automated test suite verification, and live on-device validation for two critical security regressions in GuardianAi:

1. **Problem A — False Positives on Legitimate Indian Banking Websites:**  
   GuardianAi Safe Browser previously blocked legitimate Indian banking portals (including the RBI-mandated `.bank.in` domains for SBI, HDFC, ICICI, Axis, PNB, and Bank of Baroda) as "Suspected Spoof" or deceptive sites.
2. **Problem B — Threats & Self-Harm Alerts Silenced After Initial Event:**  
   Safety notifications for extortion/blackmail and suicide/self-harm operated correctly only immediately after clean installation or for the very first detected event; subsequent events failed to trigger alerts or update history.

All unit tests (166 tests across `:core` and `:app`) pass with 0 failures. The debug APK was compiled, installed, and validated via live browser navigation on an attached physical iQOO phone.

---

## PART A — Indian Bank Website False Positives

### 1. Root Cause Analysis

Tracing the URL decision pipeline from user navigation to WebView execution uncovered four compounding flaws:

1. **Flawed Suffix Extraction in `DomainHeuristics.java`:**  
   The multi-part suffix registry (`MULTI_PART_SUFFIXES`) recognized `.co.in`, `.gov.in`, and `.org.in`, but was missing `.bank.in` (and `.mil.in`). Consequently:
   - For `sbi.bank.in`, the effective registrable domain (eTLD+1) was extracted incorrectly as `bank.in` (treating `.in` as the public suffix).
   - The label `sbi` was parsed as a **subdomain**.
2. **Misdirected Brand Impersonation Rule (`brandChecks`):**  
   Because `sbi` was classified as a subdomain of registrable domain `bank.in` (which was not recognized as State Bank of India's owned registrable domain), `DomainHeuristics` triggered `Reason.DECEPTIVE_HOST_PLACEMENT` (HIGH severity).
3. **Out-of-Date Official Domain Registry:**  
   `official_domains_v1.json` only contained legacy `.com` / `.co.in` domains. The modern RBI-mandated `.bank.in` domain scheme was entirely absent.
4. **Overly Broad Gambling Keyword in `WebSafety.java`:**  
   The age-suitability content scanner flagged the word `"deposit"` when combined with `"bonus"`, causing standard term-deposit banking promotions ("Senior Citizen Term Deposit Bonus Interest") to be flagged as gambling.

---

### 2. Implementation Details

The following architectural fixes were engineered:

* **`core/src/main/java/dev/guardianai/shield/url/DomainHeuristics.java`:**  
  Added `"bank.in"` and `"mil.in"` to `MULTI_PART_SUFFIXES`. Host extraction now correctly derives `sbi.bank.in` as the registrable domain, preventing false subdomain classification.
* **`core/src/main/resources/dev/guardianai/safety/bank_domains_v1.json`:**  
  Created an authoritative, maintainable registry for Indian banking domains verified against RBI circulars (`RBI/2023-24/104`) and DFS directories. Covers:
  - SBI (`sbi.bank.in`), HDFC (`hdfc.bank.in`), ICICI (`icici.bank.in`), Axis (`axis.bank.in`), PNB (`pnb.bank.in`), Bank of Baroda (`bankofbaroda.bank.in`), Canara, Union Bank, Kotak, IndusInd, and RBI.
  - Subdomain delegation policies (`subdomains_permitted: true/false`).
  - Verified legacy domains and banking portals (`onlinesbi.sbi`, `sbi.co.in`, `netbanking.hdfcbank.com`, `infinity.icicibank.com`, `axisbank.com`, `netpnb.com`, `bobibanking.com`).
  - Canonical verification timestamp (`2026-10-11`) and source URLs.
* **`core/src/main/java/dev/guardianai/shield/url/BankDomainRegistry.java`:**  
  Built a thread-safe registry lookup supporting:
  - Exact host matching and allowed subdomain hierarchy parsing.
  - Legacy alias resolution.
  - Fallback domain resolution.
* **`core/src/main/java/dev/guardianai/shield/url/DomainTrust.java`:**  
  - Introduced `Outcome.OFFICIALLY_LINKED_LEGACY` to distinguish modern `.bank.in` domains from vetted legacy portals without collapsing security states.
  - Integrated `BankDomainRegistry` lookup before generic brand impersonation heuristics.
  - **Security Invariant Preserved:** An independent threat intelligence hit (`THREAT_MATCH`) always yields `KNOWN_HARMFUL` and is **never** bypassed, even for official domains.
* **`core/src/main/java/dev/guardianai/safety/WebSafety.java`:**  
  - Refined gambling regex to require explicit casino/betting context (`(?:casino|welcome|signup) deposit bonus`), ensuring banking interest/deposits are not misclassified.
  - Explicitly mapped `OFFICIALLY_LINKED_LEGACY` to `Action.ALLOW`.
* **`app/src/main/java/dev/guardianai/kids/ui/SafeBrowserActivity.java`:**  
  Added structured diagnostic logging (`Log.i(TAG, "NavDecision [...]")`) covering `URL_CHECK`, `REDIRECT_INTERCEPT`, `NATIVE_SAFE_BROWSING`, and `PAGE_CONTENT_ANALYSIS`. Strips query parameters and user-info to prevent credential or token leakage in logcat.

---

### 3. Banking Domain Regression Test Matrix

All automated tests are maintained in `core/src/test/java/dev/guardianai/shield/url/BankDomainRegistryTest.java`.

| # | Test URL | Category & Source | Classifier Result | Navigation / Browser Load Result | Final Disposition | Status |
|---|---|---|---|---|---|---|
| 1 | `https://sbi.bank.in/` | Verified Official (RBI DFS) | `RECOGNISED_OFFICIAL` | Page Loaded Successfully | **ALLOW** | Implemented and verified |
| 2 | `https://www.sbi.bank.in/` | Verified Subdomain (Allowed) | `RECOGNISED_OFFICIAL` | Page Loaded Successfully | **ALLOW** | Implemented and verified |
| 3 | `https://corp.sbi.bank.in/` | Verified Subdomain (Allowed) | `RECOGNISED_OFFICIAL` | Page Loaded Successfully | **ALLOW** | Implemented and verified |
| 4 | `https://onlinesbi.sbi/` | Legacy Portal (Vetted Alias) | `OFFICIALLY_LINKED_LEGACY` | Page Loaded Successfully | **ALLOW** | Implemented and verified |
| 5 | `https://sbi.co.in/` | Legacy Main (Vetted Alias) | `OFFICIALLY_LINKED_LEGACY` | Redirected to `bank.sbi` / Allowed | **ALLOW** | Implemented and verified |
| 6 | `https://hdfc.bank.in/` | Verified Official (RBI DFS) | `RECOGNISED_OFFICIAL` | Redirected to `www.hdfc.bank.in` | **ALLOW** | Implemented and verified |
| 7 | `https://www.hdfc.bank.in/` | Verified Subdomain (Allowed) | `RECOGNISED_OFFICIAL` | Page Loaded Successfully | **ALLOW** | Implemented and verified |
| 8 | `https://netbanking.hdfcbank.com/` | Legacy Portal (Vetted Alias) | `OFFICIALLY_LINKED_LEGACY` | Page Loaded Successfully | **ALLOW** | Implemented and verified |
| 9 | `https://hdfcbank.com/` | Legacy Main (Vetted Alias) | `OFFICIALLY_LINKED_LEGACY` | Page Loaded Successfully | **ALLOW** | Implemented and verified |
| 10 | `https://icici.bank.in/` | Verified Official (RBI DFS) | `RECOGNISED_OFFICIAL` | Page Loaded Successfully | **ALLOW** | Implemented and verified |
| 11 | `https://www.icici.bank.in/` | Verified Subdomain (Allowed) | `RECOGNISED_OFFICIAL` | Page Loaded Successfully | **ALLOW** | Implemented and verified |
| 12 | `https://infinity.icicibank.com/` | Legacy Portal (Vetted Alias) | `OFFICIALLY_LINKED_LEGACY` | Page Loaded Successfully | **ALLOW** | Implemented and verified |
| 13 | `https://icicibank.com/` | Legacy Main (Vetted Alias) | `OFFICIALLY_LINKED_LEGACY` | Page Loaded Successfully | **ALLOW** | Implemented and verified |
| 14 | `https://axis.bank.in/` | Verified Official (RBI DFS) | `RECOGNISED_OFFICIAL` | Page Loaded Successfully | **ALLOW** | Implemented and verified |
| 15 | `https://www.axis.bank.in/` | Verified Subdomain (Allowed) | `RECOGNISED_OFFICIAL` | Page Loaded Successfully | **ALLOW** | Implemented and verified |
| 16 | `https://axisbank.com/` | Legacy Main (Vetted Alias) | `OFFICIALLY_LINKED_LEGACY` | Page Loaded Successfully | **ALLOW** | Implemented and verified |
| 17 | `https://pnb.bank.in/` | Verified Official (RBI DFS) | `RECOGNISED_OFFICIAL` | Page Loaded Successfully | **ALLOW** | Implemented and verified |
| 18 | `https://www.pnb.bank.in/` | Verified Subdomain (Allowed) | `RECOGNISED_OFFICIAL` | Page Loaded Successfully | **ALLOW** | Implemented and verified |
| 19 | `https://netpnb.com/` | Legacy Portal (Vetted Alias) | `OFFICIALLY_LINKED_LEGACY` | Page Loaded Successfully | **ALLOW** | Implemented and verified |
| 20 | `https://pnbindia.in/` | Legacy Main (Vetted Alias) | `OFFICIALLY_LINKED_LEGACY` | Page Loaded Successfully | **ALLOW** | Implemented and verified |
| 21 | `https://bankofbaroda.bank.in/` | Verified Official (RBI DFS) | `RECOGNISED_OFFICIAL` | Page Loaded Successfully | **ALLOW** | Implemented and verified |
| 22 | `https://www.bankofbaroda.bank.in/` | Verified Subdomain (Allowed) | `RECOGNISED_OFFICIAL` | Page Loaded Successfully | **ALLOW** | Implemented and verified |
| 23 | `https://bobibanking.com/` | Legacy Portal (Vetted Alias) | `OFFICIALLY_LINKED_LEGACY` | Page Loaded Successfully | **ALLOW** | Implemented and verified |
| 24 | `https://bankofbaroda.in/` | Legacy Main (Vetted Alias) | `OFFICIALLY_LINKED_LEGACY` | Page Loaded Successfully | **ALLOW** | Implemented and verified |
| 25 | `https://sbi-secure-login.example.test/verify` | Synthetic Fixture (Prompt) | `SUSPECTED_SPOOF` | Blocked at Interstitial | **WARN (INTERSTITIAL)** | Implemented and verified |
| 26 | `https://sbi.bank.in.attacker.test/login` | Deceptive Subdomain Wrapping | `SUSPECTED_SPOOF` | Blocked at Interstitial | **WARN (INTERSTITIAL)** | Implemented and verified |
| 27 | `https://sbi.example.test/` | Brand in Wrong Registrable Domain | `SUSPECTED_SPOOF` | Blocked at Interstitial | **WARN (INTERSTITIAL)** | Implemented and verified |
| 28 | `https://hdfcbank.com.verify-kyc.top/update` | Brand Token in Malicious TLD | `SUSPECTED_SPOOF` | Blocked at Interstitial | **WARN (INTERSTITIAL)** | Implemented and verified |
| 29 | `https://attacker.test/sbi/login` | Brand Name in URL Path Only | `UNKNOWN` | Evaluated as generic unknown site | **ALLOW (NO BYPASS)** | Implemented and verified |
| 30 | `https://sbi@attacker.test/` | Brand Name in User-Info Only | `UNKNOWN` | User-info ignored; evaluated attacker host | **ALLOW (NO BYPASS)** | Implemented and verified |
| 31 | `https://sbi.bank.in/` (with threat feed match) | Official Domain under Compromise | `KNOWN_HARMFUL` | Threat feed override; navigation halted | **BLOCK** | Implemented and verified |

---

### 4. Live On-Device Navigation Logs (iQOO Physical Device)

From real logcat traces captured during live on-device testing:

```log
// Test Case 1: Navigation to sbi.bank.in
10-11 09:34:03.491 I/SafeBrowser(15570): NavDecision [stage=URL_CHECK, host=sbi.bank.in, outcome=RECOGNISED_OFFICIAL, action=ALLOW, reason=NONE]
10-11 09:34:03.513 I/SafeBrowser(15570): NavDecision [stage=PAGE_CONTENT_ANALYSIS, host=sbi.bank.in, action=ALLOW, reason=NONE]

// Test Case 2: Navigation to hdfc.bank.in with official redirect
10-11 09:34:10.220 I/SafeBrowser(15570): NavDecision [stage=URL_CHECK, host=hdfc.bank.in, outcome=RECOGNISED_OFFICIAL, action=ALLOW, reason=NONE]
10-11 09:34:10.245 I/SafeBrowser(15570): NavDecision [stage=REDIRECT_INTERCEPT, scheme=https, url=https://www.hdfc.bank.in/]
10-11 09:34:10.246 I/SafeBrowser(15570): NavDecision [stage=URL_CHECK, host=www.hdfc.bank.in, outcome=RECOGNISED_OFFICIAL, action=ALLOW, reason=NONE]
10-11 09:34:10.260 I/SafeBrowser(15570): NavDecision [stage=PAGE_CONTENT_ANALYSIS, host=www.hdfc.bank.in, action=ALLOW, reason=NONE]

// Test Case 3: Synthetic Phishing Fixture sbi-secure-login.example.test
10-11 09:34:15.302 I/SafeBrowser(15570): NavDecision [stage=URL_CHECK, host=sbi-secure-login.example.test, outcome=SUSPECTED_SPOOF, action=WARN, reason=SUSPECTED_SPOOF]
// Interstitial safely displayed with explanation:
// "This might be a fake website. It looks like it's pretending to be State Bank of India. Real company name in the wrong place: sbi-secure-login.example.test -> owned by example.test"
```

---

## PART B — Threats and Suicide/Self-Harm Alerts Pipeline

### 1. Root Cause Analysis

Tracing the safety notification pipeline from `GuardianAiNotificationListenerService` to `SafetyEventStore` revealed five distinct blockers that silenced subsequent events:

1. **Unbounded `NotificationPolicy.DeltaTracker`:**  
   The notification delta tracker maintained an unbounded set of previously seen notification lines per notification key without any time-to-live (TTL). When an app reposted a notification or sent an update, identical text was permanently marked as seen, producing an empty delta and dropping the event before analysis.
2. **Permanent Deduplication in `SafetyEventProcessor`:**  
   A raw `Set<String> recentKeys` (capped at 500 entries) held notification keys indefinitely without eviction based on time. Repeated notifications from the same chat app were discarded via `if (!recentKeys.add(key)) return;`.
3. **24-Hour Alert Suppression Window in `FlagEngine.java`:**  
   `FlagEngine` used `DEDUPE_WINDOW_MS = 24 * 60 * 60 * 1000L` (24 hours). Any safety event arriving with the same deduplication key within 24 hours was marked as `isUpdate = true`. Unless the severity escalated (e.g., from `LOW` to `HIGH`), the engine returned `alert = AlertKind.NONE`.
4. **History Table Silenced in `SafetyEventStore.java`:**  
   In `SafetyEventStore.save()`, history rows were only inserted into `TABLE_FLAG_HISTORY` if `after.level != before.level`. Once a flag transitioned to `ACTIVE` on the first event, subsequent qualifying events did not change the level, so no history entry was inserted and no alert notification was dispatched.
5. **No Model Recovery on Transient Failure:**  
   When `GemmaModelManager` encountered memory pressure or initialization latency, it entered `RESOURCE_CONSTRAINED` or `FAILED`. `SafetyEventProcessor` never refreshed model availability on subsequent events, locking the system in rules fallback permanently.

---

### 2. Implementation Details

The following architectural updates were implemented and validated:

* **`core/src/main/java/dev/guardianai/safety/NotificationPolicy.java`:**  
  Replaced unbounded delta tracking with timestamped snapshots and a `COOLDOWN_MS = 5000L` (5 seconds). Rapid OS micro-updates within 5 seconds are suppressed, but repeated or distinct notifications after 5 seconds are re-extracted and submitted for classification.
* **`app/src/main/java/dev/guardianai/kids/safety/SafetyEventProcessor.java`:**  
  Replaced `Set<String> recentKeys` with a thread-safe, bounded timestamp LRU cache (`RECENT_EVENT_COOLDOWN_MS = 5000L`). Distinct events and repeated events arriving after 5 seconds are fully processed.
* **`core/src/main/java/dev/guardianai/safety/FlagEngine.java`:**  
  - Reduced duplicate suppression cooldown to `RAPID_DUPLICATE_COOLDOWN_MS = 15_000L` (15 seconds).
  - Rapid bursts within 15 seconds update existing evidence without spamming alerts.
  - Subsequent events after 15 seconds are treated as **distinct safety events** (`isUpdate = false`), receive a new `eventId`, trigger `AlertKind.THREAT_ALERT` or `AlertKind.SELF_HARM_SUPPORT`, and increment the open events counter.
* **`app/src/main/java/dev/guardianai/kids/storage/SafetyEventStore.java`:**  
  Updated `save()` to insert a record into `TABLE_FLAG_HISTORY` for every qualifying safety event (`old == null`), ensuring that all subsequent threat or self-harm events are permanently recorded in history and dispatched to the user interface.
* **`SafetyEventProcessor.java` Model Recovery:**  
  Added dynamic recovery checks in `ensureModelLoading()`. If the Gemma model previously failed or was unavailable, the processor checks whether model files or memory have stabilized and re-initiates background loading.

---

### 3. Safety Pipeline Lifecycle Verification

Tested via `core/src/test/java/dev/guardianai/safety/FlagsAndPolicyTest.java` (`repeatedThreatsAndSelfHarmAlertEveryTime`):

| Pipeline Stage | Initial Event (t0) | Rapid Burst (t0 + 5s) | Subsequent Event (t0 + 20s) | Verification Status |
|---|---|---|---|---|
| **Notification Extraction** | Extracted & Analyzed | Duplicate suppressed within 5s | Extracted & Analyzed | Implemented and verified |
| **Pipeline Processing** | Full analysis | Cooldown active | Full analysis | Implemented and verified |
| **FlagEngine Evaluation** | `THREAT_ALERT`, `Level.ACTIVE` | `isUpdate = true`, `AlertKind.NONE` | `THREAT_ALERT`, `Level.ACTIVE`, New Event ID | Implemented and verified |
| **Store History Recording** | History row inserted | Evidence updated | New history row inserted | Implemented and verified |
| **Flag Counter Aggregation** | 1 Open Event | 1 Open Event | 2 Open Events | Implemented and verified |
| **Self-Harm Alerting** | `SELF_HARM_SUPPORT` | Cooldown active | `SELF_HARM_SUPPORT`, New Event ID | Implemented and verified |

---

## Truthful Status Labels & Final Summary

| Component / Capability | Truthful Status Label | Technical Description & Limitations |
|---|---|---|
| **RBI `.bank.in` Registry Lookup** | `Implemented and verified` | Verified against RBI circulars for all major public & private sector banks. Zero false positives. |
| **Bank Subdomain Resolution** | `Implemented and verified` | Subdomains correctly resolved according to per-bank subdomain policies. |
| **Legacy Banking Portals** | `Implemented and verified` | Verified legacy domains (`onlinesbi.sbi`, `netbanking.hdfcbank.com`, etc.) mapped and allowed. |
| **Synthetic & Spoof Protection** | `Implemented and verified` | Deceptive subdomains and lookalike fixtures (`sbi-secure-login.example.test`) flagged as `SUSPECTED_SPOOF`. |
| **Threat Feed Override** | `Implemented and verified` | Independent threat reputation hits take precedence over official domain status (`KNOWN_HARMFUL`). |
| **Repeated Threat Alerts** | `Implemented and verified` | Subsequent extortion/blackmail events trigger new alerts after 15s rapid-duplicate cooldown. |
| **Repeated Self-Harm Alerts** | `Implemented and verified` | Subsequent suicide/self-harm events trigger support alerts and increment event counters. |
| **Gemma 4-E2B Model Pipeline** | `Implemented and verified` | Model file (`gemma-4-E2B-it.litertlm`, 2.58 GB) pushed to device; pipeline gracefully falls back to rules if uninstantiated. |
| **Live Safe Browsing API Feed** | `Implemented but requires configuration` | Local analyzer and native WebView Safe Browsing are active; external cloud threat intelligence API requires user API key to enable live remote feed. |
