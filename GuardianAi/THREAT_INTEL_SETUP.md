# GuardianAi Personal — Threat Intelligence Integration Guide (Phase 8)

This document provides the complete architecture, provider details, security guarantees, and external setup steps for live threat-intelligence integration in GuardianAi Personal.

---

## 1. Threat Intelligence Architecture

GuardianAi Personal implements a **Zero-Client-Secrets, Privacy-First Architecture**:

```
┌────────────────────────────────┐         HTTPS POST          ┌───────────────────────────────────┐
│     GuardianAi Android Client      │ ──────────────────────────> │      Firebase Cloud Functions     │
│   (Local Heuristics First)     │ <────────────────────────── │   (Server-Side Secret Management) │
└────────────────────────────────┘      Typed JSON Response    └───────────────────────────────────┘
               │                                                                 │
               ▼                                                                 ▼
      • Sanitized URL (No PII)                                        • Google Cloud Secret Manager
      • 64-char SHA-256 Hash Only                                     • Rate Limiter (30 req/min/IP)
      • Never Uploads APK Binaries                                    • Never Coerces Errors to Clean
                                                                                 │
                                                  ┌──────────────────────────────┴──────────────────────────────┐
                                                  ▼                                                             ▼
                                    ┌───────────────────────────┐                                 ┌───────────────────────────┐
                                    │    Google Web Risk API    │                                 │   VirusTotal Intel v3     │
                                    │      (URL Reputation)     │                                 │    (APK Hash Reputation)  │
                                    └───────────────────────────┘                                 └───────────────────────────┘
```

---

## 2. URL Reputation Provider: Google Web Risk API v1

### Rationale
Google Safe Browsing API terms explicitly forbid commercial distribution or incorporation into enterprise/commercial software products. **Google Web Risk API** is Google's supported, commercial-grade security service for checking client URIs against threat lists.

### Threat Categories Checked
- `SOCIAL_ENGINEERING` (Phishing, credential harvesting, banking lures)
- `MALWARE` (Malicious binary drop sites, drive-by exploit kits)
- `UNWANTED_SOFTWARE` (Deceptive adware, bundleware)

### Pricing & Quotas
- **Free Quota**: First **100,000 requests per month** are free of charge.
- **Pay-as-you-go**: $0.005 per request beyond 100,000 requests/month.
- **Default Rate Limit**: 600 requests per minute per Google Cloud project.

### Attribution Requirement
Google Web Risk Terms of Service require providing user-facing attribution when verdicts are presented:
> *"Data provided by Google Web Risk"*

This attribution is returned by the server and rendered in the GuardianAi scan audit interface.

---

## 3. APK Hash Reputation Provider: VirusTotal Intelligence v3

### Privacy Boundary: Zero Binary Uploads
- **Strict Invariant**: GuardianAi Personal **never uploads the user's APK file** to any cloud server or provider.
- Only the 64-character hexadecimal SHA-256 checksum calculated on-device is submitted.
- Any attempt to send binary files or multipart uploads is rejected with HTTP 400.

### Upstream Mapping
- `malicious > 0` or `suspicious > 1` $\rightarrow$ `THREAT_MATCH` (with vendor count and threat family).
- `malicious == 0` or HTTP 404 $\rightarrow$ `NO_KNOWN_THREAT_MATCH`.
- HTTP 429 / 5xx / Timeouts $\rightarrow$ `PROVIDER_UNAVAILABLE` or `TIMEOUT_NETWORK_ERROR` (**never converted to "No threat found"**).

---

## 4. Server Secrets & Cloud Functions Setup

### Step 1: Install Firebase CLI & Login
```bash
npm install -g firebase-tools
firebase login
```

### Step 2: Initialize or Select Firebase Project
```bash
firebase use --add <your-firebase-project-id>
```

### Step 3: Enable Google Cloud Web Risk API
1. Open Google Cloud Console: `https://console.cloud.google.com/apis/library/webrisk.googleapis.com`
2. Select your Firebase project.
3. Click **Enable**.
4. Create an API Key under **APIs & Services > Credentials**. Restrict it to the **Web Risk API**.

### Step 4: Configure Secrets via Firebase Secret Manager
Store API keys securely without committing them to source control:
```bash
firebase functions:secrets:set WEB_RISK_API_KEY
# Enter your Google Web Risk API Key when prompted

firebase functions:secrets:set VIRUSTOTAL_API_KEY
# Enter your VirusTotal API v3 Key when prompted
```

*(For local testing with the Firebase emulator, create `functions/.env.local` based on `functions/.env.example`.)*

### Step 5: Deploy Functions
```bash
cd functions
npm install
firebase deploy --only functions
```

Upon successful deployment, Firebase will output the HTTPS endpoints:
- `https://<region>-<project-id>.cloudfunctions.net/checkUrlReputation`
- `https://<region>-<project-id>.cloudfunctions.net/checkApkHashReputation`

---

## 5. Client (Android) Configuration

Configure the deployed HTTPS endpoints in `app/build.gradle.kts` via `buildConfigField`:

```kotlin
buildConfigField("String", "THREAT_INTEL_URL_ENDPOINT", "\"https://<region>-<project-id>.cloudfunctions.net/checkUrlReputation\"")
buildConfigField("String", "THREAT_INTEL_HASH_ENDPOINT", "\"https://<region>-<project-id>.cloudfunctions.net/checkApkHashReputation\"")
```

### Unconfigured / Offline Behavior
If endpoints are unconfigured (blank or not deployed):
- The app displays **"Not Checked"** / **"Live reputation unavailable"**.
- Local on-device heuristics (Punycode, TLD reputation, DEX bytecode inspection, Manifest analysis) continue running with complete integrity.
- Under no circumstances does a failure or lack of connectivity falsely mark an artifact as safe.
