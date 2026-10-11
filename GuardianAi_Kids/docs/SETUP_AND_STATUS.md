# GuardianAi Kids — setup, configuration and verification status

## 1. App configuration (`local.properties`, not committed)

```properties
sdk.dir=/path/to/Android/sdk
# Backend (empty = family pairing, help requests and online link check show "not configured")
guardianai.backendUrl=https://asia-south1-<project-id>.cloudfunctions.net/api
guardianai.firebaseWebApiKey=<Firebase Web API key — identifies the project, not a secret>
# On-device model (optional)
guardianai.gemma.modelFile=<exact .litertlm file name>
guardianai.gemma.sha256=<sha256 of that file>
```

None of these values are secrets. The Web Risk API key exists **only** in the backend's Secret Manager.

## 2. Backend (Firebase)

Prerequisites: a Firebase project on the Blaze plan (Cloud Functions + Secret Manager), with Firestore in Native
mode, Authentication (Anonymous + Google or Email providers) and Cloud Messaging enabled.

For the online link check: enable the **Web Risk API** in the same Google Cloud project, create an API key restricted
to the Web Risk API, and accept the Web Risk terms. Web Risk is the commercial product. The Safe Browsing API is for
non-commercial use only (see developers.google.com/safe-browsing/v4/usage-limits). Web Risk lookups are billed per call.

```bash
cd backend/firebase
cp .firebaserc.example .firebaserc              # set your project id
firebase functions:secrets:set WEBRISK_API_KEY  # optional; without it /checkUrl returns NOT_CONFIGURED
cd functions && npm install && npm test         # domain tests (no Firebase needed)
cd .. && firebase deploy --only functions,firestore:rules
```

`firebase.json` targets Node.js 22. Rules testing with the Firestore emulator has **not** been run (see §5).

## 3. On-device model (Gemma via LiteRT-LM)

- Runtime: `com.google.ai.edge.litertlm:litertlm-android:0.18.0` (Apache-2.0). I checked this version on Google Maven
  and wrote the adapter against the classes in that AAR.
- Model: any Gemma-family model in `.litertlm` format, for example Gemma3-1B-IT from the LiteRT Community on
  Hugging Face (the example named in the official LiteRT-LM Android docs). Gemma models are distributed under the
  Gemma Terms of Use, which you must accept before downloading. No model is bundled in this repo.
- Install (debug): `adb push <model>.litertlm /sdcard/Android/data/dev.guardianai.kids/files/models/`, then set
  `guardianai.gemma.modelFile` and `guardianai.gemma.sha256`. Then Settings → On-device AI → Load model.
- The app loads from app-specific storage only. It verifies the SHA-256 when one is configured and refuses
  to load on a mismatch. It needs roughly the model size plus 20% in free RAM (or at least 1.5 GB), and releases
  the model when the UI is hidden or memory is critical.

## 4. Build and test commands

```bash
./gradlew :core:test                 # pure-Java unit tests (145)
./gradlew :app:assembleDebug         # APK
cd backend/firebase/functions && npm test   # backend domain tests (14)
```

## 5. What was verified in this environment, and what wasn't

The development Mac had no Android SDK, and the corporate proxy blocks the Gradle distribution download. So:

| Check | Result |
|---|---|
| `:core` main + tests compiled with javac 21; JUnit 5 console | **145 passed, 0 failed** |
| `:app` Java sources compiled with javac against Android 36 `android.jar` + LiteRT-LM 0.18.0 classes + Kotlin runtime (stub R/BuildConfig) | **Compiles** (deprecation warnings only) |
| `cli-runner` compiled against the new core | Compiles |
| Backend domain logic, `node --test` with an in-memory store | **14 passed** |
| Backend `index.js` loads with firebase-functions 7.4.0 / firebase-admin 14.5.0 | Loads |
| Gradle build / AGP resource merge / R8 / lint | **Not run** |
| Install on device, UI navigation, back/font-scale behaviour | **Not run** (no device) |
| Real Gemma inference, latency and memory | **Not run** (no model or device) |
| Firestore adapter against the emulator, security rules tests | **Not run** |
| Live Web Risk lookup | **Not run** (no project or key) |
| End-to-end pairing / help request / FCM / acknowledgement with Personal | **Not run** (no backend deployed; Personal not changed) |
| Background notification listener, alerts, Safe Browser on a device | **Not run** (procedure in BACKGROUND_PROTECTION.md) |

See also `docs/BACKGROUND_PROTECTION.md` for background monitoring, the two safety flags and the Safe Browser.
