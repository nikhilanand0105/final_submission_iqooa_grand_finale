# SAATHI Ecosystem — iQOO Grand Finale Final Submission

> **On-Device Threat Intelligence & Proactive Cyber Guardian Ecosystem for Android**  
> Developed for the **iQOO Grand Finale** Hackathon by Nikhil Anand.

---

## 📌 Executive Summary

Modern mobile users in India face an epidemic of cyber threats: fraudulent WhatsApp MODs, banking trojans, screen-sharing scam apps, SMS OTP stealers, predatory messaging, and stealthy data exfiltration via third-party cloud apps. 

The **Saathi Ecosystem** is a unified, privacy-first mobile security suite designed to run **entirely on-device** with zero cloud latency and zero privacy compromise:

1. **Saathi Personal (`/Sathi`)** — Advanced mobile threat intelligence, offline APK bytecode analyzer, local DNS packet firewall, real-time data exfiltration sentinel, and Hinglish/Hindi Explainable AI risk synthesizer powered by on-device Gemma LiteRT LM.
2. **Saathi Kids (`/Sathi_Kids`)** — Next-generation digital safety guardian for children and teens featuring real-time scam/predatory chat detection, emergency SOS with location sharing, safe browser filtering, and interactive cybersecurity education.
3. **Pre-compiled Test APKs (`/apks`)** — Ready-to-install debug builds for direct evaluation on Android devices (optimized for Snapdragon 8 Elite / Android 16 / iQOO 15).

---

## 🚀 Repository Structure

```
final_submission_iqooa_grand_finale/
├── apks/                               # Pre-compiled installable APK binaries
│   ├── Saathi_Personal_v1.0_debug.apk  # Saathi Personal standalone debug build
│   └── Saathi_Kids_v1.0_debug.apk      # Saathi Kids standalone debug build
├── Sathi/                              # Saathi Personal Android App & Core Engine
│   ├── app/                            # Android App module (CRED monochrome design)
│   ├── core/                           # Pure Java/Kotlin on-device security core engine
│   ├── cli-runner/                     # Command-line scanner tool
│   ├── functions/                      # Threat intelligence helper functions
│   ├── screenshots/                    # 70+ high-resolution screenshots & live testing
│   ├── test_samples/                   # Test APKs (Clean Calculator, WhatsApp MOD, etc.)
│   └── build.gradle.kts                # Project build configuration
├── Sathi_Kids/                         # Saathi Kids Android App & Guardian Backend
│   ├── app/                            # Android App module with Kids UI & overlays
│   ├── core/                           # Kids safety rule engine, URL & message analyzers
│   ├── backend/                        # Firebase functions & Firestore security rules
│   ├── docs/                           # Architecture docs & test regression reports
│   └── build.gradle.kts                # Kids build configuration
├── local.properties.example            # Configuration template for Android SDK & Gemma
└── README.md                           # Master submission documentation
```

---

## 🛡️ Key Features & Innovations

### 1. Saathi Personal (`Sathi/`)

- **On-Device Static APK Inspection (Zero Network)**
  - Direct Dalvik Executable (`classes.dex`) bytecode scanning.
  - Custom binary XML decoder for `AndroidManifest.xml` (extracts dangerous permissions, exported activities, broadcast receivers, and intent filters).
  - Digital signature verification and certificate fingerprint analysis.
- **Rule-Based Threat Detection Suite**
  - **WhatsApp MOD Detection**: Identifies unofficial APK mods (GBWhatsApp, FMWhatsApp, YoWhatsApp) that leak chat databases.
  - **Banking Trojan & OTP Stealer**: Detects accessibility abuse, overlay permissions (`SYSTEM_ALERT_WINDOW`), and SMS interception strings.
  - **Remote Screen Sharing Abuse**: Identifies dropper wrappers abusing screen capture APIs.
  - **Toll Fraud & Ransomware Droppers**: Flags hidden background SMS senders and payload downloaders.
- **Real-Time Data Exfiltration Sentinel**
  - Watches for aggressive third-party cloud apps (e.g., TeraBox, unauthorized backup tools) running or launching in background.
  - Immediately displays the **Data Exfiltration Dialog** warning users before private photos/documents are exfiltrated.
- **Local DNS Packet Firewall (On-Device VPN)**
  - Intercepts outbound UDP port 53 DNS queries locally without routing traffic through third-party VPN servers.
  - Blocks phishing domains, malicious C2 (command & control) servers, and tracker hosts in microsecond latency.
- **Explainable AI in Hindi / Hinglish (LiteRT LM & Gemma)**
  - Translates cryptic security verdicts (e.g. `BIND_ACCESSIBILITY_SERVICE`) into clear, conversational Hindi/Hinglish explanations that everyday users understand.
  - Employs deterministic fallback when on-device LLM weights are not pre-warmed.
- **Premium User Experience**
  - Monochromatic CRED-inspired aesthetic with glowing accents, tactile cards, and fluid 5-destination navigation.

---

### 2. Saathi Kids (`Sathi_Kids/`)

- **Proactive Notification & Chat Safety Listener**
  - Monitors incoming message notifications via `NotificationListenerService`.
  - Analyzes Hindi, English, and Hinglish text for cyberbullying, predatory coercion, OTP sharing pressure, and extortion keywords.
- **Emergency SOS & Guardian Notification Flow**
  - Single-tap or shake emergency trigger for distress situations.
  - Sends immediate approximate coordinates, recent safety audit log, and battery status to designated trusted adults.
- **Safe Browser & Web Protection**
  - Embedded `SafeBrowserActivity` with local domain heuristics and official Indian banking/education domain whitelists.
- **Gamified Cyber Safety Learning**
  - Embedded micro-lessons (`app/src/main/assets/lessons/lessons_v1.json`) teaching children about phishing, password hygiene, social engineering, and safe sharing.

---

## 📱 Quick Start / Testing Pre-built APKs

Both APKs are provided in `/apks` for instant evaluation on an Android device or emulator (Android 8.0+ / API 26 through Android 16 / API 35):

```bash
# Install Saathi Personal
adb install apks/Saathi_Personal_v1.0_debug.apk

# Install Saathi Kids
adb install apks/Saathi_Kids_v1.0_debug.apk
```

---

## 🛠️ Building from Source

### Prerequisites
- JDK 17 (recommended: Eclipse Temurin 17 or OpenJDK 17)
- Android SDK (API 34/35 platform installed, build-tools 34.0.0+)
- Gradle 8.5+ (or use included `./gradlew`)

### 1. Build Saathi Personal
```bash
cd Sathi
# Create local.properties pointing to your SDK:
echo "sdk.dir=$ANDROID_HOME" > local.properties

# Run core security test suite:
./gradlew :core:test

# Build debug APK:
./gradlew :app:assembleDebug
```
Output APK: `Sathi/app/build/outputs/apk/debug/app-debug.apk`

### 2. Build Saathi Kids
```bash
cd Sathi_Kids
# Create local.properties pointing to your SDK:
echo "sdk.dir=$ANDROID_HOME" > local.properties

# Run kids safety test suite:
./gradlew :core:test

# Build debug APK:
./gradlew :app:assembleDebug
```
Output APK: `Sathi_Kids/app/build/outputs/apk/debug/app-debug.apk`

### 3. Run Command-Line APK Scanner (Desktop CLI)
```bash
cd Sathi
./gradlew :cli-runner:run --args="test_samples/device_whatsapp_mod.apk"
```

---

## 🧪 Automated Test Suite

Both apps include extensive unit and integration tests across core engines:
- `SaathiSecurityTestSuite.java` — Tests APK static analyzer, DEX bytecode decoder, signature inspector, threat rules, and firewall.
- `UrlSafetyPipelineTest.java` — Validates phishing URL scoring, domain typosquatting, and heuristic reputation checks.
- `MessageSafetyAnalyzerTest.java` — Validates Hinglish contextual risk extraction and safety classification.
- `OnDeviceLanguageModelTest.java` — Verifies Explainable AI prompts and fallback synthesis.

Run all tests:
```bash
cd Sathi && ./gradlew test
cd ../Sathi_Kids && ./gradlew test
```

---

## 📸 Screenshots & Demonstrations

Comprehensive test runs and UI captures from real device testing (iQOO / Android 16) are available under:
- `Sathi/screenshots/` — 70+ screenshots covering scan tabs, live WhatsApp MOD quarantine, SBI phishing link interception, DNS firewall toggle, and Hinglish explainable AI.
- `Sathi/test_samples/` — Real-world test sample APKs used during validation.

---

## 👨‍💻 Author & Submission Info

- **Developer:** Nikhil Anand ([@nikhilanand0105](https://github.com/nikhilanand0105))
- **Event:** iQOO Grand Finale Hackathon
- **Submission Repository:** [final_submission_iqooa_grand_finale](https://github.com/nikhilanand0105/final_submission_iqooa_grand_finale.git)
