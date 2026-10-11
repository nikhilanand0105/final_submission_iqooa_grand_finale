# Test fixtures

| File | Source | Licence | SHA-256 |
|---|---|---|---|
| `androidx-test-orchestrator-1.6.1.apk` | `https://dl.google.com/android/maven2/androidx/test/orchestrator/1.6.1/orchestrator-1.6.1.apk` (Google Maven, unmodified) | Apache-2.0 (AndroidX) | `0a8aa1f18da0613d863be7be26e2a5c8de2f6892660b86577848a122ff7df6c5` |

Used by `ApkStaticAnalyzerTest` as a real, signed, benign APK. Malformed fixtures are generated in the test code.
| `test-signer-cert.der` | Generated locally with `keytool -genkeypair` (CN=Saathi Test Fixture); private key discarded | n/a (test data) | — |

`test-signer-cert.der` is a public certificate only, used to build a synthetic "clean" APK in tests.
