package dev.guardianai.shield.apk;

import dev.guardianai.model.ThreatSeverity;
import dev.guardianai.util.CancellationToken;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.*;

public class ApkStaticAnalyzerTest {

    @TempDir
    File tmp;

    private final DefaultApkStaticAnalyzer analyzer = new DefaultApkStaticAnalyzer();

    private static File fixture() {
        try {
            return new File(ApkStaticAnalyzerTest.class.getResource("/fixtures/androidx-test-orchestrator-1.6.1.apk").toURI());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] zip(Object... nameBytes) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ZipOutputStream z = new ZipOutputStream(bos)) {
            for (int k = 0; k < nameBytes.length; k += 2) {
                z.putNextEntry(new ZipEntry((String) nameBytes[k]));
                z.write((byte[]) nameBytes[k + 1]);
                z.closeEntry();
            }
        }
        return bos.toByteArray();
    }

    private ApkAnalysisResult run(byte[] data, String name) {
        return analyzer.analyze(new ByteArrayInputStream(data), name, data.length, tmp, null, null);
    }

    // ---------- real APK ----------

    @Test
    void realApkExtractsVerifiableProperties() throws Exception {
        File f = fixture();
        ApkAnalysisResult r = analyzer.analyze(f, null, null);
        assertEquals(AnalysisStatus.COMPLETE, r.status);
        // Hash computed independently with `shasum -a 256` (see fixtures/README.md)
        assertEquals("0a8aa1f18da0613d863be7be26e2a5c8de2f6892660b86577848a122ff7df6c5", r.sha256);
        assertEquals(f.length(), r.sizeBytes);
        assertNotNull(r.manifest);
        assertEquals("androidx.test.orchestrator", r.manifest.packageName);
        assertEquals("1.6.1", r.manifest.versionName);
        assertEquals(Integer.valueOf(21), r.manifest.minSdk);
        assertTrue(r.manifest.permissions.contains("android.permission.INTERNET"));
        assertTrue(r.signing.v1 && r.signing.v2);
        assertEquals(1, r.signing.certificates.size());
        assertTrue(r.signing.certificates.get(0).sha256.matches("([0-9A-F]{2}:){31}[0-9A-F]{2}"));
        assertTrue(r.signing.certificates.get(0).androidDebug); // AndroidX test APKs are debug-signed
        assertTrue(r.hasIndicator(DefaultApkStaticAnalyzer.IND_DEBUG_CERT));
        assertEquals(1, r.inventory.dexFiles);
        assertNotNull(r.dex);
        assertTrue(r.dex.classDefs > 100);
        assertEquals(ApkRiskVerdict.STATIC_INDICATORS_FOUND, r.verdict);
        assertFalse(r.notExtracted.isEmpty());
        assertFalse(r.summary.toLowerCase().contains("safe"));
    }

    @Test
    void streamAndFileGiveSameHashAndTempIsDeleted() throws Exception {
        File f = fixture();
        try (InputStream in = new FileInputStream(f)) {
            ApkAnalysisResult r = analyzer.analyze(in, f.getName(), -1, tmp, null, null);
            assertEquals("0a8aa1f18da0613d863be7be26e2a5c8de2f6892660b86577848a122ff7df6c5", r.sha256);
            assertEquals("androidx.test.orchestrator", r.manifest.packageName);
        }
        assertEquals(0, tmp.listFiles().length, "temp copy must be deleted");
    }

    @Test
    void progressIsReported() throws Exception {
        final long[] last = {0};
        try (InputStream in = new FileInputStream(fixture())) {
            analyzer.analyze(in, "x.apk", fixture().length(), tmp, null, (stage, done, total) -> last[0] = Math.max(last[0], done));
        }
        assertTrue(last[0] > 0);
    }

    // ---------- synthetic manifests ----------

    @Test
    void permissionExtractionAndIndicators() throws Exception {
        byte[] m = AxmlTestWriter.manifest("com.example.watch", 30, true, true,
                "android.permission.RECEIVE_SMS", "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.CAMERA");
        ApkAnalysisResult r = run(zip("AndroidManifest.xml", m, "classes.dex", new byte[]{1, 2}), "w.apk");
        assertNotNull(r.manifest, r.manifestError);
        assertEquals("com.example.watch", r.manifest.packageName);
        assertEquals(Long.valueOf(42), r.manifest.versionCode);
        assertEquals("2.0", r.manifest.versionName);
        assertEquals(Integer.valueOf(30), r.manifest.targetSdk);
        assertEquals(3, r.manifest.permissions.size());
        assertTrue(r.manifest.hasLauncherActivity);
        assertEquals(1, r.manifest.accessibilityServices.size());
        assertTrue(r.hasIndicator(DefaultApkStaticAnalyzer.IND_SMS_PLUS_SCREEN));
        assertTrue(r.hasIndicator(DefaultApkStaticAnalyzer.IND_ACCESSIBILITY_SERVICE));
        assertTrue(r.hasIndicator("APK_PERMISSION_RECEIVE_SMS"));
        assertTrue(r.hasIndicator(DefaultApkStaticAnalyzer.IND_UNSIGNED));
        assertTrue(r.hasIndicator(DefaultApkStaticAnalyzer.IND_INVALID_DEX));
        assertEquals(ThreatSeverity.CRITICAL, r.highestSeverity());
        assertEquals(ApkRiskVerdict.STATIC_INDICATORS_FOUND, r.verdict);
    }

    @Test
    void missingValuesStayNullNotDefaulted() throws Exception {
        AxmlTestWriter w = new AxmlTestWriter();
        w.start("manifest", "package", AxmlTestWriter.STR, "com.example.min").end("manifest");
        ApkAnalysisResult r = run(zip("AndroidManifest.xml", w.build()), "m.apk");
        assertNotNull(r.manifest);
        assertNull(r.manifest.versionName);
        assertNull(r.manifest.versionCode);
        assertNull(r.manifest.targetSdk);
        assertNull(r.manifest.minSdk);
    }

    @Test
    void oldTargetSdkAndNoLauncher() throws Exception {
        ApkAnalysisResult r = run(zip("AndroidManifest.xml", AxmlTestWriter.manifest("com.e.old", 19, false, false)), "o.apk");
        assertTrue(r.hasIndicator(DefaultApkStaticAnalyzer.IND_OLD_TARGET_SDK));
        assertTrue(r.hasIndicator(DefaultApkStaticAnalyzer.IND_NO_LAUNCHER));
    }

    @Test
    void dexStringTableIsInspected() throws Exception {
        byte[] dex = DexTestWriter.dex("Ldalvik/system/DexClassLoader;", "Ljava/lang/Runtime;", "exec", "/system/xbin/su",
                "Landroid/telephony/SmsManager;", "sendTextMessage", "http://203.0.113.9/gate.php", "https://example.com/api");
        ApkAnalysisResult r = run(zip("AndroidManifest.xml", AxmlTestWriter.manifest("com.e.d", 30, true, false), "classes.dex", dex), "d.apk");
        assertNotNull(r.dex);
        assertEquals(0, r.dex.invalidFiles, String.valueOf(r.dex.errors));
        assertEquals(8, r.dex.strings);
        assertTrue(r.hasIndicator(DefaultApkStaticAnalyzer.IND_DYNAMIC_CODE));
        assertTrue(r.hasIndicator(DefaultApkStaticAnalyzer.IND_ROOT_SHELL));
        assertTrue(r.hasIndicator(DefaultApkStaticAnalyzer.IND_SENDS_SMS_CODE));
        assertTrue(r.hasIndicator(DefaultApkStaticAnalyzer.IND_EMBEDDED_IP_URL));
        assertTrue(r.dex.urls.contains("https://example.com/api"));
    }

    // ---------- failures ----------

    @Test
    void emptyFile() {
        ApkAnalysisResult r = run(new byte[0], "e.apk");
        assertEquals(AnalysisStatus.EMPTY_FILE, r.status);
        assertEquals(ApkRiskVerdict.CANNOT_ANALYSE, r.verdict);
    }

    @Test
    void notAZip() {
        ApkAnalysisResult r = run("hello world, definitely not a zip".getBytes(StandardCharsets.UTF_8), "t.apk");
        assertEquals(AnalysisStatus.NOT_A_ZIP, r.status);
        assertNotNull(r.sha256);
    }

    @Test
    void corruptZip() throws Exception {
        byte[] good = zip("AndroidManifest.xml", AxmlTestWriter.manifest("com.e", 30, true, false));
        byte[] trunc = java.util.Arrays.copyOf(good, good.length / 2);
        ApkAnalysisResult r = run(trunc, "c.apk");
        assertEquals(AnalysisStatus.CORRUPTED_ARCHIVE, r.status);
        assertEquals(ApkRiskVerdict.CANNOT_ANALYSE, r.verdict);
        assertEquals(sha(trunc), r.sha256);
        ApkAnalysisResult r2 = run(new byte[]{0x50, 0x4B, 0x03, 0x04, 0x14, 0, 0, 0}, "h.apk");
        assertEquals(AnalysisStatus.CORRUPTED_ARCHIVE, r2.status);
    }

    @Test
    void zipWithoutManifestIsNotAnApk() throws Exception {
        ApkAnalysisResult r = run(zip("readme.txt", "hi".getBytes()), "r.zip");
        assertEquals(AnalysisStatus.NOT_AN_APK, r.status);
        assertEquals(ApkRiskVerdict.CANNOT_ANALYSE, r.verdict);
    }

    @Test
    void plainTextOrTruncatedManifestIsIncompleteNotClean() throws Exception {
        ApkAnalysisResult r = run(zip("AndroidManifest.xml", "<manifest package=\"x\"/>".getBytes()), "p.apk");
        assertNull(r.manifest);
        assertTrue(r.manifestError.contains("plain-text"));
        assertNotEquals(ApkRiskVerdict.NO_SUSPICIOUS_STATIC_INDICATORS, r.verdict);
        byte[] m = AxmlTestWriter.manifest("com.e", 30, true, false);
        ApkAnalysisResult r2 = run(zip("AndroidManifest.xml", java.util.Arrays.copyOf(m, m.length - 30)), "t.apk");
        assertNull(r2.manifest);
        assertEquals(AnalysisStatus.PARTIAL, r2.status);
        assertNotEquals(ApkRiskVerdict.NO_SUSPICIOUS_STATIC_INDICATORS, r2.verdict);
    }

    @Test
    void garbageManifestNeverThrows() throws Exception {
        java.util.Random rnd = new java.util.Random(7);
        for (int k = 0; k < 200; k++) {
            byte[] m = AxmlTestWriter.manifest("com.fuzz", 30, true, true, "android.permission.READ_SMS");
            for (int j = 0; j < 10; j++) m[8 + rnd.nextInt(m.length - 8)] = (byte) rnd.nextInt(256);
            try {
                AxmlParser.parse(m);
            } catch (AxmlParser.ParseException expected) {
                // fine
            }
        }
    }

    @Test
    void pathTraversalEntryFlagged() throws Exception {
        ApkAnalysisResult r = run(zip("AndroidManifest.xml", AxmlTestWriter.manifest("com.e", 30, true, false),
                "../../evil.so", new byte[]{1}), "z.apk");
        assertTrue(r.hasIndicator(DefaultApkStaticAnalyzer.IND_ARCHIVE_ANOMALY));
    }

    @Test
    void decompressionBombIsSkipped() throws Exception {
        byte[] zeros = new byte[12 * 1024 * 1024];
        ApkAnalysisResult r = run(zip("AndroidManifest.xml", AxmlTestWriter.manifest("com.e", 30, true, false),
                "classes.dex", zeros), "b.apk");
        assertTrue(r.inventory.anomalies.stream().anyMatch(a -> a.contains("decompression bomb")), r.inventory.anomalies.toString());
        assertNull(r.dex);
    }

    @Test
    void oversizedDeclaredFileRejectedBeforeReading() {
        ApkAnalysisResult r = analyzer.analyze(new ByteArrayInputStream(new byte[10]), "big.apk",
                DefaultApkStaticAnalyzer.MAX_FILE_BYTES + 1, tmp, null, null);
        assertEquals(AnalysisStatus.OVERSIZED_FILE, r.status);
    }

    @Test
    void cancellation() throws Exception {
        CancellationToken t = new CancellationToken();
        t.cancel();
        try (InputStream in = new FileInputStream(fixture())) {
            ApkAnalysisResult r = analyzer.analyze(in, "x.apk", -1, tmp, t, null);
            assertEquals(AnalysisStatus.CANCELLED, r.status);
            assertEquals(ApkRiskVerdict.CANNOT_ANALYSE, r.verdict);
        }
        assertEquals(0, tmp.listFiles().length);
    }

    @Test
    void missingFileAndUnreadableStream() throws Exception {
        assertEquals(AnalysisStatus.READ_ERROR, analyzer.analyze(new File(tmp, "nope.apk"), null, null).status);
        InputStream failing = new InputStream() {
            public int read() throws IOException { throw new IOException("boom"); }
            public int read(byte[] b, int o, int l) throws IOException { throw new IOException("boom"); }
        };
        assertEquals(AnalysisStatus.READ_ERROR, analyzer.analyze(failing, "x", -1, tmp, null, null).status);
        InputStream denied = new InputStream() {
            public int read() { throw new SecurityException("denied"); }
            public int read(byte[] b, int o, int l) { throw new SecurityException("denied"); }
        };
        assertEquals(AnalysisStatus.PERMISSION_DENIED, analyzer.analyze(denied, "x", -1, tmp, null, null).status);
        assertEquals(AnalysisStatus.READ_ERROR, analyzer.analyze(null, "x", -1, tmp, null, null).status);
    }

    @Test
    void knownThreatOnlyFromConfiguredProvider() throws Exception {
        FileHashReputationProvider p = new FileHashReputationProvider() {
            public Outcome check(String sha) { return Outcome.KNOWN_MALICIOUS; }
            public boolean isConfigured() { return true; }
            public String getName() { return "Test intel"; }
        };
        ApkAnalysisResult r = new DefaultApkStaticAnalyzer(p).analyze(fixture(), null, null);
        assertEquals(ApkRiskVerdict.KNOWN_THREAT_MATCH, r.verdict);
        ApkAnalysisResult plain = analyzer.analyze(fixture(), null, null);
        assertNotEquals(ApkRiskVerdict.KNOWN_THREAT_MATCH, plain.verdict);
        assertEquals(FileHashReputationProvider.Outcome.NOT_CHECKED, plain.hashLookup);
    }

    @Test
    void cleanSyntheticAppIsNoIndicatorsNeverSafe() throws Exception {
        byte[] cert = Files.readAllBytes(new File(getClass().getResource("/fixtures/test-signer-cert.der").toURI()).toPath());
        ApkAnalysisResult r = run(zip("AndroidManifest.xml", AxmlTestWriter.manifest("com.e.clean", 33, true, false,
                "android.permission.INTERNET"), "META-INF/CERT.SF", new byte[]{1}, "META-INF/CERT.RSA", cert,
                "classes.dex", DexTestWriter.dex("Lcom/e/Main;", "onCreate")), "clean.apk");
        assertEquals(AnalysisStatus.COMPLETE, r.status);
        assertEquals(ApkRiskVerdict.NO_SUSPICIOUS_STATIC_INDICATORS, r.verdict);
        assertTrue(r.signing.certificates.get(0).subject.contains("Test Fixture"), r.signing.certificates.get(0).subject);
        for (String s : new String[]{r.summary, r.whyItMatters, r.limitations}) {
            String l = s.toLowerCase();
            assertFalse(l.contains("100%") || l.contains("malware-free") || l.contains(" is safe"), s);
        }
    }

    private static String sha(byte[] b) throws Exception {
        return DefaultApkStaticAnalyzer.hex(MessageDigest.getInstance("SHA-256").digest(b));
    }

}
