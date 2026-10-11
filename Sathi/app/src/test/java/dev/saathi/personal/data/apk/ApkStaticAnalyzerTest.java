package dev.saathi.personal.data.apk;

import dev.saathi.model.ApkAnalysisReport;
import dev.saathi.model.ScanVerdict;
import dev.saathi.model.ThreatIndicator;
import dev.saathi.model.ThreatSeverity;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.Assert.*;

public class ApkStaticAnalyzerTest {

    private File tempDir;

    @Before
    public void setUp() {
        tempDir = new File(System.getProperty("java.io.tmpdir"), "saathi_apk_test_" + System.currentTimeMillis());
        tempDir.mkdirs();
    }

    @After
    public void tearDown() {
        if (tempDir != null && tempDir.exists()) {
            File[] files = tempDir.listFiles();
            if (files != null) {
                for (File f : files) f.delete();
            }
            tempDir.delete();
        }
    }

    @Test
    public void testRealApkInspectionOnDebugBuild() {
        File realApk = new File("app/build/outputs/apk/debug/app-debug.apk");
        if (!realApk.exists()) {
            // Also check alternate relative path if running in subproject
            realApk = new File("build/outputs/apk/debug/app-debug.apk");
        }

        if (realApk.exists()) {
            ApkAnalysisReport report = ApkStaticAnalyzer.analyzeFile(realApk);

            assertNotNull("Report must not be null", report);
            assertNotNull("SHA-256 checksum must be computed", report.getSha256Checksum());
            assertEquals("SHA-256 must be 64 characters", 64, report.getSha256Checksum().length());
            assertTrue("File size must be positive", report.getFileSizeBytes() > 0);

            // Manifest verification
            assertNotNull("Manifest metadata must be parsed", report.getManifestMetadata());
            assertEquals("Package name should match app ID", "dev.saathi.personal", report.getManifestMetadata().getPackageName());

            // ZIP entry inventory
            assertTrue("Should contain multiple ZIP entries", report.getTotalZipEntries() > 0);
            assertNotNull("Zip inventory must not be null", report.getZipInventory());

            // Certificate verification (debug build is signed with debug keystore)
            assertNotNull("Certificate metadata must exist", report.getCertificateMetadata());
            assertTrue("Debug build must be identified as debug certificate", report.getCertificateMetadata().isDebugCertificate());

            // Verdict must be clean or caution (due to debug cert)
            assertTrue("Verdict must be safe or caution for clean debug build",
                    report.getVerdict() == ScanVerdict.NO_KNOWN_THREAT_DETECTED || report.getVerdict() == ScanVerdict.CAUTION);
            assertTrue("Should be eligible to install", report.canSafelyProceedWithInstall());
        }
    }

    @Test
    public void testCorruptOrTruncatedApkHandling() throws Exception {
        File corruptFile = new File(tempDir, "truncated.apk");
        try (FileOutputStream fos = new FileOutputStream(corruptFile)) {
            // Write only 12 bytes of garbage (not a valid ZIP)
            fos.write(new byte[]{0x50, 0x4B, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08});
        }

        ApkAnalysisReport report = ApkStaticAnalyzer.analyzeFile(corruptFile);
        assertNotNull("Report must be returned even for corrupt file", report);
        assertEquals("Corrupt file must yield UNABLE_TO_DETERMINE", ScanVerdict.UNABLE_TO_DETERMINE, report.getVerdict());
        assertFalse("Must not allow installation of unreadable package", report.canSafelyProceedWithInstall());
        assertNotNull("Must explain error in plain language", report.getPlainLanguageExplanation());
    }

    @Test
    public void testNonZipFileHandling() throws Exception {
        File textFile = new File(tempDir, "fake.apk");
        try (FileOutputStream fos = new FileOutputStream(textFile)) {
            fos.write("This is a plain text file pretending to be an APK".getBytes(StandardCharsets.UTF_8));
        }

        ApkAnalysisReport report = ApkStaticAnalyzer.analyzeFile(textFile);
        assertNotNull("Report must not be null", report);
        assertEquals("Non-zip file must yield UNABLE_TO_DETERMINE", ScanVerdict.UNABLE_TO_DETERMINE, report.getVerdict());
        assertFalse(report.canSafelyProceedWithInstall());
    }

    @Test
    public void testSyntheticTrojanApkDetection() throws Exception {
        File trojanApk = new File(tempDir, "TrojanSample.apk");
        try (FileOutputStream fos = new FileOutputStream(trojanApk);
             ZipOutputStream zos = new ZipOutputStream(fos)) {

            // AndroidManifest.xml requesting overlay + accessibility
            zos.putNextEntry(new ZipEntry("AndroidManifest.xml"));
            String manifest = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
                    "<manifest package=\"com.fraud.stealer\" versionCode=\"1\" versionName=\"1.0\">\n" +
                    "    <uses-permission android:name=\"android.permission.BIND_ACCESSIBILITY_SERVICE\" />\n" +
                    "    <uses-permission android:name=\"android.permission.SYSTEM_ALERT_WINDOW\" />\n" +
                    "    <uses-permission android:name=\"android.permission.RECEIVE_SMS\" />\n" +
                    "</manifest>";
            zos.write(manifest.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            // classes.dex with screen observation bytecode hooks
            zos.putNextEntry(new ZipEntry("classes.dex"));
            String dexContent = "dex\n035\0findAccessibilityNodeInfosByViewId\0performGlobalAction\0https://malicious-c2.top/api\0";
            zos.write(dexContent.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        }

        ApkAnalysisReport report = ApkStaticAnalyzer.analyzeFile(trojanApk);
        assertNotNull(report);
        assertEquals("Banking trojan combo must yield HIGH_RISK", ScanVerdict.HIGH_RISK, report.getVerdict());
        assertFalse("Must advise against installation", report.canSafelyProceedWithInstall());

        List<ThreatIndicator> indicators = report.getIndicators();
        assertFalse("Must return indicators for trojan pattern", indicators.isEmpty());

        // Check structured evidence properties
        boolean foundAccessibilityFact = false;
        boolean foundHeuristicRule = false;

        for (ThreatIndicator ti : indicators) {
            assertNotNull("Indicator ID must not be null", ti.getId());
            assertNotNull("Indicator Title must not be null", ti.getTitle());
            assertNotNull("Evidence Source must be declared", ti.getEvidenceSource());
            assertNotNull("Risk Rationale must be declared", ti.getRiskRationale());

            if (ti.isDirectFact()) {
                foundAccessibilityFact = true;
            } else {
                foundHeuristicRule = true;
            }
        }

        assertTrue("Must have at least one direct factual observation", foundAccessibilityFact);
        assertTrue("Must have at least one heuristic rule evaluation", foundHeuristicRule);
    }

    @Test
    public void testWhatsAppModApkDetectedAsDangerous() throws Exception {
        File modApk = new File(tempDir, "GBWhatsApp_v19.50_MOD.apk");
        try (FileOutputStream fos = new FileOutputStream(modApk);
             ZipOutputStream zos = new ZipOutputStream(fos)) {

            // AndroidManifest.xml claiming com.gbwhatsapp
            zos.putNextEntry(new ZipEntry("AndroidManifest.xml"));
            String manifest = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
                    "<manifest package=\"com.gbwhatsapp\" versionCode=\"1\" versionName=\"19.50\">\n" +
                    "    <uses-permission android:name=\"android.permission.INTERNET\" />\n" +
                    "    <uses-permission android:name=\"android.permission.READ_CONTACTS\" />\n" +
                    "</manifest>";
            zos.write(manifest.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            // classes.dex with mod signatures
            zos.putNextEntry(new ZipEntry("classes.dex"));
            String dexContent = "dex\n035\0com/gbwhatsapp\0GBWhatsApp\0GBSettings\0";
            zos.write(dexContent.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        }

        ApkAnalysisReport report = ApkStaticAnalyzer.analyzeFile(modApk);
        assertNotNull(report);
        assertEquals("WhatsApp MOD must yield HIGH_RISK", ScanVerdict.HIGH_RISK, report.getVerdict());
        assertFalse("Must advise against installing WhatsApp MOD", report.canSafelyProceedWithInstall());

        boolean hasModIndicator = report.getIndicators().stream()
                .anyMatch(ti -> ti.getId().equals("WHATSAPP_MOD_UNAUTHORIZED_FORK"));
        assertTrue("Must include WHATSAPP_MOD_UNAUTHORIZED_FORK indicator", hasModIndicator);
        assertTrue("Plain language explanation must explain WhatsApp MOD risk",
                report.getPlainLanguageExplanation().contains("WHATSAPP MOD") ||
                report.getPlainLanguageExplanation().contains("WhatsApp"));
    }

    @Test
    public void testCleanNonModApkVerifiedAsSafe() throws Exception {
        File cleanApk = new File(tempDir, "CleanCalculator.apk");
        try (FileOutputStream fos = new FileOutputStream(cleanApk);
             ZipOutputStream zos = new ZipOutputStream(fos)) {

            // AndroidManifest.xml with clean package
            zos.putNextEntry(new ZipEntry("AndroidManifest.xml"));
            String manifest = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
                    "<manifest package=\"com.sample.cleancalculator\" versionCode=\"1\" versionName=\"1.0\">\n" +
                    "    <uses-permission android:name=\"android.permission.INTERNET\" />\n" +
                    "    <application>\n" +
                    "        <activity android:name=\".MainActivity\" />\n" +
                    "    </application>\n" +
                    "</manifest>";
            zos.write(manifest.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            // classes.dex with standard innocent classes
            zos.putNextEntry(new ZipEntry("classes.dex"));
            String dexContent = "dex\n035\0Ljava/lang/String;\0Landroid/widget/TextView;\0";
            zos.write(dexContent.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        }

        ApkAnalysisReport report = ApkStaticAnalyzer.analyzeFile(cleanApk);
        assertNotNull(report);
        assertEquals("Clean non-mod APK must yield NO_KNOWN_THREAT_DETECTED", ScanVerdict.NO_KNOWN_THREAT_DETECTED, report.getVerdict());
        assertTrue("Clean non-mod APK must be safe to install", report.canSafelyProceedWithInstall());
        assertTrue("Clean APK indicators should be empty", report.getIndicators().isEmpty());
    }
}
