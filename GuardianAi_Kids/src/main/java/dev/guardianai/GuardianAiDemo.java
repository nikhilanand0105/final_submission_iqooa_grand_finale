package dev.guardianai;

import dev.guardianai.engine.GuardianAiApkIntelligence;
import dev.guardianai.model.*;
import dev.guardianai.sense.ConversationRiskReport;
import dev.guardianai.sense.GuardianAiSenseEngine;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class GuardianAiDemo {

    public static void main(String[] args) {
        printBanner();

        GuardianAiApkIntelligence apkEngine = new GuardianAiApkIntelligence();
        GuardianAiSenseEngine senseEngine = new GuardianAiSenseEngine();

        System.out.println("================================================================================");
        System.out.println(" PART 1: GuardianAi APK INTELLIGENCE (UNDER GUARDIANAI SHIELD) - STATIC REVERSE ENG");
        System.out.println("================================================================================");

        // Test Scenario 1: Banking Trojan (ATS Pattern)
        byte[] bankingTrojanApk = createSyntheticApk(
                "com.secure.quickbank.update",
                "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\" package=\"com.secure.quickbank.update\">\n" +
                "    <uses-permission android:name=\"android.permission.SYSTEM_ALERT_WINDOW\" />\n" +
                "    <uses-permission android:name=\"android.permission.INTERNET\" />\n" +
                "    <application>\n" +
                "        <service android:name=\".AutoService\" android:permission=\"android.permission.BIND_ACCESSIBILITY_SERVICE\" />\n" +
                "    </application>\n" +
                "</manifest>",
                true, // includes accessibility strings in DEX
                false
        );

        ApkAnalysisReport report1 = apkEngine.analyzeApk(
                "QuickBank_Update_v2.apk",
                new java.io.ByteArrayInputStream(bankingTrojanApk),
                bankingTrojanApk.length
        );
        printApkReport(report1);

        // Test Scenario 2: Benign Calculator App
        byte[] benignApk = createSyntheticApk(
                "com.math.simplecalculator",
                "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\" package=\"com.math.simplecalculator\">\n" +
                "    <application>\n" +
                "        <activity android:name=\".MainActivity\">\n" +
                "            <intent-filter>\n" +
                "                <action android:name=\"android.intent.action.MAIN\" />\n" +
                "                <category android:name=\"android.intent.category.LAUNCHER\" />\n" +
                "            </intent-filter>\n" +
                "        </activity>\n" +
                "    </application>\n" +
                "</manifest>",
                false,
                false
        );

        ApkAnalysisReport report2 = apkEngine.analyzeApk(
                "SimpleCalculator.apk",
                new java.io.ByteArrayInputStream(benignApk),
                benignApk.length
        );
        printApkReport(report2);

        System.out.println("\n================================================================================");
        System.out.println(" PART 2: GuardianAi SENSE (CHILD ONLINE SAFETY & HINGLISH UNDERSTANDING)");
        System.out.println("================================================================================");

        // Test 2A: Benign Innocent Secret (Surprise Birthday)
        String msg1 = "Hey Rohan! Kal Rahul ki surprise birthday party hai, kisi ko mat batana!";
        testSense(senseEngine, "Innocent Birthday Secret", msg1);

        // Test 2B: Predatory Grooming (Secrecy + Camera Demand)
        String msg2 = "Camera on kar video call pe, kisi ko mat batana, game pass dunga.";
        testSense(senseEngine, "Predatory Coercion Attempt", msg2);

        // Test 2C: Child Gaming Financial Scam
        String msg3 = "Free BGMI UC aur diamonds chahiye toh jaldi UPI PIN daal de is link pe: http://free-uc-rewards.biz";
        testSense(senseEngine, "Gaming Currency Fraud", msg3);

        System.out.println("\n================================================================================");
        System.out.println(" PART 3: GuardianAi SENIOR - PLAIN-LANGUAGE CHECKLIST & 1930 HELPLINE");
        System.out.println("================================================================================");
        System.out.println("Elder-Friendly Advice for Suspicious Bank SMS / Links:");
        System.out.println("• Plain Language: \"Never enter your UPI PIN to receive money. UPI PIN is only for sending money.\"");
        System.out.println("• Emergency Action: If an unknown caller persuaded you to send money, call 1930 immediately.");
        System.out.println("• Official Portal: National Cyber Crime Reporting Portal (cybercrime.gov.in)");
        System.out.println("================================================================================");
    }

    private static void testSense(GuardianAiSenseEngine engine, String testCaseName, String text) {
        System.out.println("\n--- [Test: " + testCaseName + "] ---");
        System.out.println("Excerpt: \"" + text + "\"");
        ConversationRiskReport report = engine.analyze(text);
        System.out.println("Category: " + report.getCategory());
        System.out.println("Severity: " + report.getSeverity());
        System.out.println("Child Guidance: " + report.getChildExplanation());
        System.out.println("Safe Options: " + report.getSafeOptionsForChild());
        System.out.println("SOS Prompt Triggered: " + (report.shouldPromptSos() ? "YES [One-Tap SOS Activated]" : "NO"));
    }

    private static void printApkReport(ApkAnalysisReport report) {
        System.out.println("\n--------------------------------------------------------------------------------");
        System.out.println("APK FILE: " + report.getFileName() + " (" + report.getFileSizeBytes() + " bytes)");
        System.out.println("SHA-256 : " + report.getSha256Checksum());
        System.out.println("VERDICT : >>> " + report.getVerdict().getDisplayName().toUpperCase() + " <<<");
        System.out.println("CAN INSTALL SAFELY: " + (report.canSafelyProceedWithInstall() ? "YES" : "NO - STRONGLY DISCOURAGED"));
        System.out.println("\n[PLAIN-LANGUAGE / SENIOR EXPLANATION]");
        System.out.println(report.getPlainLanguageExplanation().trim());
        System.out.println("\n[DETECTED THREAT INDICATORS]");
        if (report.getIndicators().isEmpty()) {
            System.out.println("• None. Clean static baseline.");
        } else {
            for (ThreatIndicator ti : report.getIndicators()) {
                System.out.println("• [" + ti.getSeverity() + "] " + ti.getTitle() + " - " + ti.getDescription());
            }
        }
        System.out.println("\n[RECOMMENDED ACTIONS]");
        for (String action : report.getRecommendedActions()) {
            System.out.println("• " + action);
        }
    }

    private static byte[] createSyntheticApk(String pkgName, String manifestXml, boolean includeAccessibilityInDex, boolean includeSmsInDex) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ZipOutputStream zos = new ZipOutputStream(baos);

            // 1. AndroidManifest.xml
            zos.putNextEntry(new ZipEntry("AndroidManifest.xml"));
            zos.write(manifestXml.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            // 2. Synthetic DEX file
            zos.putNextEntry(new ZipEntry("classes.dex"));
            byte[] dexBytes = createMinimalDexBytes(includeAccessibilityInDex, includeSmsInDex);
            zos.write(dexBytes);
            zos.closeEntry();

            // 3. META-INF cert dummy
            zos.putNextEntry(new ZipEntry("META-INF/CERT.RSA"));
            zos.write(new byte[]{0x30, (byte) 0x82, 0x01, 0x00});
            zos.closeEntry();

            zos.close();
            return baos.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] createMinimalDexBytes(boolean accessibility, boolean sms) {
        byte[] dex = new byte[512];
        // Magic dex\n035\0
        dex[0] = 'd'; dex[1] = 'e'; dex[2] = 'x'; dex[3] = '\n';
        dex[4] = '0'; dex[5] = '3'; dex[6] = '5'; dex[7] = 0;
        dex[56] = 2; // stringIdsSize = 2 (little endian)
        dex[60] = 112; // stringIdsOff = 112

        // Offset table at 112
        dex[112] = (byte) 120; // string 0 offset
        dex[116] = (byte) 200; // string 1 offset

        // String 0
        dex[120] = 10; // len
        byte[] s1 = (accessibility ? "findAccessibilityNodeInfosByViewId" : "Ljava/lang/String;").getBytes(StandardCharsets.UTF_8);
        System.arraycopy(s1, 0, dex, 121, Math.min(s1.length, 60));

        // String 1
        dex[200] = 10; // len
        byte[] s2 = (sms ? "Ldalvik/system/DexClassLoader;" : "Ljava/lang/Integer;").getBytes(StandardCharsets.UTF_8);
        System.arraycopy(s2, 0, dex, 201, Math.min(s2.length, 60));

        return dex;
    }

    private static void printBanner() {
        System.out.println("================================================================================");
        System.out.println("  GUARDIANAI CORE SECURITY & SAFETY ENGINE — PROTOTYPE & VERIFICATION RUNNER        ");
        System.out.println("  Personal (with Senior Mode) & Family (GuardianAi Sense & Shield)                  ");
        System.out.println("================================================================================");
    }
}
