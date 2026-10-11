package dev.guardianai;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class GenerateSampleApks {

    public static void main(String[] args) throws Exception {
        File outDir = new File("d:/iqoo-gf/test_samples");
        outDir.mkdirs();

        // 1. Create GBWhatsApp_v19.50_MOD.apk
        File modApk = new File(outDir, "GBWhatsApp_v19.50_MOD.apk");
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(modApk))) {
            zos.putNextEntry(new ZipEntry("AndroidManifest.xml"));
            String manifest = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
                    "<manifest package=\"com.gbwhatsapp\" versionCode=\"1950\" versionName=\"19.50\">\n" +
                    "    <uses-permission android:name=\"android.permission.INTERNET\" />\n" +
                    "    <uses-permission android:name=\"android.permission.READ_CONTACTS\" />\n" +
                    "    <uses-permission android:name=\"android.permission.RECEIVE_SMS\" />\n" +
                    "    <uses-permission android:name=\"android.permission.SYSTEM_ALERT_WINDOW\" />\n" +
                    "    <application android:label=\"GBWhatsApp\">\n" +
                    "        <activity android:name=\"com.gbwhatsapp.HomeActivity\" />\n" +
                    "    </application>\n" +
                    "</manifest>";
            zos.write(manifest.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            zos.putNextEntry(new ZipEntry("classes.dex"));
            String dex = "dex\n035\0com/gbwhatsapp\0GBWhatsApp\0GBSettings\0WhatsAppMod\0Anti-Ban\0";
            zos.write(dex.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        }
        System.out.println("Created: " + modApk.getAbsolutePath() + " (" + modApk.length() + " bytes)");

        // 2. Create Clean_Calculator_Safe_v1.apk
        File cleanApk = new File(outDir, "Clean_Calculator_Safe_v1.apk");
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(cleanApk))) {
            zos.putNextEntry(new ZipEntry("AndroidManifest.xml"));
            String manifest = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
                    "<manifest package=\"com.sample.cleancalculator\" versionCode=\"1\" versionName=\"1.0\">\n" +
                    "    <uses-permission android:name=\"android.permission.INTERNET\" />\n" +
                    "    <application android:label=\"Clean Calculator\">\n" +
                    "        <activity android:name=\"com.sample.cleancalculator.MainActivity\" />\n" +
                    "    </application>\n" +
                    "</manifest>";
            zos.write(manifest.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            zos.putNextEntry(new ZipEntry("classes.dex"));
            String dex = "dex\n035\0Ljava/lang/String;\0Landroid/widget/TextView;\0com/sample/cleancalculator/MainActivity\0";
            zos.write(dex.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        }
        System.out.println("Created: " + cleanApk.getAbsolutePath() + " (" + cleanApk.length() + " bytes)");

        // 3. Create WhatsApp.apk (Normal Official WhatsApp APK)
        File whatsappKeyStore = new File(outDir, "whatsapp.keystore");
        File whatsappDer = new File(outDir, "whatsapp.der");
        if (whatsappKeyStore.exists()) whatsappKeyStore.delete();
        if (whatsappDer.exists()) whatsappDer.delete();

        ProcessBuilder pb1 = new ProcessBuilder("keytool", "-genkeypair", "-alias", "whatsapp",
                "-keyalg", "RSA", "-keysize", "2048", "-validity", "3650",
                "-dname", "CN=WhatsApp, O=WhatsApp LLC, L=Mountain View, ST=California, C=US",
                "-keystore", whatsappKeyStore.getAbsolutePath(), "-storepass", "password", "-keypass", "password");
        pb1.redirectErrorStream(true);
        pb1.start().waitFor();

        ProcessBuilder pb2 = new ProcessBuilder("keytool", "-exportcert", "-alias", "whatsapp",
                "-keystore", whatsappKeyStore.getAbsolutePath(), "-storepass", "password",
                "-file", whatsappDer.getAbsolutePath());
        pb2.redirectErrorStream(true);
        pb2.start().waitFor();

        byte[] certBytes = java.nio.file.Files.readAllBytes(whatsappDer.toPath());

        File officialWhatsappApk = new File(outDir, "WhatsApp.apk");
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(officialWhatsappApk))) {
            zos.putNextEntry(new ZipEntry("AndroidManifest.xml"));
            String manifest = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
                    "<manifest package=\"com.whatsapp\" versionCode=\"22401\" versionName=\"2.24.1\">\n" +
                    "    <uses-permission android:name=\"android.permission.INTERNET\" />\n" +
                    "    <uses-permission android:name=\"android.permission.CAMERA\" />\n" +
                    "    <uses-permission android:name=\"android.permission.RECORD_AUDIO\" />\n" +
                    "    <uses-permission android:name=\"android.permission.READ_CONTACTS\" />\n" +
                    "    <uses-permission android:name=\"android.permission.ACCESS_FINE_LOCATION\" />\n" +
                    "    <uses-permission android:name=\"android.permission.RECEIVE_SMS\" />\n" +
                    "    <application android:label=\"WhatsApp\">\n" +
                    "        <activity android:name=\"com.whatsapp.HomeActivity\" />\n" +
                    "    </application>\n" +
                    "</manifest>";
            zos.write(manifest.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            zos.putNextEntry(new ZipEntry("classes.dex"));
            String dex = "dex\n035\0Lcom/whatsapp/HomeActivity;\0Lcom/whatsapp/Conversation;\0";
            zos.write(dex.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            zos.putNextEntry(new ZipEntry("META-INF/WHATSAPP.RSA"));
            zos.write(certBytes);
            zos.closeEntry();
        }
        System.out.println("Created: " + officialWhatsappApk.getAbsolutePath() + " (" + officialWhatsappApk.length() + " bytes)");

        // 3. Verify with GuardianAiApkIntelligence
        dev.guardianai.engine.GuardianAiApkIntelligence engine = new dev.guardianai.engine.GuardianAiApkIntelligence();
        dev.guardianai.model.ApkAnalysisReport modReport = engine.analyzeApk(modApk);
        System.out.println("GBWhatsApp MOD Verdict: " + modReport.getVerdict() + " | Can Install: " + modReport.canSafelyProceedWithInstall());
        for (dev.guardianai.model.ThreatIndicator ti : modReport.getIndicators()) {
            System.out.println("  -> [" + ti.getSeverity() + "] " + ti.getTitle() + " (" + ti.getId() + ")");
        }

        dev.guardianai.model.ApkAnalysisReport cleanReport = engine.analyzeApk(cleanApk);
        System.out.println("Clean Calculator Verdict: " + cleanReport.getVerdict() + " | Can Install: " + cleanReport.canSafelyProceedWithInstall());
        for (dev.guardianai.model.ThreatIndicator ti : cleanReport.getIndicators()) {
            System.out.println("  -> [" + ti.getSeverity() + "] " + ti.getTitle() + " (" + ti.getId() + ")");
        }

        dev.guardianai.model.ApkAnalysisReport officialReport = engine.analyzeApk(officialWhatsappApk);
        System.out.println("Official WhatsApp.apk Verdict: " + officialReport.getVerdict() + " | Can Install: " + officialReport.canSafelyProceedWithInstall());
        for (dev.guardianai.model.ThreatIndicator ti : officialReport.getIndicators()) {
            System.out.println("  -> [" + ti.getSeverity() + "] " + ti.getTitle() + " (" + ti.getId() + ")");
        }

        File deviceMod = new File("d:/iqoo-gf/test_samples/device_whatsapp_mod.apk");
        if (deviceMod.exists()) {
            dev.guardianai.model.ApkAnalysisReport devReport = engine.analyzeApk(deviceMod);
            System.out.println("DEVICE WhatsApp Mod.apk Verdict: " + devReport.getVerdict() + " | Can Install: " + devReport.canSafelyProceedWithInstall());
            for (dev.guardianai.model.ThreatIndicator ti : devReport.getIndicators()) {
                System.out.println("  -> [" + ti.getSeverity() + "] " + ti.getTitle() + " (" + ti.getId() + ")");
            }
        }
    }
}
