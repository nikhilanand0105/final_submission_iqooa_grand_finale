package dev.saathi.shield.apk;

import dev.saathi.model.ThreatSeverity;
import dev.saathi.util.CancellationToken;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;

/**
 * Static APK analyzer. Reads the selected file only; never installs, loads or executes it.
 * Resource limits guard against decompression bombs and oversized inputs.
 */
public class DefaultApkStaticAnalyzer implements ApkStaticAnalyzer {

    public static final String VERSION = "apk-static-2";

    public static final long MAX_FILE_BYTES = 200L * 1024 * 1024;
    static final int MAX_ENTRIES = 20_000;
    static final int MAX_MANIFEST_BYTES = 4 * 1024 * 1024;
    static final int MAX_DEX_BYTES = 64 * 1024 * 1024;
    static final long MAX_TOTAL_DEX_BYTES = 160L * 1024 * 1024;
    static final int MAX_DEX_FILES = 20;
    static final int MAX_SIG_FILE_BYTES = 1024 * 1024;
    static final long BOMB_RATIO = 200;

    // Indicator ids
    public static final String IND_PERMISSION = "APK_PERMISSION_";
    public static final String IND_SMS_PLUS_SCREEN = "APK_SMS_WITH_SCREEN_CONTROL";
    public static final String IND_ACCESSIBILITY_SERVICE = "APK_ACCESSIBILITY_SERVICE";
    public static final String IND_DEVICE_ADMIN = "APK_DEVICE_ADMIN";
    public static final String IND_NOTIFICATION_LISTENER = "APK_NOTIFICATION_LISTENER";
    public static final String IND_SMS_RECEIVER = "APK_SMS_RECEIVER";
    public static final String IND_NO_LAUNCHER = "APK_NO_LAUNCHER_ICON";
    public static final String IND_OLD_TARGET_SDK = "APK_OLD_TARGET_SDK";
    public static final String IND_DEBUGGABLE = "APK_DEBUGGABLE";
    public static final String IND_UNSIGNED = "APK_UNSIGNED";
    public static final String IND_DEBUG_CERT = "APK_DEBUG_CERTIFICATE";
    public static final String IND_EXPIRED_CERT = "APK_EXPIRED_CERTIFICATE";
    public static final String IND_DYNAMIC_CODE = "APK_DYNAMIC_CODE_LOADING";
    public static final String IND_ROOT_SHELL = "APK_ROOT_SHELL_REFERENCES";
    public static final String IND_SENDS_SMS_CODE = "APK_SMS_SENDING_CODE";
    public static final String IND_INSTALLS_APPS = "APK_INSTALLS_OTHER_APPS";
    public static final String IND_LOCK_WIPE = "APK_LOCK_OR_WIPE_CODE";
    public static final String IND_PACKED = "APK_PACKED_CODE";
    public static final String IND_ARCHIVE_ANOMALY = "APK_ARCHIVE_ANOMALY";
    public static final String IND_INVALID_DEX = "APK_INVALID_DEX";
    public static final String IND_EMBEDDED_IP_URL = "APK_EMBEDDED_IP_URL";
    public static final String IND_CLEARTEXT_URLS = "APK_CLEARTEXT_URLS";

    private static final class Perm {
        final String plain;
        final ThreatSeverity sev;
        Perm(String plain, ThreatSeverity sev) { this.plain = plain; this.sev = sev; }
    }

    private static final Map<String, Perm> PERMS = new LinkedHashMap<>();
    static {
        p("READ_SMS", "read your text messages (including OTP codes)", ThreatSeverity.HIGH);
        p("RECEIVE_SMS", "see new text messages as they arrive (including OTP codes)", ThreatSeverity.HIGH);
        p("SEND_SMS", "send text messages, which can cost money", ThreatSeverity.HIGH);
        p("READ_CALL_LOG", "read the list of your calls", ThreatSeverity.HIGH);
        p("PROCESS_OUTGOING_CALLS", "see and redirect calls you make", ThreatSeverity.HIGH);
        p("BIND_DEVICE_ADMIN", "control device lock and wipe settings", ThreatSeverity.HIGH);
        p("REQUEST_INSTALL_PACKAGES", "install other apps", ThreatSeverity.MEDIUM);
        p("SYSTEM_ALERT_WINDOW", "draw over other apps (can show fake screens on top)", ThreatSeverity.MEDIUM);
        p("READ_CONTACTS", "read your contacts", ThreatSeverity.MEDIUM);
        p("RECORD_AUDIO", "use the microphone", ThreatSeverity.MEDIUM);
        p("ACCESS_FINE_LOCATION", "know your exact location", ThreatSeverity.MEDIUM);
        p("ACCESS_BACKGROUND_LOCATION", "track your location even when the app is closed", ThreatSeverity.MEDIUM);
        p("PACKAGE_USAGE_STATS", "see which apps you use and when", ThreatSeverity.MEDIUM);
        p("MANAGE_EXTERNAL_STORAGE", "read and change all your files", ThreatSeverity.MEDIUM);
        p("READ_PHONE_NUMBERS", "read your phone number", ThreatSeverity.LOW);
        p("QUERY_ALL_PACKAGES", "see every app on your phone", ThreatSeverity.LOW);
        p("CAMERA", "use the camera", ThreatSeverity.INFO);
        p("ACCESS_COARSE_LOCATION", "know your rough location", ThreatSeverity.INFO);
        p("READ_PHONE_STATE", "read phone status and identity", ThreatSeverity.INFO);
    }

    private static void p(String n, String plain, ThreatSeverity s) {
        PERMS.put("android.permission." + n, new Perm(plain, s));
    }

    private final FileHashReputationProvider hashProvider;

    public DefaultApkStaticAnalyzer() {
        this(FileHashReputationProvider.NONE);
    }

    public DefaultApkStaticAnalyzer(FileHashReputationProvider hashProvider) {
        this.hashProvider = hashProvider == null ? FileHashReputationProvider.NONE : hashProvider;
    }

    @Override
    public String getVersion() {
        return VERSION;
    }

    // ---------------------------------------------------------------------------------------------

    @Override
    public ApkAnalysisResult analyze(InputStream in, String fileName, long declaredSize, File workDir,
                                     CancellationToken token, ProgressListener progress) {
        long t0 = System.currentTimeMillis();
        String name = safeName(fileName);
        if (in == null) return fail(AnalysisStatus.READ_ERROR, name, declaredSize, null, t0);
        if (declaredSize > MAX_FILE_BYTES) return fail(AnalysisStatus.OVERSIZED_FILE, name, declaredSize, null, t0);
        File tmp = null;
        try {
            if (workDir == null) workDir = new File(System.getProperty("java.io.tmpdir"));
            tmp = File.createTempFile("scan_", ".bin", workDir);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            long n = 0;
            byte[] buf = new byte[64 * 1024];
            try (InputStream is = new BufferedInputStream(in); OutputStream os = new FileOutputStream(tmp)) {
                int r;
                while ((r = is.read(buf)) != -1) {
                    if (cancelled(token)) return fail(AnalysisStatus.CANCELLED, name, n, null, t0);
                    n += r;
                    if (n > MAX_FILE_BYTES) return fail(AnalysisStatus.OVERSIZED_FILE, name, n, null, t0);
                    md.update(buf, 0, r);
                    os.write(buf, 0, r);
                    if (progress != null) progress.onProgress("Reading file", n, declaredSize);
                }
            } catch (SecurityException e) {
                return fail(AnalysisStatus.PERMISSION_DENIED, name, declaredSize, null, t0);
            }
            return analyzeCopied(tmp, name, n, hex(md.digest()), token, progress, t0);
        } catch (IOException e) {
            return fail(AnalysisStatus.READ_ERROR, name, declaredSize, null, t0);
        } catch (Exception e) {
            return fail(AnalysisStatus.READ_ERROR, name, declaredSize, null, t0);
        } finally {
            if (tmp != null && !tmp.delete()) tmp.deleteOnExit();
        }
    }

    @Override
    public ApkAnalysisResult analyze(File file, CancellationToken token, ProgressListener progress) {
        long t0 = System.currentTimeMillis();
        if (file == null || !file.exists()) return fail(AnalysisStatus.READ_ERROR, file == null ? "file" : file.getName(), 0, null, t0);
        if (!file.canRead()) return fail(AnalysisStatus.PERMISSION_DENIED, file.getName(), file.length(), null, t0);
        if (file.length() > MAX_FILE_BYTES) return fail(AnalysisStatus.OVERSIZED_FILE, file.getName(), file.length(), null, t0);
        try (InputStream is = new FileInputStream(file)) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[64 * 1024];
            long n = 0;
            int r;
            while ((r = is.read(buf)) != -1) {
                if (cancelled(token)) return fail(AnalysisStatus.CANCELLED, file.getName(), n, null, t0);
                md.update(buf, 0, r);
                n += r;
                if (progress != null) progress.onProgress("Reading file", n, file.length());
            }
            return analyzeCopied(file, file.getName(), n, hex(md.digest()), token, progress, t0);
        } catch (SecurityException e) {
            return fail(AnalysisStatus.PERMISSION_DENIED, file.getName(), file.length(), null, t0);
        } catch (Exception e) {
            return fail(AnalysisStatus.READ_ERROR, file.getName(), file.length(), null, t0);
        }
    }

    // ---------------------------------------------------------------------------------------------

    private ApkAnalysisResult analyzeCopied(File f, String name, long size, String sha, CancellationToken token,
                                            ProgressListener progress, long t0) {
        if (size == 0) return fail(AnalysisStatus.EMPTY_FILE, name, 0, sha, t0);
        if (!startsWithZipMagic(f)) return fail(AnalysisStatus.NOT_A_ZIP, name, size, sha, t0);

        List<String> notExtracted = new ArrayList<>();
        List<String> anomalies = new ArrayList<>();
        Set<String> abis = new LinkedHashSet<>();
        Map<String, byte[]> v1Blocks = new LinkedHashMap<>();
        byte[] manifestBytes = null;
        boolean manifestTooBig = false;
        boolean limitsHit = false;
        boolean v1Present = false;
        DexInspector.Summary dex = null;
        int total = 0, dexCount = 0, libs = 0, assets = 0, res = 0, meta = 0;
        long declaredUncompressed = 0, dexBytesRead = 0;

        if (progress != null) progress.onProgress("Opening archive", size, size);
        try (ZipFile zip = new ZipFile(f)) {
            Enumeration<? extends ZipEntry> en = zip.entries();
            Set<String> seen = new HashSet<>();
            List<ZipEntry> dexEntries = new ArrayList<>();
            while (en.hasMoreElements()) {
                if (cancelled(token)) return fail(AnalysisStatus.CANCELLED, name, size, sha, t0);
                ZipEntry e = en.nextElement();
                if (++total > MAX_ENTRIES) {
                    limitsHit = true;
                    anomalies.add("Archive has more than " + MAX_ENTRIES + " entries; the rest were not listed");
                    break;
                }
                String n = e.getName();
                if (!seen.add(n)) anomalies.add("Duplicate entry name: " + clip(n));
                if (n.contains("../") || n.contains("..\\") || n.startsWith("/") || n.contains("\0")) {
                    anomalies.add("Entry name tries to escape its folder: " + clip(n));
                }
                long us = e.getSize(), cs = e.getCompressedSize();
                if (us > 0) declaredUncompressed += us;
                boolean bomb = us > 10L * 1024 * 1024 && cs > 0 && us / cs > BOMB_RATIO;
                if (bomb) anomalies.add("Entry " + clip(n) + " expands " + (us / cs) + "x (possible decompression bomb); skipped");

                if (n.equals("AndroidManifest.xml")) {
                    if (bomb) { manifestTooBig = true; continue; }
                    manifestBytes = readBounded(zip, e, MAX_MANIFEST_BYTES);
                    if (manifestBytes == null) manifestTooBig = true;
                } else if (n.matches("classes\\d*\\.dex")) {
                    dexCount++;
                    if (!bomb) dexEntries.add(e);
                } else if (n.startsWith("META-INF/")) {
                    meta++;
                    String up = n.toUpperCase(Locale.ROOT);
                    if (up.endsWith(".SF")) v1Present = true;
                    if ((up.endsWith(".RSA") || up.endsWith(".DSA") || up.endsWith(".EC")) && !bomb) {
                        byte[] b = readBounded(zip, e, MAX_SIG_FILE_BYTES);
                        if (b != null) v1Blocks.put(n, b);
                    }
                } else if (n.startsWith("lib/")) {
                    libs++;
                    String[] parts = n.split("/");
                    if (parts.length >= 3) abis.add(parts[1]);
                } else if (n.startsWith("assets/")) {
                    assets++;
                } else if (n.startsWith("res/") || n.equals("resources.arsc")) {
                    res++;
                }
            }

            // DEX string tables
            if (!dexEntries.isEmpty()) {
                dex = new DexInspector.Summary();
                int k = 0;
                for (ZipEntry e : dexEntries) {
                    if (cancelled(token)) return fail(AnalysisStatus.CANCELLED, name, size, sha, t0);
                    if (k++ >= MAX_DEX_FILES || dexBytesRead >= MAX_TOTAL_DEX_BYTES) {
                        limitsHit = true;
                        notExtracted.add("Only the first " + (k - 1) + " code files were inspected (size limits)");
                        break;
                    }
                    if (progress != null) progress.onProgress("Inspecting code " + e.getName(), k, dexEntries.size());
                    byte[] d = readBounded(zip, e, MAX_DEX_BYTES);
                    if (d == null) {
                        limitsHit = true;
                        notExtracted.add(e.getName() + " is larger than the inspection limit and was skipped");
                        continue;
                    }
                    dexBytesRead += d.length;
                    DexInspector.inspect(d, e.getName(), dex);
                }
                if (dex.truncated) {
                    limitsHit = true;
                    notExtracted.add("Code strings were only partly inspected (size limit)");
                }
            }
        } catch (ZipException e) {
            return fail(AnalysisStatus.CORRUPTED_ARCHIVE, name, size, sha, t0);
        } catch (IOException | RuntimeException e) {
            return fail(AnalysisStatus.CORRUPTED_ARCHIVE, name, size, sha, t0);
        }

        ZipInventory inv = new ZipInventory(total, dexCount, libs, assets, res, meta, declaredUncompressed, abis, anomalies);

        if (manifestBytes == null && !manifestTooBig) {
            return result(AnalysisStatus.NOT_AN_APK, ApkRiskVerdict.CANNOT_ANALYSE, name, size, sha, null,
                    "No AndroidManifest.xml in the archive", null, inv, dex, new ArrayList<ApkIndicator>(),
                    FileHashReputationProvider.Outcome.NOT_CHECKED, notExtracted, t0);
        }

        ManifestInfo manifest = null;
        String manifestError = null;
        if (manifestTooBig) {
            manifestError = "The manifest is larger than the inspection limit";
        } else {
            try {
                manifest = AxmlParser.parse(manifestBytes);
            } catch (AxmlParser.ParseException e) {
                manifestError = e.getMessage();
            }
        }
        if (manifest == null) notExtracted.add("App details and permissions (manifest could not be read: " + manifestError + ")");

        // Signing
        if (progress != null) progress.onProgress("Reading signatures", size, size);
        List<String> sigErrors = new ArrayList<>();
        List<SigningInfo.Cert> certs = new ArrayList<>(ApkSigningInspector.v1Certs(v1Blocks, sigErrors));
        ApkSigningInspector.BlockResult br;
        try (RandomAccessFile raf = new RandomAccessFile(f, "r")) {
            br = ApkSigningInspector.signingBlock(raf, sigErrors);
        } catch (IOException e) {
            br = new ApkSigningInspector.BlockResult();
            sigErrors.add("Could not reopen file for signature reading");
        }
        for (SigningInfo.Cert c : br.certs) {
            boolean dup = false;
            for (SigningInfo.Cert x : certs) if (x.sha256.equals(c.sha256)) dup = true;
            if (!dup) certs.add(c);
        }
        SigningInfo signing = new SigningInfo(v1Present || !v1Blocks.isEmpty(), br.v2, br.v3, certs, sigErrors);
        notExtracted.add("Signature validity (signatures are read but not cryptographically verified; Android checks them when installing)");
        notExtracted.add("App label and icon text stored in resources (resources.arsc is not decoded)");
        notExtracted.add("Native code (lib/*.so) behaviour");

        // Hash reputation
        FileHashReputationProvider.Outcome hashOut;
        try {
            hashOut = hashProvider.isConfigured() ? hashProvider.check(sha) : FileHashReputationProvider.Outcome.NOT_CHECKED;
        } catch (RuntimeException e) {
            hashOut = FileHashReputationProvider.Outcome.UNAVAILABLE;
        }
        if (hashOut == null) hashOut = FileHashReputationProvider.Outcome.UNAVAILABLE;

        List<ApkIndicator> inds = indicators(manifest, signing, dex, anomalies);
        boolean partial = manifest == null || limitsHit || (dex != null && dex.invalidFiles > 0) || !sigErrors.isEmpty();
        AnalysisStatus status = partial ? AnalysisStatus.PARTIAL : AnalysisStatus.COMPLETE;

        ApkRiskVerdict verdict;
        boolean counted = false;
        for (ApkIndicator i : inds) if (i.severity.getWeight() >= ThreatSeverity.LOW.getWeight()) counted = true;
        if (hashOut == FileHashReputationProvider.Outcome.KNOWN_MALICIOUS) verdict = ApkRiskVerdict.KNOWN_THREAT_MATCH;
        else if (counted) verdict = ApkRiskVerdict.STATIC_INDICATORS_FOUND;
        else if (partial) verdict = ApkRiskVerdict.ANALYSIS_INCOMPLETE;
        else verdict = ApkRiskVerdict.NO_SUSPICIOUS_STATIC_INDICATORS;

        return result(status, verdict, name, size, sha, manifest, manifestError, signing, inv, dex, inds, hashOut, notExtracted, t0);
    }

    // ---------------------------------------------------------------------------------------------

    private List<ApkIndicator> indicators(ManifestInfo m, SigningInfo s, DexInspector.Summary d, List<String> anomalies) {
        List<ApkIndicator> out = new ArrayList<>();
        if (m != null) {
            for (String perm : m.permissions) {
                Perm p = PERMS.get(perm);
                if (p == null) continue;
                String shortName = perm.substring(perm.lastIndexOf('.') + 1);
                out.add(new ApkIndicator(IND_PERMISSION + shortName, "Asks to " + p.plain,
                        "The app's manifest requests permission to " + p.plain + ".", perm, p.sev));
            }
            boolean sms = m.permissions.contains("android.permission.READ_SMS") || m.permissions.contains("android.permission.RECEIVE_SMS");
            boolean overlay = m.permissions.contains("android.permission.SYSTEM_ALERT_WINDOW");
            if (sms && (overlay || !m.accessibilityServices.isEmpty())) {
                out.add(new ApkIndicator(IND_SMS_PLUS_SCREEN, "Can read messages AND control the screen",
                        "Reading texts together with drawing over or controlling other apps is a combination seen in apps that steal OTP codes.",
                        "SMS permission + " + (overlay ? "SYSTEM_ALERT_WINDOW" : "accessibility service"), ThreatSeverity.CRITICAL));
            }
            if (!m.accessibilityServices.isEmpty()) {
                out.add(new ApkIndicator(IND_ACCESSIBILITY_SERVICE, "Can watch and tap the screen for you",
                        "It declares an accessibility service. These can read what's on screen and press buttons. Real helper apps use this, but it's powerful.",
                        String.join(", ", m.accessibilityServices), ThreatSeverity.HIGH));
            }
            if (!m.deviceAdminReceivers.isEmpty()) {
                out.add(new ApkIndicator(IND_DEVICE_ADMIN, "Wants to be a device administrator",
                        "Device admin apps can lock the phone or block being uninstalled.",
                        String.join(", ", m.deviceAdminReceivers), ThreatSeverity.HIGH));
            }
            if (!m.notificationListeners.isEmpty()) {
                out.add(new ApkIndicator(IND_NOTIFICATION_LISTENER, "Can read all your notifications",
                        "It declares a notification listener, which can read messages and codes that show up in notifications.",
                        String.join(", ", m.notificationListeners), ThreatSeverity.HIGH));
            }
            if (!m.smsReceivers.isEmpty()) {
                out.add(new ApkIndicator(IND_SMS_RECEIVER, "Wakes up when a text message arrives",
                        "Part of the app runs automatically whenever an SMS comes in.",
                        String.join(", ", m.smsReceivers), ThreatSeverity.MEDIUM));
            }
            if (!m.hasLauncherActivity && m.activities > 0) {
                out.add(new ApkIndicator(IND_NO_LAUNCHER, "No app icon to open it",
                        "The app has no normal launcher icon, so it may run without you seeing it in your app list.",
                        m.activities + " activities, none marked as launcher", ThreatSeverity.MEDIUM));
            }
            if (m.targetSdk != null && m.targetSdk < 23) {
                out.add(new ApkIndicator(IND_OLD_TARGET_SDK, "Built for very old Android",
                        "Apps built for Android older than 6.0 get many permissions at install time without asking you.",
                        "targetSdkVersion " + m.targetSdk, ThreatSeverity.MEDIUM));
            }
            if (m.debuggable) {
                out.add(new ApkIndicator(IND_DEBUGGABLE, "Test build",
                        "The app is marked as a debug build, which isn't how store apps are released.",
                        "android:debuggable=true", ThreatSeverity.LOW));
            }
        }
        if (!s.isSigned()) {
            out.add(new ApkIndicator(IND_UNSIGNED, "No readable signature",
                    "No signing certificate could be found. Android won't install unsigned apps; the file may be tampered with or incomplete.",
                    "schemes: " + s.schemes(), ThreatSeverity.HIGH));
        } else {
            for (SigningInfo.Cert c : s.certificates) {
                if (c.androidDebug) {
                    out.add(new ApkIndicator(IND_DEBUG_CERT, "Signed with a test key",
                            "It's signed with Android's debug key, used for testing — not by a published developer.",
                            c.subject, ThreatSeverity.MEDIUM));
                } else if (c.expired) {
                    out.add(new ApkIndicator(IND_EXPIRED_CERT, "Expired signing certificate",
                            "The developer certificate has expired. Older apps sometimes have this; it's worth noting.",
                            c.subject, ThreatSeverity.INFO));
                }
            }
        }
        if (d != null) {
            if (d.refs.contains(DexInspector.REF_DEX_CLASSLOADER) || d.refs.contains(DexInspector.REF_INMEMORY_CLASSLOADER)) {
                out.add(new ApkIndicator(IND_DYNAMIC_CODE, "Can load extra code later",
                        "The code references class loaders that load code at run time, so what it does could change after installing.",
                        d.refs.contains(DexInspector.REF_DEX_CLASSLOADER) ? DexInspector.REF_DEX_CLASSLOADER : DexInspector.REF_INMEMORY_CLASSLOADER,
                        ThreatSeverity.MEDIUM));
            }
            if (d.refs.contains(DexInspector.REF_SU) && d.refs.contains(DexInspector.REF_RUNTIME) && d.refs.contains(DexInspector.REF_EXEC)) {
                out.add(new ApkIndicator(IND_ROOT_SHELL, "Tries to use root (superuser) commands",
                        "The code refers to the 'su' superuser program and to running shell commands.",
                        "Runtime.exec + su path", ThreatSeverity.HIGH));
            }
            if (d.refs.contains(DexInspector.REF_SMS_MANAGER) && d.refs.contains(DexInspector.REF_SEND_TEXT)) {
                out.add(new ApkIndicator(IND_SENDS_SMS_CODE, "Has code to send text messages",
                        "The code references SmsManager.sendTextMessage, which can send SMS (sometimes to paid numbers).",
                        "SmsManager.sendTextMessage", ThreatSeverity.MEDIUM));
            }
            if (d.refs.contains(DexInspector.REF_PACKAGE_INSTALLER)) {
                out.add(new ApkIndicator(IND_INSTALLS_APPS, "Has code to install other apps",
                        "The code references Android's PackageInstaller.", DexInspector.REF_PACKAGE_INSTALLER, ThreatSeverity.LOW));
            }
            if (d.refs.contains(DexInspector.REF_DEVICE_POLICY) && d.refs.contains(DexInspector.REF_LOCK_WIPE)) {
                out.add(new ApkIndicator(IND_LOCK_WIPE, "Has code to lock or wipe the phone",
                        "The code references device-policy lock/wipe functions.", "DevicePolicyManager.lockNow/wipeData", ThreatSeverity.MEDIUM));
            }
            if (d.refs.contains(DexInspector.REF_PACKER)) {
                out.add(new ApkIndicator(IND_PACKED, "Code is hidden by a protector",
                        "The code is wrapped by a commercial protector, so most of it can't be inspected here.",
                        "known protector class names", ThreatSeverity.LOW));
            }
            if (d.invalidFiles > 0) {
                out.add(new ApkIndicator(IND_INVALID_DEX, "Broken code file",
                        "A code file inside the app isn't valid, which is unusual for a real app.",
                        String.join("; ", d.errors), ThreatSeverity.MEDIUM));
            }
            List<String> ipUrls = new ArrayList<>();
            int cleartext = 0;
            for (String u : d.urls) {
                if (u.matches("https?://\\d{1,3}(\\.\\d{1,3}){3}.*")) ipUrls.add(u);
                if (u.startsWith("http://")) cleartext++;
            }
            if (!ipUrls.isEmpty()) {
                out.add(new ApkIndicator(IND_EMBEDDED_IP_URL, "Connects to number-only web addresses",
                        "The code contains web addresses that are raw IP numbers instead of names.",
                        clip(String.join(", ", ipUrls.subList(0, Math.min(3, ipUrls.size())))), ThreatSeverity.LOW));
            }
            if (cleartext >= 3) {
                out.add(new ApkIndicator(IND_CLEARTEXT_URLS, "Uses unencrypted web links",
                        "Several web addresses in the code use http instead of https.", cleartext + " http:// addresses", ThreatSeverity.INFO));
            }
        }
        for (String a : anomalies) {
            out.add(new ApkIndicator(IND_ARCHIVE_ANOMALY, "Unusual archive structure",
                    "The app file is put together in a way normal build tools don't produce.", a, ThreatSeverity.HIGH));
        }
        out.sort((x, y) -> y.severity.getWeight() - x.severity.getWeight());
        return out;
    }

    // ---------------------------------------------------------------------------------------------

    private ApkAnalysisResult result(AnalysisStatus status, ApkRiskVerdict v, String name, long size, String sha,
                                     ManifestInfo m, String mErr, SigningInfo s, ZipInventory inv, DexInspector.Summary d,
                                     List<ApkIndicator> inds, FileHashReputationProvider.Outcome hash,
                                     List<String> notExtracted, long t0) {
        String summary, why;
        List<String> steps = new ArrayList<>();
        ThreatSeverity top = ThreatSeverity.INFO;
        for (ApkIndicator i : inds) if (i.severity.getWeight() > top.getWeight()) top = i.severity;
        switch (v) {
            case KNOWN_THREAT_MATCH:
                summary = hashProvider.getName() + " recognises this exact file as harmful.";
                why = "This file has been reported as harmful before.";
                steps.add("Don't install it");
                steps.add("Delete the file");
                steps.add("Tell a trusted adult where it came from");
                break;
            case STATIC_INDICATORS_FOUND:
                summary = top.getWeight() >= ThreatSeverity.HIGH.getWeight()
                        ? "This app has serious warning signs: " + inds.get(0).title.toLowerCase(Locale.ROOT) + "."
                        : "This app has " + countAtLeast(inds, ThreatSeverity.LOW) + " warning sign(s) to think about.";
                why = inds.get(0).explanation;
                steps.add("Don't install it on your own — show it to a trusted adult first");
                steps.add("Check if the real app is on the Play Store instead");
                if (top.getWeight() >= ThreatSeverity.HIGH.getWeight()) steps.add("If someone pushed you to install it, that's a reason to say no");
                break;
            case NO_SUSPICIOUS_STATIC_INDICATORS:
                summary = "No warning signs were found by these checks.";
                why = "That's good, but these checks can't see everything an app might do after it's installed.";
                steps.add("Only install apps from people or stores you trust");
                steps.add("The Play Store is usually the safer place to get apps");
                steps.add("Ask a trusted adult if you're unsure");
                break;
            case ANALYSIS_INCOMPLETE:
                summary = "Only part of this file could be checked, so I can't say much about it.";
                why = "When important parts can't be read, it's safest not to install the app.";
                steps.add("Don't install it until an adult has looked at it");
                steps.add("Try getting the app from the Play Store instead");
                break;
            default:
                summary = "I couldn't check this file: " + status.getDescription().toLowerCase(Locale.ROOT) + ".";
                why = whyFailed(status);
                steps.addAll(stepsFailed(status));
                break;
        }
        String lim = "This is a static check: it reads the file but never runs or installs it, so it can't see everything the app does. "
                + "Warning signs are not proof of harm, and no warning signs is not a guarantee of safety. "
                + (hash == FileHashReputationProvider.Outcome.NOT_CHECKED ? "The file was not compared with an online threat database."
                : hash == FileHashReputationProvider.Outcome.UNAVAILABLE ? "The online threat database couldn't be reached." : "");
        return new ApkAnalysisResult(status, v, name, size, sha, m, mErr, s, inv, d, inds, hash, hashProvider.getName(),
                summary, why, steps, lim.trim(), notExtracted, VERSION, System.currentTimeMillis() - t0);
    }

    private ApkAnalysisResult fail(AnalysisStatus st, String name, long size, String sha, long t0) {
        return result(st, ApkRiskVerdict.CANNOT_ANALYSE, name, Math.max(0, size), sha, null, null, null, null, null,
                new ArrayList<ApkIndicator>(), FileHashReputationProvider.Outcome.NOT_CHECKED, new ArrayList<String>(), t0);
    }

    private static String whyFailed(AnalysisStatus s) {
        switch (s) {
            case EMPTY_FILE: return "The file has nothing in it — the download may not have finished.";
            case NOT_A_ZIP: return "Android apps (.apk) have a special format, and this file doesn't have it.";
            case NOT_AN_APK: return "It's a zip archive, but it isn't an Android app.";
            case CORRUPTED_ARCHIVE: return "The file is damaged or only partly downloaded.";
            case OVERSIZED_FILE: return "Very large files can't be checked safely on the phone.";
            case PERMISSION_DENIED: return "Android didn't let Saathi read this file.";
            case CANCELLED: return "The check was stopped before it finished.";
            default: return "Something went wrong while reading the file.";
        }
    }

    private static List<String> stepsFailed(AnalysisStatus s) {
        List<String> l = new ArrayList<>();
        if (s == AnalysisStatus.CANCELLED || s == AnalysisStatus.PERMISSION_DENIED || s == AnalysisStatus.READ_ERROR) {
            l.add("Try choosing the file again");
        }
        l.add("Don't install a file that couldn't be checked");
        l.add("Ask a trusted adult to look at it with you");
        return l;
    }

    private static int countAtLeast(List<ApkIndicator> inds, ThreatSeverity s) {
        int c = 0;
        for (ApkIndicator i : inds) if (i.severity.getWeight() >= s.getWeight()) c++;
        return c;
    }

    /** Reads at most max bytes of an entry, regardless of its declared size. Returns null if it is larger. */
    static byte[] readBounded(ZipFile zip, ZipEntry e, int max) throws IOException {
        try (InputStream in = zip.getInputStream(e)) {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[16 * 1024];
            int r;
            while ((r = in.read(buf)) != -1) {
                if (out.size() + r > max) return null;
                out.write(buf, 0, r);
            }
            return out.toByteArray();
        }
    }

    private static boolean startsWithZipMagic(File f) {
        try (InputStream in = new FileInputStream(f)) {
            byte[] h = new byte[4];
            int n = in.read(h);
            return n == 4 && h[0] == 'P' && h[1] == 'K' && (h[2] == 3 || h[2] == 5) && (h[3] == 4 || h[3] == 6);
        } catch (IOException e) {
            return false;
        }
    }

    private static boolean cancelled(CancellationToken t) {
        return t != null && t.isCancelled();
    }

    private static String safeName(String n) {
        if (n == null || n.trim().isEmpty()) return "selected file";
        String s = n.trim().replaceAll("[\\p{Cntrl}]", "");
        return s.length() > 120 ? s.substring(0, 120) + "…" : s;
    }

    private static String clip(String s) {
        return s.length() > 120 ? s.substring(0, 120) + "…" : s;
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}
