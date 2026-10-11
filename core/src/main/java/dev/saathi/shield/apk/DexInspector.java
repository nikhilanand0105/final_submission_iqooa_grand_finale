package dev.saathi.shield.apk;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reads the header and string table of a DEX file (documented Dalvik executable format) and looks for
 * API/class references and URLs in that table. This is string-level static inspection: it shows which
 * classes/methods are referenced, not whether or how the code calls them. DEX code is never loaded or run.
 */
public final class DexInspector {

    static final int MAX_STRINGS = 300_000;
    static final int MAX_URLS = 40;

    /** Facts from one or more DEX files. */
    public static final class Summary {
        public int files;
        public int invalidFiles;
        public long strings, typeIds, methodIds, classDefs;
        public boolean truncated;
        public final Set<String> refs = new LinkedHashSet<>(); // matched reference keys, see REF_* constants
        public final Set<String> urls = new LinkedHashSet<>();
        public final List<String> errors = new ArrayList<>();
    }

    public static final String REF_DEX_CLASSLOADER = "Ldalvik/system/DexClassLoader;";
    public static final String REF_INMEMORY_CLASSLOADER = "Ldalvik/system/InMemoryDexClassLoader;";
    public static final String REF_RUNTIME = "Ljava/lang/Runtime;";
    public static final String REF_EXEC = "exec";
    public static final String REF_SU = "su-binary-path";
    public static final String REF_SMS_MANAGER = "Landroid/telephony/SmsManager;";
    public static final String REF_SEND_TEXT = "sendTextMessage";
    public static final String REF_ACCESSIBILITY = "Landroid/accessibilityservice/AccessibilityService;";
    public static final String REF_GLOBAL_ACTION = "performGlobalAction";
    public static final String REF_PACKAGE_INSTALLER = "Landroid/content/pm/PackageInstaller;";
    public static final String REF_DEVICE_POLICY = "Landroid/app/admin/DevicePolicyManager;";
    public static final String REF_LOCK_WIPE = "lockNow|wipeData";
    public static final String REF_MEDIA_PROJECTION = "Landroid/media/projection/MediaProjection;";
    public static final String REF_PACKER = "packer";

    private static final Set<String> EXACT = new HashSet<>();
    static {
        EXACT.add(REF_DEX_CLASSLOADER);
        EXACT.add(REF_INMEMORY_CLASSLOADER);
        EXACT.add(REF_RUNTIME);
        EXACT.add(REF_EXEC);
        EXACT.add(REF_SMS_MANAGER);
        EXACT.add(REF_SEND_TEXT);
        EXACT.add(REF_ACCESSIBILITY);
        EXACT.add(REF_GLOBAL_ACTION);
        EXACT.add(REF_PACKAGE_INSTALLER);
        EXACT.add(REF_DEVICE_POLICY);
        EXACT.add(REF_MEDIA_PROJECTION);
    }

    /** Class-name prefixes of commercial code protectors ("packers"); packed code hides its real logic from inspection. */
    private static final String[] PACKER_PREFIXES = {
            "Lcom/secneo/", "Lcom/qihoo/util/", "Lcom/tencent/StubShell/", "Lcom/baidu/protect/",
            "Lcom/bangcle/", "Lcom/ijiami/", "Lcom/shell/SuperApplication;", "Lcom/stub/StubApp;"};

    private static final Pattern URL = Pattern.compile("https?://[A-Za-z0-9._~:/?#\\[\\]@!$&'()*+,;=%-]{4,200}");

    private DexInspector() {}

    static boolean hasDexMagic(byte[] d) {
        return d != null && d.length >= 0x70 && d[0] == 'd' && d[1] == 'e' && d[2] == 'x' && d[3] == '\n'
                && Character.isDigit(d[4]) && Character.isDigit(d[5]) && Character.isDigit(d[6]) && d[7] == 0;
    }

    static void inspect(byte[] d, String name, Summary s) {
        s.files++;
        if (!hasDexMagic(d)) {
            s.invalidFiles++;
            s.errors.add(name + " is not a valid DEX file");
            return;
        }
        ByteBuffer b = ByteBuffer.wrap(d).order(ByteOrder.LITTLE_ENDIAN);
        if (b.getInt(0x28) != 0x12345678) {
            s.invalidFiles++;
            s.errors.add(name + " has an unexpected byte order tag");
            return;
        }
        long stringIdsSize = b.getInt(0x38) & 0xFFFFFFFFL;
        long stringIdsOff = b.getInt(0x3C) & 0xFFFFFFFFL;
        s.typeIds += b.getInt(0x40) & 0xFFFFFFFFL;
        s.methodIds += b.getInt(0x58) & 0xFFFFFFFFL;
        s.classDefs += b.getInt(0x60) & 0xFFFFFFFFL;
        if (stringIdsOff + stringIdsSize * 4 > d.length) {
            s.invalidFiles++;
            s.errors.add(name + " string table points outside the file");
            return;
        }
        long n = stringIdsSize;
        if (s.strings + n > MAX_STRINGS) {
            n = Math.max(0, MAX_STRINGS - s.strings);
            s.truncated = true;
        }
        boolean hasRuntime = false;
        for (int k = 0; k < n; k++) {
            int off = b.getInt((int) (stringIdsOff + k * 4L));
            String str = readMutf8(d, off);
            if (str == null) continue;
            s.strings++;
            if (EXACT.contains(str)) s.refs.add(str);
            if (str.equals("lockNow") || str.equals("wipeData")) s.refs.add(REF_LOCK_WIPE);
            if (str.equals("/system/bin/su") || str.equals("/system/xbin/su") || str.equals("/sbin/su")) s.refs.add(REF_SU);
            for (String p : PACKER_PREFIXES) if (str.startsWith(p)) s.refs.add(REF_PACKER);
            if (s.urls.size() < MAX_URLS && (str.contains("http://") || str.contains("https://"))) {
                Matcher m = URL.matcher(str);
                while (m.find() && s.urls.size() < MAX_URLS) {
                    String u = m.group();
                    if (!isSchemaNoise(u)) s.urls.add(u);
                }
            }
            if (str.equals(REF_RUNTIME)) hasRuntime = true;
        }
        if (!hasRuntime) s.refs.remove(REF_RUNTIME);
    }

    /** XML namespace / schema URLs that appear in almost every app and say nothing about behaviour. */
    private static boolean isSchemaNoise(String u) {
        return u.startsWith("http://schemas.android.com/") || u.startsWith("http://www.w3.org/")
                || u.startsWith("http://xml.org/") || u.startsWith("http://ns.adobe.com/") || u.startsWith("http://apache.org/");
    }

    /** Reads a string_data_item (uleb128 utf16 length + MUTF-8 bytes + NUL). Returns null if malformed. */
    static String readMutf8(byte[] d, int off) {
        if (off < 0 || off >= d.length) return null;
        int p = off;
        int len = 0, shift = 0;
        while (true) {
            if (p >= d.length || shift > 28) return null;
            int c = d[p++] & 0xFF;
            len |= (c & 0x7F) << shift;
            if ((c & 0x80) == 0) break;
            shift += 7;
        }
        if (len > 4096) return null; // long strings are not useful for reference matching
        int start = p;
        while (p < d.length && d[p] != 0) {
            if (p - start > len * 3) return null;
            p++;
        }
        if (p >= d.length) return null;
        return new String(d, start, p - start, StandardCharsets.UTF_8);
    }
}
