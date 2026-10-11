package dev.saathi.shield.apk;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Parser for Android compiled binary XML (AXML), as used for AndroidManifest.xml inside APKs.
 * Implements the documented ResChunk format (string pool, resource map, start/end element chunks) with bounds
 * checks on every read. Unknown values are left null rather than replaced with defaults.
 * Does not resolve resource references (e.g. @string/app_name) because resources.arsc is not decoded.
 */
public final class AxmlParser {

    public static class ParseException extends Exception {
        public ParseException(String m) { super(m); }
    }

    private static final int RES_STRING_POOL = 0x0001;
    private static final int RES_XML = 0x0003;
    private static final int RES_XML_START_NS = 0x0100;
    private static final int RES_XML_END_NS = 0x0101;
    private static final int RES_XML_START_ELEMENT = 0x0102;
    private static final int RES_XML_END_ELEMENT = 0x0103;
    private static final int RES_XML_CDATA = 0x0104;
    private static final int RES_XML_RESOURCE_MAP = 0x0180;

    private static final int TYPE_REFERENCE = 0x01;
    private static final int TYPE_STRING = 0x03;
    private static final int TYPE_INT_DEC = 0x10;
    private static final int TYPE_INT_HEX = 0x11;
    private static final int TYPE_BOOLEAN = 0x12;

    // android.R.attr ids, used when attribute name strings are stripped/obfuscated
    private static final Map<Integer, String> ATTR_IDS = new HashMap<>();
    static {
        ATTR_IDS.put(0x01010001, "label");
        ATTR_IDS.put(0x01010003, "name");
        ATTR_IDS.put(0x01010006, "permission");
        ATTR_IDS.put(0x0101000f, "debuggable");
        ATTR_IDS.put(0x01010010, "exported");
        ATTR_IDS.put(0x0101020c, "minSdkVersion");
        ATTR_IDS.put(0x0101021b, "versionCode");
        ATTR_IDS.put(0x0101021c, "versionName");
        ATTR_IDS.put(0x01010270, "targetSdkVersion");
        ATTR_IDS.put(0x010104ec, "usesCleartextTraffic");
    }

    private static final int MAX_STRINGS = 200_000;
    private static final int MAX_ELEMENTS = 200_000;

    /** A decoded attribute value: exactly one of str / num / bool / ref is meaningful. */
    static final class Val {
        String str; Long num; Boolean bool; Integer ref;
        String asString() {
            if (str != null) return str;
            if (num != null) return String.valueOf(num);
            if (bool != null) return String.valueOf(bool);
            if (ref != null) return String.format("@0x%08x", ref);
            return null;
        }
    }

    private AxmlParser() {}

    public static ManifestInfo parse(byte[] data) throws ParseException {
        if (data == null || data.length < 8) throw new ParseException("Manifest is empty or truncated");
        ByteBuffer b = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        int type = u16(b, 0);
        if (type != RES_XML) {
            String head = new String(data, 0, Math.min(16, data.length), StandardCharsets.ISO_8859_1).trim();
            if (head.startsWith("<")) throw new ParseException("Manifest is plain-text XML, not a compiled Android manifest");
            throw new ParseException("Manifest does not start with an Android binary XML header");
        }
        int headerSize = u16(b, 2);
        long total = u32(b, 4);
        if (headerSize < 8 || total > data.length || total < headerSize) throw new ParseException("Manifest header sizes are inconsistent");

        List<String> strings = new ArrayList<>();
        int[] resMap = new int[0];
        ManifestInfo.Builder mb = new ManifestInfo.Builder();
        Deque<String> stack = new ArrayDeque<>();
        Deque<Map<String, Val>> attrStack = new ArrayDeque<>();
        int elements = 0;

        int pos = headerSize;
        while (pos + 8 <= total) {
            int ct = u16(b, pos);
            int chs = u16(b, pos + 2);
            long cs = u32(b, pos + 4);
            if (cs < 8 || pos + cs > total || chs > cs) throw new ParseException("Corrupt chunk at offset " + pos);
            int end = (int) (pos + cs);
            switch (ct) {
                case RES_STRING_POOL:
                    strings = parseStringPool(b, pos, chs, end);
                    break;
                case RES_XML_RESOURCE_MAP: {
                    int n = (end - pos - chs) / 4;
                    resMap = new int[n];
                    for (int k = 0; k < n; k++) resMap[k] = (int) u32(b, pos + chs + k * 4);
                    break;
                }
                case RES_XML_START_ELEMENT: {
                    if (++elements > MAX_ELEMENTS) throw new ParseException("Manifest has too many elements");
                    int ext = pos + chs;
                    need(ext + 20, end);
                    String name = str(strings, (int) u32(b, ext + 4));
                    int attrStart = u16(b, ext + 8);
                    int attrSize = u16(b, ext + 10);
                    int attrCount = u16(b, ext + 12);
                    if (attrSize < 20) throw new ParseException("Bad attribute size");
                    Map<String, Val> attrs = new HashMap<>();
                    for (int k = 0; k < attrCount; k++) {
                        int a = ext + attrStart + k * attrSize;
                        need(a + 20, end);
                        int nameIdx = (int) u32(b, a + 4);
                        int rawIdx = (int) u32(b, a + 8);
                        int dataType = b.get(a + 15) & 0xFF;
                        int dv = (int) u32(b, a + 16);
                        String an = nameIdx >= 0 && nameIdx < resMap.length && ATTR_IDS.containsKey(resMap[nameIdx])
                                ? ATTR_IDS.get(resMap[nameIdx]) : str(strings, nameIdx);
                        if (an == null || an.isEmpty()) continue;
                        Val v = new Val();
                        if (dataType == TYPE_STRING) v.str = str(strings, dv);
                        else if (dataType == TYPE_INT_DEC || dataType == TYPE_INT_HEX) v.num = (long) dv;
                        else if (dataType == TYPE_BOOLEAN) v.bool = dv != 0;
                        else if (dataType == TYPE_REFERENCE) v.ref = dv;
                        else if (rawIdx >= 0) v.str = str(strings, rawIdx);
                        attrs.put(an, v);
                    }
                    onStart(mb, name, attrs, stack, attrStack);
                    stack.push(name == null ? "" : name);
                    attrStack.push(attrs);
                    break;
                }
                case RES_XML_END_ELEMENT:
                    if (!stack.isEmpty()) {
                        String closing = stack.pop();
                        Map<String, Val> attrs = attrStack.pop();
                        onEnd(mb, closing, attrs, stack, attrStack);
                    }
                    break;
                case RES_XML_START_NS:
                case RES_XML_END_NS:
                case RES_XML_CDATA:
                    break;
                default:
                    // Unknown chunk types are skipped by size, as the platform does.
                    break;
            }
            pos = end;
        }
        if (mb.packageName == null) throw new ParseException("Manifest has no package name");
        return mb.build();
    }

    // ---- semantic extraction --------------------------------------------

    private static String s(Map<String, Val> a, String k) {
        Val v = a.get(k);
        return v == null ? null : v.asString();
    }

    private static void onStart(ManifestInfo.Builder mb, String tag, Map<String, Val> a,
                                Deque<String> stack, Deque<Map<String, Val>> attrStack) {
        if (tag == null) return;
        String parent = stack.peek();
        switch (tag) {
            case "manifest":
                mb.packageName = s(a, "package");
                Val vc = a.get("versionCode");
                if (vc != null && vc.num != null) mb.versionCode = vc.num & 0xFFFFFFFFL;
                mb.versionName = s(a, "versionName");
                break;
            case "uses-sdk": {
                Val min = a.get("minSdkVersion");
                Val tgt = a.get("targetSdkVersion");
                if (min != null && min.num != null) mb.minSdk = min.num.intValue();
                if (tgt != null && tgt.num != null) mb.targetSdk = tgt.num.intValue();
                break;
            }
            case "uses-permission":
            case "uses-permission-sdk-23": {
                String p = s(a, "name");
                if (p != null && !mb.permissions.contains(p)) mb.permissions.add(p);
                break;
            }
            case "application": {
                Val d = a.get("debuggable");
                mb.debuggable = d != null && Boolean.TRUE.equals(d.bool);
                Val ct = a.get("usesCleartextTraffic");
                if (ct != null && ct.bool != null) mb.usesCleartextTraffic = ct.bool;
                Val l = a.get("label");
                if (l != null) mb.label = l.str != null ? l.str : (l.ref != null ? "(resource label)" : null);
                break;
            }
            case "activity":
            case "activity-alias":
                mb.activities++;
                break;
            case "service": {
                mb.services++;
                String perm = s(a, "permission");
                if ("android.permission.BIND_ACCESSIBILITY_SERVICE".equals(perm)) mb.accessibilityServices.add(nameOf(a));
                if ("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE".equals(perm)) mb.notificationListeners.add(nameOf(a));
                break;
            }
            case "receiver": {
                mb.receivers++;
                if ("android.permission.BIND_DEVICE_ADMIN".equals(s(a, "permission"))) mb.deviceAdminReceivers.add(nameOf(a));
                break;
            }
            case "provider":
                mb.providers++;
                break;
            case "action": {
                String act = s(a, "name");
                if ("intent-filter".equals(parent) && act != null) {
                    String component = componentOf(stack, attrStack);
                    if ("android.accessibilityservice.AccessibilityService".equals(act)) mb.accessibilityServices.add(component);
                    if ("android.app.action.DEVICE_ADMIN_ENABLED".equals(act)) mb.deviceAdminReceivers.add(component);
                    if ("android.provider.Telephony.SMS_RECEIVED".equals(act)) mb.smsReceivers.add(component);
                    if ("android.intent.action.BOOT_COMPLETED".equals(act)) mb.bootReceivers.add(component);
                    if ("android.intent.action.MAIN".equals(act)) mb.pendingMain = true;
                }
                break;
            }
            case "category":
                if ("intent-filter".equals(parent) && "android.intent.category.LAUNCHER".equals(s(a, "name"))) mb.pendingLauncher = true;
                break;
            case "intent-filter":
                mb.pendingMain = false;
                mb.pendingLauncher = false;
                break;
            default:
                break;
        }
    }

    private static void onEnd(ManifestInfo.Builder mb, String tag, Map<String, Val> a,
                              Deque<String> stack, Deque<Map<String, Val>> attrStack) {
        if ("intent-filter".equals(tag)) {
            if (mb.pendingMain && mb.pendingLauncher) mb.hasLauncherActivity = true;
            mb.pendingMain = false;
            mb.pendingLauncher = false;
        }
    }

    private static String nameOf(Map<String, Val> a) {
        String n = s(a, "name");
        return n == null ? "(unnamed)" : n;
    }

    /** Name of the component (activity/service/receiver) enclosing the current intent-filter. */
    private static String componentOf(Deque<String> stack, Deque<Map<String, Val>> attrStack) {
        java.util.Iterator<String> ti = stack.iterator();
        java.util.Iterator<Map<String, Val>> ai = attrStack.iterator();
        while (ti.hasNext() && ai.hasNext()) {
            String t = ti.next();
            Map<String, Val> at = ai.next();
            if (t.equals("activity") || t.equals("service") || t.equals("receiver") || t.equals("activity-alias")) return nameOf(at);
        }
        return "(unnamed)";
    }

    // ---- low-level --------------------------------------------------------

    private static List<String> parseStringPool(ByteBuffer b, int pos, int hs, int end) throws ParseException {
        need(pos + 28, end);
        long count = u32(b, pos + 8);
        long flags = u32(b, pos + 16);
        long stringsStart = u32(b, pos + 20);
        if (count > MAX_STRINGS) throw new ParseException("String pool too large");
        boolean utf8 = (flags & 0x100) != 0;
        int offsets = pos + hs;
        need(offsets + (int) count * 4, end);
        List<String> out = new ArrayList<>((int) count);
        for (int k = 0; k < count; k++) {
            int so = (int) (pos + stringsStart + u32(b, offsets + k * 4));
            if (so < pos || so >= end) { out.add(null); continue; }
            try {
                out.add(utf8 ? readUtf8(b, so, end) : readUtf16(b, so, end));
            } catch (ParseException e) {
                out.add(null);
            }
        }
        return out;
    }

    private static String readUtf8(ByteBuffer b, int p, int end) throws ParseException {
        need(p + 2, end);
        int c = b.get(p) & 0xFF;               // UTF-16 length (1 or 2 bytes) — skipped
        p += (c & 0x80) != 0 ? 2 : 1;
        need(p + 1, end);
        int n = b.get(p) & 0xFF;               // UTF-8 byte length (1 or 2 bytes)
        if ((n & 0x80) != 0) { need(p + 2, end); n = ((n & 0x7F) << 8) | (b.get(p + 1) & 0xFF); p += 2; } else p += 1;
        need(p + n, end);
        byte[] bytes = new byte[n];
        for (int k = 0; k < n; k++) bytes[k] = b.get(p + k);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static String readUtf16(ByteBuffer b, int p, int end) throws ParseException {
        need(p + 2, end);
        int n = u16(b, p);
        p += 2;
        if ((n & 0x8000) != 0) { need(p + 2, end); n = ((n & 0x7FFF) << 16) | u16(b, p); p += 2; }
        need(p + n * 2, end);
        char[] cs = new char[n];
        for (int k = 0; k < n; k++) cs[k] = (char) u16(b, p + k * 2);
        return new String(cs);
    }

    private static String str(List<String> pool, int idx) {
        return idx >= 0 && idx < pool.size() ? pool.get(idx) : null;
    }

    private static void need(long upTo, long end) throws ParseException {
        if (upTo > end || upTo < 0) throw new ParseException("Manifest data is truncated");
    }

    private static int u16(ByteBuffer b, int p) throws ParseException {
        if (p < 0 || p + 2 > b.limit()) throw new ParseException("Manifest data is truncated");
        return b.getShort(p) & 0xFFFF;
    }

    private static long u32(ByteBuffer b, int p) throws ParseException {
        if (p < 0 || p + 4 > b.limit()) throw new ParseException("Manifest data is truncated");
        return b.getInt(p) & 0xFFFFFFFFL;
    }
}
