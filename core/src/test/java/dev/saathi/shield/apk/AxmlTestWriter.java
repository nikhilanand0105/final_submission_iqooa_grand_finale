package dev.saathi.shield.apk;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

/** Builds minimal compiled-AXML manifests for tests (UTF-16 string pool, typed attributes). */
final class AxmlTestWriter {

    private final List<String> pool = new ArrayList<>();
    private final ByteArrayOutputStream body = new ByteArrayOutputStream();

    int s(String v) {
        int i = pool.indexOf(v);
        if (i >= 0) return i;
        pool.add(v);
        return pool.size() - 1;
    }

    /** attrs: name, type, value(String for string type, Integer otherwise) triples. */
    AxmlTestWriter start(String tag, Object... attrs) {
        int n = attrs.length / 3;
        ByteBuffer b = ByteBuffer.allocate(36 + n * 20).order(ByteOrder.LITTLE_ENDIAN);
        b.putShort((short) 0x0102).putShort((short) 16).putInt(36 + n * 20).putInt(1).putInt(-1);
        b.putInt(-1).putInt(s(tag)).putShort((short) 20).putShort((short) 20).putShort((short) n)
                .putShort((short) 0).putShort((short) 0).putShort((short) 0);
        for (int k = 0; k < n; k++) {
            String an = (String) attrs[k * 3];
            int type = (Integer) attrs[k * 3 + 1];
            Object v = attrs[k * 3 + 2];
            int data = type == 0x03 ? s((String) v) : (Integer) v;
            b.putInt(-1).putInt(s(an)).putInt(type == 0x03 ? data : -1).putShort((short) 8).put((byte) 0).put((byte) type).putInt(data);
        }
        body.write(b.array(), 0, b.capacity());
        return this;
    }

    AxmlTestWriter end(String tag) {
        ByteBuffer b = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        b.putShort((short) 0x0103).putShort((short) 16).putInt(24).putInt(1).putInt(-1).putInt(-1).putInt(s(tag));
        body.write(b.array(), 0, 24);
        return this;
    }

    byte[] build() {
        ByteArrayOutputStream strData = new ByteArrayOutputStream();
        int[] offs = new int[pool.size()];
        for (int k = 0; k < pool.size(); k++) {
            offs[k] = strData.size();
            String v = pool.get(k);
            ByteBuffer sb = ByteBuffer.allocate(2 + v.length() * 2 + 2).order(ByteOrder.LITTLE_ENDIAN);
            sb.putShort((short) v.length());
            for (char c : v.toCharArray()) sb.putChar(c);
            sb.putShort((short) 0);
            strData.write(sb.array(), 0, sb.capacity());
        }
        while (strData.size() % 4 != 0) strData.write(0);
        int poolHeader = 28;
        int poolSize = poolHeader + pool.size() * 4 + strData.size();
        ByteBuffer p = ByteBuffer.allocate(poolSize).order(ByteOrder.LITTLE_ENDIAN);
        p.putShort((short) 1).putShort((short) poolHeader).putInt(poolSize).putInt(pool.size()).putInt(0)
                .putInt(0).putInt(poolHeader + pool.size() * 4).putInt(0);
        for (int o : offs) p.putInt(o);
        p.put(strData.toByteArray());
        byte[] bodyBytes = body.toByteArray();
        int total = 8 + poolSize + bodyBytes.length;
        ByteBuffer out = ByteBuffer.allocate(total).order(ByteOrder.LITTLE_ENDIAN);
        out.putShort((short) 3).putShort((short) 8).putInt(total).put(p.array()).put(bodyBytes);
        return out.array();
    }

    static final int STR = 0x03, INT = 0x10, BOOL = 0x12;

    /** Manifest with the given permissions and optional extras. */
    static byte[] manifest(String pkg, int targetSdk, boolean launcher, boolean accessibility, String... perms) {
        AxmlTestWriter w = new AxmlTestWriter();
        w.start("manifest", "package", STR, pkg, "versionCode", INT, 42, "versionName", STR, "2.0");
        w.start("uses-sdk", "minSdkVersion", INT, 21, "targetSdkVersion", INT, targetSdk).end("uses-sdk");
        for (String p : perms) w.start("uses-permission", "name", STR, p).end("uses-permission");
        w.start("application", "label", STR, "Test App");
        w.start("activity", "name", STR, ".Main");
        if (launcher) {
            w.start("intent-filter");
            w.start("action", "name", STR, "android.intent.action.MAIN").end("action");
            w.start("category", "name", STR, "android.intent.category.LAUNCHER").end("category");
            w.end("intent-filter");
        }
        w.end("activity");
        if (accessibility) {
            w.start("service", "name", STR, ".Watcher", "permission", STR, "android.permission.BIND_ACCESSIBILITY_SERVICE").end("service");
        }
        w.end("application").end("manifest");
        return w.build();
    }
}
