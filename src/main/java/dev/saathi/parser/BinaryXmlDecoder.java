package dev.saathi.parser;

import dev.saathi.model.ManifestMetadata;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Pure Java decoder for compiled Android Binary XML (AXML) manifests.
 * Extracts package identity, permissions, services, receivers, and intent filters without external libraries.
 */
public class BinaryXmlDecoder {

    private static final int RES_XML_TYPE = 0x0003;
    private static final int RES_STRING_POOL_TYPE = 0x0001;
    private static final int RES_XML_START_ELEMENT_TYPE = 0x0102;
    private static final int RES_XML_END_ELEMENT_TYPE = 0x0103;

    public static ManifestMetadata decode(byte[] axmlBytes) {
        if (axmlBytes == null || axmlBytes.length < 8) {
            return fallbackEmpty("Invalid or empty manifest bytes");
        }

        try {
            // Check if it's plain text XML (e.g., in synthetic test cases or uncompiled files)
            String preview = new String(axmlBytes, 0, Math.min(axmlBytes.length, 128), StandardCharsets.UTF_8).trim();
            if (preview.startsWith("<?xml") || preview.startsWith("<manifest")) {
                return parsePlainTextXml(new String(axmlBytes, StandardCharsets.UTF_8));
            }

            ByteBuffer buffer = ByteBuffer.wrap(axmlBytes).order(ByteOrder.LITTLE_ENDIAN);
            int magic = buffer.getShort() & 0xFFFF;
            if (magic != RES_XML_TYPE) {
                // If not standard AXML magic, attempt plain XML fallback
                return parsePlainTextXml(new String(axmlBytes, StandardCharsets.UTF_8));
            }

            buffer.position(8); // Skip main chunk header

            List<String> stringPool = new ArrayList<>();
            String packageName = "unknown.package";
            String versionName = "1.0";
            int versionCode = 1;
            int minSdk = 21;
            int targetSdk = 33;
            Set<String> requestedPermissions = new HashSet<>();
            List<String> activities = new ArrayList<>();
            List<String> services = new ArrayList<>();
            List<String> receivers = new ArrayList<>();
            boolean hasCustomDeviceAdmin = false;
            boolean hasAccessibilityService = false;
            boolean hasLauncherActivity = false;

            String currentTag = null;
            boolean inIntentFilter = false;
            boolean hasMainAction = false;
            boolean hasLauncherCategory = false;

            while (buffer.remaining() >= 8) {
                int chunkType = buffer.getShort() & 0xFFFF;
                int headerSize = buffer.getShort() & 0xFFFF;
                int chunkSize = buffer.getInt();

                int chunkDataStart = buffer.position();
                int nextChunkOffset = chunkDataStart - 8 + chunkSize;

                if (chunkType == RES_STRING_POOL_TYPE) {
                    stringPool = parseStringPool(buffer, chunkDataStart - 8, chunkSize);
                } else if (chunkType == RES_XML_START_ELEMENT_TYPE) {
                    buffer.position(chunkDataStart + 8); // Skip line number and comment index
                    int uriIdx = buffer.getInt();
                    int nameIdx = buffer.getInt();
                    int attrStart = buffer.getShort() & 0xFFFF;
                    int attrSize = buffer.getShort() & 0xFFFF;
                    int attrCount = buffer.getShort() & 0xFFFF;

                    String tagName = getString(stringPool, nameIdx);
                    currentTag = tagName;

                    Map<String, String> attributes = new HashMap<>();
                    buffer.position(chunkDataStart - 8 + attrStart);

                    for (int i = 0; i < attrCount; i++) {
                        int attrUri = buffer.getInt();
                        int attrNameIdx = buffer.getInt();
                        int attrValueStringIdx = buffer.getInt();
                        int attrType = buffer.getInt();
                        int attrData = buffer.getInt();

                        String attrName = getString(stringPool, attrNameIdx);
                        String attrVal = attrValueStringIdx >= 0 ? getString(stringPool, attrValueStringIdx) : String.valueOf(attrData);
                        if (attrName != null && attrVal != null) {
                            attributes.put(attrName, attrVal);
                        }
                    }

                    if ("manifest".equalsIgnoreCase(tagName)) {
                        if (attributes.containsKey("package")) packageName = attributes.get("package");
                        if (attributes.containsKey("versionName")) versionName = attributes.get("versionName");
                    } else if ("uses-permission".equalsIgnoreCase(tagName)) {
                        String perm = attributes.get("name");
                        if (perm != null) requestedPermissions.add(perm);
                    } else if ("activity".equalsIgnoreCase(tagName)) {
                        String name = attributes.get("name");
                        if (name != null) activities.add(name);
                    } else if ("service".equalsIgnoreCase(tagName)) {
                        String name = attributes.get("name");
                        if (name != null) services.add(name);
                        String permission = attributes.get("permission");
                        if (permission != null && permission.contains("BIND_ACCESSIBILITY_SERVICE")) {
                            hasAccessibilityService = true;
                        }
                    } else if ("receiver".equalsIgnoreCase(tagName)) {
                        String name = attributes.get("name");
                        if (name != null) receivers.add(name);
                        String permission = attributes.get("permission");
                        if (permission != null && permission.contains("BIND_DEVICE_ADMIN")) {
                            hasCustomDeviceAdmin = true;
                        }
                    } else if ("intent-filter".equalsIgnoreCase(tagName)) {
                        inIntentFilter = true;
                        hasMainAction = false;
                        hasLauncherCategory = false;
                    } else if ("action".equalsIgnoreCase(tagName) && inIntentFilter) {
                        String actionName = attributes.get("name");
                        if ("android.intent.action.MAIN".equals(actionName)) {
                            hasMainAction = true;
                        }
                    } else if ("category".equalsIgnoreCase(tagName) && inIntentFilter) {
                        String catName = attributes.get("name");
                        if ("android.intent.category.LAUNCHER".equals(catName)) {
                            hasLauncherCategory = true;
                        }
                    }
                } else if (chunkType == RES_XML_END_ELEMENT_TYPE) {
                    if (inIntentFilter && hasMainAction && hasLauncherCategory) {
                        hasLauncherActivity = true;
                        inIntentFilter = false;
                    }
                }

                if (nextChunkOffset > 0 && nextChunkOffset <= buffer.limit()) {
                    buffer.position(nextChunkOffset);
                } else {
                    break;
                }
            }

            return new ManifestMetadata(
                    packageName,
                    versionName,
                    versionCode,
                    minSdk,
                    targetSdk,
                    requestedPermissions,
                    activities,
                    services,
                    receivers,
                    hasCustomDeviceAdmin,
                    hasAccessibilityService,
                    hasLauncherActivity
            );

        } catch (Exception e) {
            return parsePlainTextXml(new String(axmlBytes, StandardCharsets.UTF_8));
        }
    }

    private static List<String> parseStringPool(ByteBuffer buffer, int poolStart, int poolSize) {
        List<String> pool = new ArrayList<>();
        try {
            buffer.position(poolStart + 8);
            int stringCount = buffer.getInt();
            int styleCount = buffer.getInt();
            int flags = buffer.getInt();
            int stringsOffset = buffer.getInt();
            int stylesOffset = buffer.getInt();

            boolean isUtf8 = (flags & (1 << 8)) != 0;

            int[] offsets = new int[stringCount];
            for (int i = 0; i < stringCount; i++) {
                offsets[i] = buffer.getInt();
            }

            int stringDataStart = poolStart + stringsOffset;
            for (int i = 0; i < stringCount; i++) {
                buffer.position(stringDataStart + offsets[i]);
                if (isUtf8) {
                    int u8len = buffer.get() & 0xFF;
                    byte[] bytes = new byte[u8len];
                    buffer.get(bytes);
                    pool.add(new String(bytes, StandardCharsets.UTF_8));
                } else {
                    int u16len = buffer.getShort() & 0xFFFF;
                    char[] chars = new char[u16len];
                    for (int c = 0; c < u16len; c++) {
                        chars[c] = buffer.getChar();
                    }
                    pool.add(new String(chars));
                }
            }
        } catch (Exception ignored) {
        }
        return pool;
    }

    private static String getString(List<String> pool, int index) {
        if (index >= 0 && index < pool.size()) {
            return pool.get(index);
        }
        return null;
    }

    /**
     * Resilient fallback parser for XML manifests in test environments or non-compiled structures.
     */
    public static ManifestMetadata parsePlainTextXml(String xml) {
        Set<String> permissions = new HashSet<>();
        List<String> activities = new ArrayList<>();
        List<String> services = new ArrayList<>();
        List<String> receivers = new ArrayList<>();
        String packageName = "com.example.app";
        String versionName = "1.0.0";
        boolean hasAccessibility = false;
        boolean hasDeviceAdmin = false;
        boolean hasLauncher = false;

        for (String line : xml.split("\n")) {
            String trimmed = line.trim();
            if (trimmed.contains("package=\"")) {
                int start = trimmed.indexOf("package=\"") + 9;
                int end = trimmed.indexOf("\"", start);
                if (end > start) packageName = trimmed.substring(start, end);
            }
            if (trimmed.contains("uses-permission") && trimmed.contains("android:name=\"")) {
                int start = trimmed.indexOf("android:name=\"") + 14;
                int end = trimmed.indexOf("\"", start);
                if (end > start) permissions.add(trimmed.substring(start, end));
            }
            if (trimmed.contains("<activity") && trimmed.contains("android:name=\"")) {
                int start = trimmed.indexOf("android:name=\"") + 14;
                int end = trimmed.indexOf("\"", start);
                if (end > start) activities.add(trimmed.substring(start, end));
            }
            if (trimmed.contains("<service") && trimmed.contains("android:name=\"")) {
                int start = trimmed.indexOf("android:name=\"") + 14;
                int end = trimmed.indexOf("\"", start);
                if (end > start) services.add(trimmed.substring(start, end));
            }
            if (trimmed.contains("<receiver") && trimmed.contains("android:name=\"")) {
                int start = trimmed.indexOf("android:name=\"") + 14;
                int end = trimmed.indexOf("\"", start);
                if (end > start) receivers.add(trimmed.substring(start, end));
            }
            if (trimmed.contains("BIND_ACCESSIBILITY_SERVICE")) {
                hasAccessibility = true;
            }
            if (trimmed.contains("BIND_DEVICE_ADMIN")) {
                hasDeviceAdmin = true;
            }
            if (trimmed.contains("android.intent.category.LAUNCHER")) {
                hasLauncher = true;
            }
        }

        return new ManifestMetadata(
                packageName, versionName, 1, 21, 34,
                permissions, activities, services, receivers,
                hasDeviceAdmin, hasAccessibility, hasLauncher
        );
    }

    private static ManifestMetadata fallbackEmpty(String reason) {
        return new ManifestMetadata(
                "unknown.package", "0.0", 0, 0, 0,
                Collections.emptySet(), Collections.emptyList(), Collections.emptyList(), Collections.emptyList(),
                false, false, false
        );
    }
}
