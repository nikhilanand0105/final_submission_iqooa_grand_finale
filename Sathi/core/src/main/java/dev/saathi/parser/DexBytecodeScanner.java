package dev.saathi.parser;

import dev.saathi.model.DexInspectionResult;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pure Java parser for Dalvik Executable (DEX) files.
 * Scans bytecode structures, string identifiers, and method references to detect dangerous APIs,
 * dynamic code loaders, command executions, and suspicious network indicators.
 */
public class DexBytecodeScanner {

    private static final byte[] DEX_MAGIC_PREFIX = new byte[]{'d', 'e', 'x', '\n'};
    private static final Pattern URL_PATTERN = Pattern.compile("https?://[a-zA-Z0-9.-]+(:[0-9]+)?(/[a-zA-Z0-9._~:/?#\\[\\]@!$&'()*+,;=-]*)?");
    private static final Pattern IP_PATTERN = Pattern.compile("\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b");

    private static final List<String> DYNAMIC_LOADING_APIS = Arrays.asList(
            "Ldalvik/system/DexClassLoader;",
            "Ldalvik/system/InMemoryDexClassLoader;",
            "Ldalvik/system/PathClassLoader;",
            "loadDex"
    );

    private static final List<String> REFLECTION_APIS = Arrays.asList(
            "Ljava/lang/reflect/Method;->invoke",
            "Ljava/lang/Class;->forName",
            "Ljava/lang/Class;->getMethod",
            "Ljava/lang/Class;->getDeclaredMethod"
    );

    private static final List<String> COMMAND_EXEC_APIS = Arrays.asList(
            "Ljava/lang/Runtime;->exec",
            "Ljava/lang/ProcessBuilder;->start",
            "/system/bin/sh",
            "/bin/sh"
    );

    private static final List<String> NATIVE_LOAD_APIS = Arrays.asList(
            "Ljava/lang/System;->loadLibrary",
            "Ljava/lang/System;->load"
    );

    private static final List<String> ROOT_CHECK_STRINGS = Arrays.asList(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/system/app/Superuser.apk",
            "test-keys",
            "com.topjohnwu.magisk"
    );

    private static final List<String> ACCESSIBILITY_ABUSE_STRINGS = Arrays.asList(
            "performGlobalAction",
            "findAccessibilityNodeInfosByViewId",
            "findAccessibilityNodeInfosByText",
            "FLAG_RETRIEVE_INTERACTIVE_WINDOWS",
            "AccessibilityServiceInfo"
    );

    private static final List<String> WHATSAPP_MOD_STRINGS = Arrays.asList(
            "com/gbwhatsapp",
            "com/whatsapp/plus",
            "com/yowhatsapp",
            "com/fmwhatsapp",
            "com/whatsapp/gold",
            "GBWhatsApp",
            "WhatsApp Plus",
            "YoWhatsApp",
            "FMWhatsApp",
            "WhatsApp Gold",
            "WhatsAppMod",
            "WhatsAppPlus",
            "GBSettings",
            "YoSettings",
            "FMSettings",
            "AeroSettings",
            "Anti-Ban",
            "WA Tweaker"
    );

    public static DexInspectionResult scan(List<byte[]> dexFilesBytes) {
        if (dexFilesBytes == null || dexFilesBytes.isEmpty()) {
            return new DexInspectionResult(0, 0, 0, Collections.emptySet(), Collections.emptyList(), Collections.emptyList(), false, false, false, false, false, false);
        }

        int dexCount = dexFilesBytes.size();
        int totalClasses = 0;
        int totalMethods = 0;
        Set<String> suspiciousApis = new HashSet<>();
        Set<String> urls = new HashSet<>();
        Set<String> ips = new HashSet<>();

        boolean usesDynamicLoading = false;
        boolean usesReflection = false;
        boolean executesCommands = false;
        boolean loadsNative = false;
        boolean hasRootCheck = false;
        boolean hasAccessibilityAbuse = false;

        for (byte[] dexBytes : dexFilesBytes) {
            if (dexBytes == null || dexBytes.length < 4) continue;

            List<String> strings = new ArrayList<>();

            // If valid DEX header is present, parse structural string pool
            if (dexBytes.length >= 112 &&
                dexBytes[0] == DEX_MAGIC_PREFIX[0] && dexBytes[1] == DEX_MAGIC_PREFIX[1] &&
                dexBytes[2] == DEX_MAGIC_PREFIX[2] && dexBytes[3] == DEX_MAGIC_PREFIX[3]) {

                ByteBuffer buffer = ByteBuffer.wrap(dexBytes).order(ByteOrder.LITTLE_ENDIAN);
                try {
                    buffer.position(56);
                    int stringIdsSize = buffer.getInt();
                    int stringIdsOff = buffer.getInt();
                    int typeIdsSize = buffer.getInt();
                    int typeIdsOff = buffer.getInt();
                    int protoIdsSize = buffer.getInt();
                    int protoIdsOff = buffer.getInt();
                    int fieldIdsSize = buffer.getInt();
                    int fieldIdsOff = buffer.getInt();
                    int methodIdsSize = buffer.getInt();
                    int methodIdsOff = buffer.getInt();
                    int classDefsSize = buffer.getInt();
                    int classDefsOff = buffer.getInt();

                    totalClasses += classDefsSize;
                    totalMethods += methodIdsSize;

                    // Read string pool
                    strings = readStrings(buffer, stringIdsSize, stringIdsOff);
                } catch (Exception ignored) {
                }
            }

            // Fallback: extract ASCII / UTF-8 string tokens if table parsing produced no strings
            if (strings == null || strings.isEmpty()) {
                strings = extractRawStrings(dexBytes);
            }

            for (String str : strings) {
                if (str == null || str.isEmpty()) continue;

                for (String modStr : WHATSAPP_MOD_STRINGS) {
                    if (str.contains(modStr)) {
                        suspiciousApis.add("WhatsAppModIdentifier: " + modStr);
                    }
                }

                for (String api : DYNAMIC_LOADING_APIS) {
                    if (str.contains(api)) {
                        usesDynamicLoading = true;
                        suspiciousApis.add("DynamicClassLoader: " + api);
                    }
                }

                for (String api : REFLECTION_APIS) {
                    if (str.contains(api)) {
                            usesReflection = true;
                            suspiciousApis.add("Reflection: " + api);
                        }
                    }

                    for (String api : COMMAND_EXEC_APIS) {
                        if (str.contains(api)) {
                            executesCommands = true;
                            suspiciousApis.add("ShellExecution: " + api);
                        }
                    }

                    for (String api : NATIVE_LOAD_APIS) {
                        if (str.contains(api)) {
                            loadsNative = true;
                            suspiciousApis.add("NativeLibraryLoader: " + api);
                        }
                    }

                    for (String rootStr : ROOT_CHECK_STRINGS) {
                        if (str.contains(rootStr)) {
                            hasRootCheck = true;
                        }
                    }

                    for (String accStr : ACCESSIBILITY_ABUSE_STRINGS) {
                        if (str.contains(accStr)) {
                            hasAccessibilityAbuse = true;
                            suspiciousApis.add("AccessibilityInteraction: " + accStr);
                        }
                    }

                    // Extract URLs and IPs if length is appropriate
                    if (str.length() > 7 && (str.startsWith("http://") || str.startsWith("https://"))) {
                        Matcher urlMatcher = URL_PATTERN.matcher(str);
                        while (urlMatcher.find()) {
                            urls.add(urlMatcher.group());
                        }
                    }

                    Matcher ipMatcher = IP_PATTERN.matcher(str);
                    while (ipMatcher.find()) {
                        String matchedIp = ipMatcher.group();
                        if (!matchedIp.equals("0.0.0.0") && !matchedIp.equals("127.0.0.1")) {
                            ips.add(matchedIp);
                        }
                }
            }
        }

        return new DexInspectionResult(
                dexCount,
                totalClasses,
                totalMethods,
                suspiciousApis,
                new ArrayList<>(urls),
                new ArrayList<>(ips),
                usesDynamicLoading,
                usesReflection,
                executesCommands,
                loadsNative,
                hasRootCheck,
                hasAccessibilityAbuse
        );
    }

    private static List<String> readStrings(ByteBuffer buffer, int stringIdsSize, int stringIdsOff) {
        List<String> strings = new ArrayList<>(Math.min(stringIdsSize, 10000));
        try {
            int countToRead = Math.min(stringIdsSize, 15000); // Safety limit for memory on constrained devices
            int[] stringDataOffsets = new int[countToRead];

            buffer.position(stringIdsOff);
            for (int i = 0; i < countToRead; i++) {
                stringDataOffsets[i] = buffer.getInt();
            }

            for (int offset : stringDataOffsets) {
                if (offset < 0 || offset >= buffer.limit()) continue;
                buffer.position(offset);
                // Read MUTF-8 length (ULEB128)
                int utf16Length = readUleb128(buffer);
                // Read until null terminator
                StringBuilder sb = new StringBuilder();
                while (buffer.hasRemaining()) {
                    byte b = buffer.get();
                    if (b == 0) break;
                    sb.append((char) (b & 0xFF));
                    if (sb.length() > 512) break; // Avoid gigantic string allocations
                }
                strings.add(sb.toString());
            }
        } catch (Exception ignored) {
        }
        return strings;
    }

    private static int readUleb128(ByteBuffer buffer) {
        int result = 0;
        int shift = 0;
        while (buffer.hasRemaining()) {
            byte b = buffer.get();
            result |= (b & 0x7F) << shift;
            if ((b & 0x80) == 0) break;
            shift += 7;
            if (shift > 28) break;
        }
        return result;
    }

    private static List<String> extractRawStrings(byte[] data) {
        List<String> list = new ArrayList<>();
        if (data == null) return list;
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            if (b >= 32 && b <= 126) {
                sb.append((char) b);
                if (sb.length() > 512) {
                    list.add(sb.toString());
                    sb.setLength(0);
                }
            } else {
                if (sb.length() >= 4) {
                    list.add(sb.toString());
                }
                sb.setLength(0);
            }
        }
        if (sb.length() >= 4) {
            list.add(sb.toString());
        }
        return list;
    }
}

