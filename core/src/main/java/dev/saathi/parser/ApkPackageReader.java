package dev.saathi.parser;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

/**
 * Reads an APK archive without loading the entire file into heap memory.
 * Features zip bomb protection, bounded entry decompression, and full ZIP inventory enumeration.
 */
public class ApkPackageReader {

    public static final long MAX_APK_SIZE = 150 * 1024 * 1024L; // 150 MB safety limit
    public static final int MAX_ZIP_ENTRIES = 10000;
    public static final long MAX_TOTAL_UNCOMPRESSED = 250 * 1024 * 1024L; // 250 MB
    public static final long MAX_DEX_ENTRY_SIZE = 35 * 1024 * 1024L; // 35 MB per DEX
    public static final long MAX_MANIFEST_SIZE = 10 * 1024 * 1024L; // 10 MB
    public static final long MAX_META_INF_SIZE = 2 * 1024 * 1024L; // 2 MB

    public static class ExtractedApkData {
        public byte[] manifestBytes;
        public List<byte[]> dexFilesBytes = new ArrayList<>();
        public Map<String, byte[]> metaInfEntries = new HashMap<>();
        public List<String> embeddedHiddenPayloads = new ArrayList<>();
        public String sha256Checksum = "";
        public long totalSizeBytes = 0;

        // Structured ZIP inventory & anomalies
        public int totalZipEntries = 0;
        public long totalUncompressedBytes = 0;
        public List<String> zipEntryInventory = new ArrayList<>();
        public List<String> dexEntryNames = new ArrayList<>();
        public List<String> nativeLibraries = new ArrayList<>();
        public List<String> structuralAnomalies = new ArrayList<>();
    }

    public static ExtractedApkData read(File apkFile) throws Exception {
        if (apkFile == null || !apkFile.exists() || !apkFile.canRead()) {
            throw new IllegalArgumentException("APK file is null, missing, or unreadable.");
        }
        if (apkFile.length() > MAX_APK_SIZE) {
            throw new IllegalArgumentException("APK file size (" + (apkFile.length() / (1024 * 1024)) + " MB) exceeds 150 MB safety threshold.");
        }

        ExtractedApkData data = new ExtractedApkData();
        data.totalSizeBytes = apkFile.length();

        // 1. Streaming SHA-256 computation (minimal memory overhead)
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (FileInputStream fis = new FileInputStream(apkFile)) {
            byte[] chunk = new byte[16384];
            int read;
            while ((read = fis.read(chunk)) != -1) {
                md.update(chunk, 0, read);
            }
        }
        data.sha256Checksum = bytesToHex(md.digest());

        // 2. Random-access ZipFile parsing directly on disk
        try (ZipFile zipFile = new ZipFile(apkFile)) {
            int entryCount = zipFile.size();
            data.totalZipEntries = entryCount;
            if (entryCount > MAX_ZIP_ENTRIES) {
                data.structuralAnomalies.add("Archive contains excessive entries: " + entryCount + " (threshold: " + MAX_ZIP_ENTRIES + ")");
            }

            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            long accumulatedUncompressed = 0;
            int dexExtractedCount = 0;

            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();

                if (data.zipEntryInventory.size() < 120) {
                    data.zipEntryInventory.add(name);
                }

                if (name.contains("../") || name.contains("..\\")) {
                    data.structuralAnomalies.add("Path traversal sequence in entry: " + name);
                }

                long entrySize = entry.getSize();
                long compressedSize = entry.getCompressedSize();

                if (entrySize > 0) {
                    accumulatedUncompressed += entrySize;
                    if (entrySize > 1024 * 1024 && compressedSize > 0) {
                        long ratio = entrySize / compressedSize;
                        if (ratio > 100) {
                            data.structuralAnomalies.add("Decompression bomb indicator: " + name + " (ratio: " + ratio + ":1)");
                        }
                    }
                }

                if (accumulatedUncompressed > MAX_TOTAL_UNCOMPRESSED) {
                    data.structuralAnomalies.add("Total uncompressed size exceeds 250 MB safety threshold.");
                    break;
                }

                if ("AndroidManifest.xml".equals(name)) {
                    if (entrySize <= MAX_MANIFEST_SIZE) {
                        try (InputStream is = zipFile.getInputStream(entry)) {
                            data.manifestBytes = readStreamBounded(is, MAX_MANIFEST_SIZE);
                        }
                    } else {
                        data.structuralAnomalies.add("AndroidManifest.xml exceeds 10 MB limit.");
                    }
                } else if (name.startsWith("classes") && name.endsWith(".dex")) {
                    data.dexEntryNames.add(name);
                    if (dexExtractedCount < 10 && (entrySize <= 0 || entrySize <= MAX_DEX_ENTRY_SIZE)) {
                        try (InputStream is = zipFile.getInputStream(entry)) {
                            byte[] dexBytes = readStreamBounded(is, MAX_DEX_ENTRY_SIZE);
                            if (dexBytes != null) {
                                data.dexFilesBytes.add(dexBytes);
                                dexExtractedCount++;
                            }
                        }
                    }
                } else if (name.startsWith("META-INF/")) {
                    String upper = name.toUpperCase(Locale.ROOT);
                    if (upper.endsWith(".RSA") || upper.endsWith(".DSA") || upper.endsWith(".EC") ||
                        upper.endsWith(".SF") || upper.equals("META-INF/MANIFEST.MF")) {
                        try (InputStream is = zipFile.getInputStream(entry)) {
                            byte[] metaBytes = readStreamBounded(is, MAX_META_INF_SIZE);
                            if (metaBytes != null) {
                                data.metaInfEntries.put(name, metaBytes);
                            }
                        }
                    }
                } else if (name.startsWith("lib/") && name.endsWith(".so")) {
                    data.nativeLibraries.add(name);
                } else if (name.startsWith("assets/") || name.startsWith("res/raw/")) {
                    String lower = name.toLowerCase(Locale.ROOT);
                    if (lower.endsWith(".apk") || lower.endsWith(".dex") || lower.endsWith(".jar") || lower.endsWith(".so")) {
                        data.embeddedHiddenPayloads.add(name);
                    }
                }
            }

            data.totalUncompressedBytes = accumulatedUncompressed;
        }

        return data;
    }

    public static ExtractedApkData read(InputStream inputStream, long totalSizeBytes) throws Exception {
        if (totalSizeBytes > MAX_APK_SIZE) {
            throw new IllegalArgumentException("APK size (" + (totalSizeBytes / (1024 * 1024)) + " MB) exceeds 150 MB safety threshold.");
        }

        ExtractedApkData data = new ExtractedApkData();
        data.totalSizeBytes = totalSizeBytes;

        DigestInputStream dis = new DigestInputStream(inputStream, MessageDigest.getInstance("SHA-256"));
        long accumulatedUncompressed = 0;
        int dexExtractedCount = 0;
        int entryCount = 0;

        try (ZipInputStream zis = new ZipInputStream(dis)) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                entryCount++;
                if (entryCount > MAX_ZIP_ENTRIES) {
                    data.structuralAnomalies.add("Archive contains excessive entries: >" + MAX_ZIP_ENTRIES);
                    zis.closeEntry();
                    break;
                }

                String name = entry.getName();
                if (data.zipEntryInventory.size() < 120) {
                    data.zipEntryInventory.add(name);
                }

                if (name.contains("../") || name.contains("..\\")) {
                    data.structuralAnomalies.add("Path traversal sequence in entry: " + name);
                }

                if ("AndroidManifest.xml".equals(name)) {
                    data.manifestBytes = readStreamBounded(zis, MAX_MANIFEST_SIZE);
                } else if (name.startsWith("classes") && name.endsWith(".dex")) {
                    data.dexEntryNames.add(name);
                    if (dexExtractedCount < 10) {
                        byte[] dexBytes = readStreamBounded(zis, MAX_DEX_ENTRY_SIZE);
                        if (dexBytes != null) {
                            data.dexFilesBytes.add(dexBytes);
                            dexExtractedCount++;
                        }
                    }
                } else if (name.startsWith("META-INF/")) {
                    String upper = name.toUpperCase(Locale.ROOT);
                    if (upper.endsWith(".RSA") || upper.endsWith(".DSA") || upper.endsWith(".EC") ||
                        upper.endsWith(".SF") || upper.equals("META-INF/MANIFEST.MF")) {
                        byte[] metaBytes = readStreamBounded(zis, MAX_META_INF_SIZE);
                        if (metaBytes != null) {
                            data.metaInfEntries.put(name, metaBytes);
                        }
                    }
                } else if (name.startsWith("lib/") && name.endsWith(".so")) {
                    data.nativeLibraries.add(name);
                } else if (name.startsWith("assets/") || name.startsWith("res/raw/")) {
                    String lower = name.toLowerCase(Locale.ROOT);
                    if (lower.endsWith(".apk") || lower.endsWith(".dex") || lower.endsWith(".jar") || lower.endsWith(".so")) {
                        data.embeddedHiddenPayloads.add(name);
                    }
                }
                zis.closeEntry();
            }
        }

        data.totalZipEntries = entryCount;
        data.sha256Checksum = bytesToHex(dis.getMessageDigest().digest());
        return data;
    }

    private static byte[] readStreamBounded(InputStream is, long maxBytes) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int len;
        long total = 0;
        while ((len = is.read(buf)) != -1) {
            total += len;
            if (total > maxBytes) {
                return null;
            }
            baos.write(buf, 0, len);
        }
        return baos.toByteArray();
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
