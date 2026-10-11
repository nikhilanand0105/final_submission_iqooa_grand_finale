package dev.saathi.parser;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Reads an APK archive without extracting it to disk, streaming its key components
 * (manifest, DEX files, signature blocks, and hidden asset payloads).
 */
public class ApkPackageReader {

    public static class ExtractedApkData {
        public byte[] manifestBytes;
        public List<byte[]> dexFilesBytes = new ArrayList<>();
        public Map<String, byte[]> metaInfEntries = new HashMap<>();
        public List<String> embeddedHiddenPayloads = new ArrayList<>();
        public String sha256Checksum;
        public long totalSizeBytes;
    }

    public static ExtractedApkData read(File apkFile) throws Exception {
        try (FileInputStream fis = new FileInputStream(apkFile)) {
            return read(fis, apkFile.length());
        }
    }

    public static ExtractedApkData read(InputStream inputStream, long totalSizeBytes) throws Exception {
        ExtractedApkData data = new ExtractedApkData();
        data.totalSizeBytes = totalSizeBytes;

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        int read;

        MessageDigest md = MessageDigest.getInstance("SHA-256");

        // Read all bytes to compute full checksum and enable zip streaming
        while ((read = inputStream.read(chunk)) != -1) {
            md.update(chunk, 0, read);
            buffer.write(chunk, 0, read);
        }

        byte[] allBytes = buffer.toByteArray();
        data.sha256Checksum = bytesToHex(md.digest());
        if (data.totalSizeBytes <= 0) {
            data.totalSizeBytes = allBytes.length;
        }

        try (ZipInputStream zis = new ZipInputStream(new java.io.ByteArrayInputStream(allBytes))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String name = entry.getName();

                if ("AndroidManifest.xml".equals(name)) {
                    data.manifestBytes = readEntryBytes(zis);
                } else if (name.startsWith("classes") && name.endsWith(".dex")) {
                    data.dexFilesBytes.add(readEntryBytes(zis));
                } else if (name.startsWith("META-INF/")) {
                    data.metaInfEntries.put(name, readEntryBytes(zis));
                } else if (name.startsWith("assets/") || name.startsWith("res/raw/")) {
                    String lower = name.toLowerCase();
                    if (lower.endsWith(".apk") || lower.endsWith(".dex") || lower.endsWith(".jar") || lower.endsWith(".so")) {
                        data.embeddedHiddenPayloads.add(name);
                    }
                }
                zis.closeEntry();
            }
        }

        return data;
    }

    private static byte[] readEntryBytes(ZipInputStream zis) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int len;
        while ((len = zis.read(buf)) != -1) {
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
