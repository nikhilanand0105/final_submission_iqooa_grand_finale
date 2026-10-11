package dev.saathi.parser;

import dev.saathi.model.CertificateMetadata;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Map;

/**
 * Parses and verifies digital certificates from APK META-INF signatures.
 * Flags debug keys, test keys, self-signed oddities, and certificate expiration.
 */
public class SignatureInspector {

    private static final byte[] APK_SIG_BLOCK_MAGIC = new byte[]{
            0x41, 0x50, 0x4B, 0x20, 0x53, 0x69, 0x67, 0x20,
            0x42, 0x6C, 0x6F, 0x63, 0x6B, 0x20, 0x34, 0x32 // "APK Sig Block 42"
    };

    public static CertificateMetadata inspect(Map<String, byte[]> metaInfEntries) {
        return inspect(metaInfEntries, null);
    }

    public static CertificateMetadata inspect(Map<String, byte[]> metaInfEntries, java.io.File apkFile) {
        // 1. Check v1 signature block files: .RSA, .DSA, .EC
        if (metaInfEntries != null && !metaInfEntries.isEmpty()) {
            for (Map.Entry<String, byte[]> entry : metaInfEntries.entrySet()) {
                String name = entry.getKey().toUpperCase(java.util.Locale.ROOT);
                if (name.endsWith(".RSA") || name.endsWith(".DSA") || name.endsWith(".EC")) {
                    try {
                        CertificateFactory cf = CertificateFactory.getInstance("X.509");
                        ByteArrayInputStream bais = new ByteArrayInputStream(entry.getValue());
                        for (java.security.cert.Certificate cert : cf.generateCertificates(bais)) {
                            if (cert instanceof X509Certificate) {
                                return extractMetadata((X509Certificate) cert);
                            }
                        }
                    } catch (Exception ignored) {
                    }
                }
            }
        }

        // 2. Check APK Signature Scheme v2/v3 block from APK file directly
        if (apkFile != null && apkFile.exists() && apkFile.length() > 64) {
            CertificateMetadata v2v3 = parseApkSigningBlock(apkFile);
            if (v2v3 != null) {
                return v2v3;
            }
        }

        return new CertificateMetadata(
                "Unsigned or Custom Signed",
                "Unsigned",
                "0",
                "NO_FINGERPRINT",
                new Date(),
                new Date(System.currentTimeMillis() + 86400000L),
                true,
                false,
                false
        );
    }

    private static CertificateMetadata parseApkSigningBlock(java.io.File apkFile) {
        try (java.io.RandomAccessFile raf = new java.io.RandomAccessFile(apkFile, "r")) {
            long fileLength = raf.length();
            if (fileLength < 1024) return null;

            int searchLength = (int) Math.min(fileLength, 65536);
            byte[] tail = new byte[searchLength];
            raf.seek(fileLength - searchLength);
            raf.readFully(tail);

            int eocdOffsetInTail = -1;
            for (int i = searchLength - 22; i >= 0; i--) {
                if (tail[i] == 0x50 && tail[i + 1] == 0x4B && tail[i + 2] == 0x05 && tail[i + 3] == 0x06) {
                    eocdOffsetInTail = i;
                    break;
                }
            }

            if (eocdOffsetInTail == -1) return null;

            java.nio.ByteBuffer eocdBuffer = java.nio.ByteBuffer.wrap(tail).order(java.nio.ByteOrder.LITTLE_ENDIAN);
            long centralDirOffset = eocdBuffer.getInt(eocdOffsetInTail + 16) & 0xFFFFFFFFL;

            if (centralDirOffset < 32 || centralDirOffset > fileLength) return null;

            raf.seek(centralDirOffset - 16);
            byte[] magic = new byte[16];
            raf.readFully(magic);
            if (!java.util.Arrays.equals(magic, APK_SIG_BLOCK_MAGIC)) {
                return null;
            }

            raf.seek(centralDirOffset - 24);
            byte[] sizeBytes = new byte[8];
            raf.readFully(sizeBytes);
            long blockSize = java.nio.ByteBuffer.wrap(sizeBytes).order(java.nio.ByteOrder.LITTLE_ENDIAN).getLong();

            long blockStart = centralDirOffset - blockSize - 8;
            if (blockStart < 0 || blockStart >= centralDirOffset) return null;

            raf.seek(blockStart + 8);
            long remaining = blockSize - 24;
            while (remaining > 12) {
                byte[] pairHdr = new byte[12];
                raf.readFully(pairHdr);
                java.nio.ByteBuffer pairBuf = java.nio.ByteBuffer.wrap(pairHdr).order(java.nio.ByteOrder.LITTLE_ENDIAN);
                long pairSize = pairBuf.getLong();
                int id = pairBuf.getInt();
                remaining -= 12;

                int valueLen = (int) (pairSize - 4);
                if (valueLen <= 0 || valueLen > remaining) break;

                if (id == 0x7109871A || id == 0xF05368C0) {
                    byte[] valueBytes = new byte[valueLen];
                    raf.readFully(valueBytes);
                    java.nio.ByteBuffer vb = java.nio.ByteBuffer.wrap(valueBytes).order(java.nio.ByteOrder.LITTLE_ENDIAN);

                    int signersSeqLen = vb.getInt();
                    int signerLen = vb.getInt();
                    int signedDataLen = vb.getInt();

                    int digestsLen = vb.getInt();
                    vb.position(vb.position() + digestsLen);

                    int certsLen = vb.getInt();
                    int certLen = vb.getInt();
                    byte[] certBytes = new byte[certLen];
                    vb.get(certBytes);

                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    X509Certificate x509 = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
                    return extractMetadata(x509);
                } else {
                    raf.skipBytes(valueLen);
                    remaining -= valueLen;
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    public static CertificateMetadata extractMetadata(X509Certificate x509) {
        String subject = x509.getSubjectX500Principal().getName();
        String issuer = x509.getIssuerX500Principal().getName();
        String serialNumber = x509.getSerialNumber().toString(16);
        Date notBefore = x509.getNotBefore();
        Date notAfter = x509.getNotAfter();

        boolean isSelfSigned = subject.equals(issuer);
        boolean isExpired = new Date().after(notAfter) || new Date().before(notBefore);

        String lowerSubject = subject.toLowerCase();
        boolean isDebugCertificate = lowerSubject.contains("android debug") ||
                lowerSubject.contains("testkey") ||
                lowerSubject.contains("android") && lowerSubject.contains("debug");

        String sha256Fingerprint = computeSha256(x509);

        return new CertificateMetadata(
                subject,
                issuer,
                serialNumber,
                sha256Fingerprint,
                notBefore,
                notAfter,
                isSelfSigned,
                isDebugCertificate,
                isExpired
        );
    }

    private static String computeSha256(X509Certificate cert) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(cert.getEncoded());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02X:", b));
            }
            if (sb.length() > 0) sb.setLength(sb.length() - 1);
            return sb.toString();
        } catch (Exception e) {
            return "UNKNOWN_HASH";
        }
    }
}
