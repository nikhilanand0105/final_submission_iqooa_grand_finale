package dev.guardianai.parser;

import dev.guardianai.model.CertificateMetadata;

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

    public static CertificateMetadata inspect(Map<String, byte[]> metaInfEntries) {
        if (metaInfEntries == null || metaInfEntries.isEmpty()) {
            return new CertificateMetadata("Unknown", "Unknown", "N/A", "N/A", null, null, false, false, false);
        }

        // Look for signature block files: .RSA, .DSA, .EC
        for (Map.Entry<String, byte[]> entry : metaInfEntries.entrySet()) {
            String name = entry.getKey().toUpperCase();
            if (name.endsWith(".RSA") || name.endsWith(".DSA") || name.endsWith(".EC")) {
                try {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    ByteArrayInputStream bais = new ByteArrayInputStream(entry.getValue());
                    // Many PKCS7 files can be parsed directly by CertificateFactory or generateCertificates
                    for (java.security.cert.Certificate cert : cf.generateCertificates(bais)) {
                        if (cert instanceof X509Certificate) {
                            X509Certificate x509 = (X509Certificate) cert;
                            return extractMetadata(x509);
                        }
                    }
                } catch (Exception ignored) {
                }
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
