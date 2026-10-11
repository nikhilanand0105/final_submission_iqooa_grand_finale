package dev.saathi.model;

import java.util.Date;

/**
 * X.509 certificate and signing scheme information.
 */
public class CertificateMetadata {
    private final String subject;
    private final String issuer;
    private final String serialNumber;
    private final String sha256Fingerprint;
    private final Date notBefore;
    private final Date notAfter;
    private final boolean isSelfSigned;
    private final boolean isDebugCertificate;
    private final boolean isExpired;

    public CertificateMetadata(
            String subject,
            String issuer,
            String serialNumber,
            String sha256Fingerprint,
            Date notBefore,
            Date notAfter,
            boolean isSelfSigned,
            boolean isDebugCertificate,
            boolean isExpired) {
        this.subject = subject;
        this.issuer = issuer;
        this.serialNumber = serialNumber;
        this.sha256Fingerprint = sha256Fingerprint;
        this.notBefore = notBefore;
        this.notAfter = notAfter;
        this.isSelfSigned = isSelfSigned;
        this.isDebugCertificate = isDebugCertificate;
        this.isExpired = isExpired;
    }

    public String getSubject() {
        return subject;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public String getSha256Fingerprint() {
        return sha256Fingerprint;
    }

    public Date getNotBefore() {
        return notBefore;
    }

    public Date getNotAfter() {
        return notAfter;
    }

    public boolean isSelfSigned() {
        return isSelfSigned;
    }

    public boolean isDebugCertificate() {
        return isDebugCertificate;
    }

    public boolean isExpired() {
        return isExpired;
    }
}
