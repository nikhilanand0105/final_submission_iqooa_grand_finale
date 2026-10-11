package dev.guardianai.shield.apk;

import java.util.Collections;
import java.util.List;

/** Signing schemes present and certificates extracted. Signatures themselves are not verified. */
public final class SigningInfo {

    public static final class Cert {
        public final String subject;
        public final String issuer;
        public final String sha256;
        public final long notBefore;
        public final long notAfter;
        public final boolean selfSigned;
        public final boolean androidDebug;
        public final boolean expired;
        public final String algorithm;

        Cert(String subject, String issuer, String sha256, long notBefore, long notAfter, boolean selfSigned,
             boolean androidDebug, boolean expired, String algorithm) {
            this.subject = subject;
            this.issuer = issuer;
            this.sha256 = sha256;
            this.notBefore = notBefore;
            this.notAfter = notAfter;
            this.selfSigned = selfSigned;
            this.androidDebug = androidDebug;
            this.expired = expired;
            this.algorithm = algorithm;
        }
    }

    public final boolean v1, v2, v3;
    public final List<Cert> certificates;
    public final List<String> errors;

    SigningInfo(boolean v1, boolean v2, boolean v3, List<Cert> certificates, List<String> errors) {
        this.v1 = v1;
        this.v2 = v2;
        this.v3 = v3;
        this.certificates = Collections.unmodifiableList(certificates);
        this.errors = Collections.unmodifiableList(errors);
    }

    public boolean isSigned() {
        return (v1 || v2 || v3) && !certificates.isEmpty();
    }

    public String schemes() {
        StringBuilder b = new StringBuilder();
        if (v1) b.append("v1 ");
        if (v2) b.append("v2 ");
        if (v3) b.append("v3 ");
        return b.length() == 0 ? "none" : b.toString().trim();
    }
}
