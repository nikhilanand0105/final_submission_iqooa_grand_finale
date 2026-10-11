package dev.guardianai.shield.apk;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Extracts signing certificates from an APK without verifying signatures.
 * - v1 (JAR) signatures: PKCS#7 blocks in META-INF/*.RSA|DSA|EC, parsed with the platform CertificateFactory.
 * - v2/v3 signatures: the "APK Signing Block" located before the ZIP central directory, parsed per the
 *   documented length-prefixed layout.
 * Signature verification is NOT performed here; Android verifies signatures itself at install time.
 */
public final class ApkSigningInspector {

    private static final long SIG_BLOCK_MAGIC_LO = 0x20676953204b5041L; // "APK Sig "
    private static final long SIG_BLOCK_MAGIC_HI = 0x3234206b636f6c42L; // "Block 42"
    private static final int ID_V2 = 0x7109871a;
    private static final int ID_V3 = 0xf05368c0;
    private static final int ID_V31 = 0x1b93ad61;
    private static final int MAX_BLOCK = 16 * 1024 * 1024;

    private ApkSigningInspector() {}

    /** Parses certificates from v1 signature block files (name -> bytes). */
    static List<SigningInfo.Cert> v1Certs(Map<String, byte[]> blocks, List<String> errors) {
        Map<String, SigningInfo.Cert> out = new LinkedHashMap<>();
        for (Map.Entry<String, byte[]> e : blocks.entrySet()) {
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                Collection<? extends Certificate> cs = cf.generateCertificates(new ByteArrayInputStream(e.getValue()));
                for (Certificate c : cs) {
                    if (c instanceof X509Certificate) {
                        SigningInfo.Cert ci = describe((X509Certificate) c);
                        out.put(ci.sha256, ci);
                    }
                }
            } catch (Exception ex) {
                errors.add("Could not read v1 signature block " + e.getKey());
            }
        }
        return new ArrayList<>(out.values());
    }

    /** Result of scanning for the APK Signing Block. */
    static final class BlockResult {
        boolean v2, v3;
        final List<SigningInfo.Cert> certs = new ArrayList<>();
    }

    static BlockResult signingBlock(RandomAccessFile f, List<String> errors) {
        BlockResult r = new BlockResult();
        try {
            long len = f.length();
            long eocd = findEocd(f, len);
            if (eocd < 0) { errors.add("ZIP end record not found while looking for v2/v3 signatures"); return r; }
            byte[] e = new byte[22];
            f.seek(eocd);
            f.readFully(e);
            long cdOffset = ByteBuffer.wrap(e).order(ByteOrder.LITTLE_ENDIAN).getInt(16) & 0xFFFFFFFFL;
            if (cdOffset < 32 || cdOffset > eocd) return r;
            byte[] footer = new byte[24];
            f.seek(cdOffset - 24);
            f.readFully(footer);
            ByteBuffer fb = ByteBuffer.wrap(footer).order(ByteOrder.LITTLE_ENDIAN);
            if (fb.getLong(8) != SIG_BLOCK_MAGIC_LO || fb.getLong(16) != SIG_BLOCK_MAGIC_HI) return r; // no v2+ block
            long size = fb.getLong(0);
            if (size < 24 || size > MAX_BLOCK || size + 8 > cdOffset) { errors.add("APK Signing Block has an invalid size"); return r; }
            byte[] block = new byte[(int) size - 24];
            f.seek(cdOffset - size - 8 + 8);
            f.readFully(block);
            ByteBuffer bb = ByteBuffer.wrap(block).order(ByteOrder.LITTLE_ENDIAN);
            while (bb.remaining() >= 12) {
                long pairLen = bb.getLong();
                if (pairLen < 4 || pairLen > bb.remaining()) { errors.add("APK Signing Block entry is malformed"); break; }
                int id = bb.getInt();
                int vlen = (int) pairLen - 4;
                ByteBuffer v = slice(bb, vlen);
                if (id == ID_V2 || id == ID_V3 || id == ID_V31) {
                    if (id == ID_V2) r.v2 = true; else r.v3 = true;
                    try {
                        readSigners(v, r.certs);
                    } catch (RuntimeException ex) {
                        errors.add("Could not read " + (id == ID_V2 ? "v2" : "v3") + " signer data");
                    }
                }
            }
        } catch (IOException | RuntimeException ex) {
            errors.add("Could not read the APK Signing Block");
        }
        return r;
    }

    private static void readSigners(ByteBuffer v, List<SigningInfo.Cert> out) {
        ByteBuffer signers = lp(v);
        while (signers.hasRemaining()) {
            ByteBuffer signer = lp(signers);
            ByteBuffer signedData = lp(signer);
            lp(signedData); // digests
            ByteBuffer certs = lp(signedData);
            while (certs.hasRemaining()) {
                ByteBuffer der = lp(certs);
                byte[] bytes = new byte[der.remaining()];
                der.get(bytes);
                try {
                    X509Certificate c = (X509Certificate) CertificateFactory.getInstance("X.509")
                            .generateCertificate(new ByteArrayInputStream(bytes));
                    SigningInfo.Cert ci = describe(c);
                    boolean dup = false;
                    for (SigningInfo.Cert x : out) if (x.sha256.equals(ci.sha256)) dup = true;
                    if (!dup) out.add(ci);
                } catch (Exception ignored) {
                    // unreadable certificate: counted by caller via missing certs
                }
            }
        }
    }

    private static ByteBuffer lp(ByteBuffer b) {
        if (b.remaining() < 4) throw new IllegalArgumentException("truncated");
        int n = b.getInt();
        if (n < 0 || n > b.remaining()) throw new IllegalArgumentException("bad length");
        return slice(b, n);
    }

    private static ByteBuffer slice(ByteBuffer b, int n) {
        ByteBuffer s = b.slice();
        s.limit(n);
        s.order(ByteOrder.LITTLE_ENDIAN);
        b.position(b.position() + n);
        return s;
    }

    private static long findEocd(RandomAccessFile f, long len) throws IOException {
        int max = (int) Math.min(len, 22 + 65535);
        if (max < 22) return -1;
        byte[] tail = new byte[max];
        f.seek(len - max);
        f.readFully(tail);
        for (int p = max - 22; p >= 0; p--) {
            if (tail[p] == 0x50 && tail[p + 1] == 0x4b && tail[p + 2] == 0x05 && tail[p + 3] == 0x06) {
                int commentLen = (tail[p + 20] & 0xFF) | ((tail[p + 21] & 0xFF) << 8);
                if (p + 22 + commentLen == max) return len - max + p;
            }
        }
        return -1;
    }

    static SigningInfo.Cert describe(X509Certificate c) throws Exception {
        byte[] d = MessageDigest.getInstance("SHA-256").digest(c.getEncoded());
        StringBuilder hex = new StringBuilder();
        for (int k = 0; k < d.length; k++) {
            if (k > 0) hex.append(':');
            hex.append(String.format("%02X", d[k]));
        }
        String subject = c.getSubjectX500Principal().getName();
        String issuer = c.getIssuerX500Principal().getName();
        Date now = new Date();
        return new SigningInfo.Cert(subject, issuer, hex.toString(), c.getNotBefore().getTime(), c.getNotAfter().getTime(),
                subject.equals(issuer), subject.contains("CN=Android Debug"), now.after(c.getNotAfter()),
                c.getSigAlgName());
    }
}
