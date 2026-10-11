package dev.saathi.rules;

import dev.saathi.model.CertificateMetadata;
import dev.saathi.model.DexInspectionResult;
import dev.saathi.model.ManifestMetadata;
import dev.saathi.model.ThreatIndicator;
import dev.saathi.model.ThreatSeverity;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Detects dangerous, unauthorized WhatsApp MODs and counterfeit forks (GBWhatsApp, WhatsApp Plus,
 * YoWhatsApp, FMWhatsApp, WhatsApp Gold, Aero WhatsApp, etc.).
 *
 * WhatsApp strictly prohibits unauthorized third-party modifications under its Terms of Service.
 * These modified clones break end-to-end encryption integrity, inject backdoor hooks to intercept
 * messages and OTPs, leak credentials and media to untrusted servers, and trigger permanent WhatsApp account bans.
 */
public class WhatsAppModRule implements SecurityRule {

    private static final List<String> KNOWN_MOD_PACKAGES = Arrays.asList(
            "com.gbwhatsapp",
            "com.whatsapp.plus",
            "com.yowhatsapp",
            "com.fmwhatsapp",
            "com.whatsapp.gold",
            "com.aero.whatsapp",
            "com.aerowhatsapp",
            "com.ogwhatsapp",
            "com.obwhatsapp",
            "com.soula2",
            "com.nswhatsapp",
            "com.nsнеwhatsapp",
            "com.mbwhatsapp",
            "com.whatsapp4b",
            "com.whatsapp.mod",
            "com.whatsapp.update",
            "com.whatsapp.clone",
            "com.fouadwhatsapp",
            "com.heywhatsapp"
    );

    private static final List<String> KNOWN_MOD_KEYWORDS = Arrays.asList(
            "gbwhatsapp",
            "whatsappplus",
            "yowhatsapp",
            "fmwhatsapp",
            "whatsappgold",
            "aerowhatsapp",
            "ogwhatsapp",
            "obwhatsapp",
            "soula2",
            "nswhatsapp",
            "mbwhatsapp",
            "fouadwhatsapp"
    );

    @Override
    public String getRuleId() {
        return "RULE_WHATSAPP_MOD_DETECTION";
    }

    @Override
    public String getRuleName() {
        return "Unauthorized WhatsApp MOD & Counterfeit Clone Detection";
    }

    @Override
    public List<ThreatIndicator> evaluate(
            ManifestMetadata manifest,
            DexInspectionResult dex,
            CertificateMetadata certificate,
            List<String> hiddenPayloads) {
        return evaluate(manifest, dex, certificate, hiddenPayloads, null);
    }

    public List<ThreatIndicator> evaluate(
            ManifestMetadata manifest,
            DexInspectionResult dex,
            CertificateMetadata certificate,
            List<String> hiddenPayloads,
            String fileName) {

        List<ThreatIndicator> indicators = new ArrayList<>();
        String pkg = manifest != null && manifest.getPackageName() != null ? manifest.getPackageName().toLowerCase(Locale.ROOT) : "";
        String cleanPkg = pkg.replace("_", "").replace("-", "");

        boolean isModPackage = false;
        String detectedModName = "WhatsApp MOD";

        for (String knownMod : KNOWN_MOD_PACKAGES) {
            if (pkg.equals(knownMod) || pkg.startsWith(knownMod + ".")) {
                isModPackage = true;
                detectedModName = extractModDisplayName(knownMod);
                break;
            }
        }

        if (!isModPackage) {
            for (String kw : KNOWN_MOD_KEYWORDS) {
                if (cleanPkg.contains(kw)) {
                    isModPackage = true;
                    detectedModName = extractModDisplayName(kw);
                    break;
                }
            }
        }

        if (!isModPackage && cleanPkg.contains("whatsapp")) {
            if (cleanPkg.contains("mod") || cleanPkg.contains("plus") || cleanPkg.contains("gb") ||
                    cleanPkg.contains("gold") || cleanPkg.contains("yo") || cleanPkg.contains("fm") ||
                    cleanPkg.contains("pink") || cleanPkg.contains("blue") || cleanPkg.contains("red") ||
                    cleanPkg.contains("clone") || cleanPkg.contains("update") || cleanPkg.contains("dual") ||
                    cleanPkg.contains("pro") || cleanPkg.contains("aero") || cleanPkg.contains("og") ||
                    cleanPkg.contains("ob") || cleanPkg.contains("mb")) {
                isModPackage = true;
                detectedModName = "Modified WhatsApp Variant (" + pkg + ")";
            }
        }

        // Check if claims to be official com.whatsapp or com.whatsapp.w4b but signed with untrusted / debug / self-signed certificate
        boolean claimsOfficialWhatsApp = pkg.equals("com.whatsapp") || pkg.equals("com.whatsapp.w4b");
        boolean isOfficialSigner = isOfficialWhatsAppCertificate(certificate);
        boolean isCounterfeitOfficial = claimsOfficialWhatsApp && !isOfficialSigner;

        // Check DEX bytecode artifacts
        boolean hasModDexArtifacts = false;
        String detectedDexArtifact = null;
        if (dex != null) {
            for (String api : dex.getSuspiciousApiReferences()) {
                if (api.startsWith("WhatsAppModIdentifier: ")) {
                    hasModDexArtifacts = true;
                    detectedDexArtifact = api.substring("WhatsAppModIdentifier: ".length());
                    break;
                }
            }
        }

        // Check file name if provided
        boolean isModFileName = false;
        if (fileName != null) {
            String lowerFile = fileName.toLowerCase(Locale.ROOT).replace("_", "").replace("-", "").replace(" ", "");
            if (lowerFile.contains("whatsapp") && (lowerFile.contains("mod") || lowerFile.contains("gb") ||
                    lowerFile.contains("plus") || lowerFile.contains("gold") || lowerFile.contains("yo") ||
                    lowerFile.contains("fm") || lowerFile.contains("pink") || lowerFile.contains("blue") ||
                    lowerFile.contains("aero") || lowerFile.contains("og"))) {
                isModFileName = true;
            }
        }

        if (isModPackage || isCounterfeitOfficial || hasModDexArtifacts || isModFileName) {
            String detail;
            if (isCounterfeitOfficial) {
                detail = "This APK claims to be the official WhatsApp package ('" + pkg + "'), but its digital signing certificate does not match Meta's official WhatsApp production key. This is a repacked, backdoored trojan WhatsApp version.";
            } else if (isModPackage) {
                detail = "Detected unauthorized modified WhatsApp package (" + detectedModName + ", package: '" + pkg + "'). Unofficial WhatsApp mods bypass official security safeguards, break end-to-end encryption assurance, and lead to immediate WhatsApp account bans.";
            } else if (hasModDexArtifacts) {
                detail = "Bytecode inspection discovered WhatsApp MOD hooks and unofficial framework signatures (" + detectedDexArtifact + ").";
            } else {
                detail = "The package name and binary archive identify this APK as an unauthorized WhatsApp modification (" + fileName + ").";
            }

            indicators.add(new ThreatIndicator(
                    "WHATSAPP_MOD_UNAUTHORIZED_FORK",
                    "Dangerous WhatsApp MOD / Unofficial Clone Detected (" + detectedModName + ")",
                    detail + " Installing this modified app puts your phone, banking OTPs, private chats, and media at critical risk of interception and account suspension.",
                    ThreatSeverity.CRITICAL,
                    "MALICIOUS_APP_MOD",
                    "WhatsApp Security Standard",
                    "WhatsApp prohibits third-party clients under its Terms of Service. Modified WhatsApp APKs are widely documented to contain remote surveillance, contact harvesting, and spyware backdoors.",
                    true
            ));
        }

        return indicators;
    }

    private String extractModDisplayName(String identifier) {
        if (identifier.contains("gb")) return "GBWhatsApp";
        if (identifier.contains("plus")) return "WhatsApp Plus";
        if (identifier.contains("gold")) return "WhatsApp Gold";
        if (identifier.contains("yo")) return "YoWhatsApp";
        if (identifier.contains("fm")) return "FMWhatsApp";
        if (identifier.contains("aero")) return "WhatsApp Aero";
        if (identifier.contains("og")) return "OGWhatsApp";
        if (identifier.contains("ob")) return "OBWhatsApp";
        return "WhatsApp MOD";
    }

    public static boolean isOfficialWhatsApp(ManifestMetadata manifest, CertificateMetadata certificate) {
        if (manifest == null) return false;
        String pkg = manifest.getPackageName() != null ? manifest.getPackageName().toLowerCase(Locale.ROOT) : "";
        if (!"com.whatsapp".equals(pkg) && !"com.whatsapp.w4b".equals(pkg)) {
            return false;
        }
        return isOfficialWhatsAppCertificate(certificate);
    }

    public static boolean isOfficialWhatsAppCertificate(CertificateMetadata cert) {
        if (cert == null) return false;
        if (cert.isDebugCertificate()) return false;
        String issuer = cert.getIssuer() != null ? cert.getIssuer().toLowerCase(Locale.ROOT) : "";
        String subject = cert.getSubject() != null ? cert.getSubject().toLowerCase(Locale.ROOT) : "";
        return issuer.contains("whatsapp") || subject.contains("whatsapp") || issuer.contains("meta") || subject.contains("meta");
    }
}
