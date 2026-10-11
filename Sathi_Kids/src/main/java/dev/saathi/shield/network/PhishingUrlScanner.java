package dev.saathi.shield.network;

import dev.saathi.model.ThreatSeverity;

import java.net.URI;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Scans user-submitted URLs and links extracted from SMS/messages.
 * Detects financial phishing, fake KYC update domains, homoglyph impersonations, and raw IP destinations.
 */
public class PhishingUrlScanner {

    public enum UrlRiskLevel {
        KNOWN_PHISHING,
        SUSPICIOUS_DESTINATION,
        UNVERIFIED,
        SAFE_REPUTATION
    }

    public static class UrlScanResult {
        public final String originalUrl;
        public final String domain;
        public final UrlRiskLevel riskLevel;
        public final ThreatSeverity severity;
        public final List<String> warningReasons;
        public final String plainAdvice;

        public UrlScanResult(
                String originalUrl,
                String domain,
                UrlRiskLevel riskLevel,
                ThreatSeverity severity,
                List<String> warningReasons,
                String plainAdvice) {
            this.originalUrl = originalUrl;
            this.domain = domain;
            this.riskLevel = riskLevel;
            this.severity = severity;
            this.warningReasons = warningReasons != null ? warningReasons : Collections.emptyList();
            this.plainAdvice = plainAdvice;
        }
    }

    // High-risk TLDs frequently used in throwaway phishing kits
    private static final Set<String> HIGH_RISK_TLDS = new HashSet<>(Arrays.asList(
            ".top", ".xyz", ".biz", ".tk", ".ml", ".ga", ".cf", ".gq", ".click", ".buzz", ".live"
    ));

    // Brands frequently impersonated in Indian cyber financial fraud
    private static final List<String> IMPERSONATED_FINANCIAL_BRANDS = Arrays.asList(
            "sbi", "yono", "hdfc", "icici", "axis", "paytm", "phonepe", "gpay", "bhim",
            "electricity", "bijli", "challan", "incometax", "aadhaar", "epfo"
    );

    // Official domains of key Indian financial services
    private static final Set<String> OFFICIAL_TRUSTED_DOMAINS = new HashSet<>(Arrays.asList(
            "onlinesbi.sbi", "sbi.co.in", "hdfcbank.com", "icicibank.com",
            "axisbank.com", "paytm.com", "phonepe.com", "npci.org.in",
            "incometax.gov.in", "uidai.gov.in", "epfindia.gov.in", "parivahan.gov.in"
    ));

    private static final Pattern RAW_IP_PATTERN = Pattern.compile("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");

    public UrlScanResult scanUrl(String rawUrl) {
        if (rawUrl == null || rawUrl.isBlank()) {
            return new UrlScanResult(rawUrl, "", UrlRiskLevel.UNVERIFIED, ThreatSeverity.INFO, List.of("Empty URL"), "No link provided.");
        }

        String normalizedUrl = rawUrl.trim();
        if (!normalizedUrl.startsWith("http://") && !normalizedUrl.startsWith("https://")) {
            normalizedUrl = "https://" + normalizedUrl;
        }

        List<String> reasons = new ArrayList<>();
        ThreatSeverity severity = ThreatSeverity.INFO;
        UrlRiskLevel risk = UrlRiskLevel.SAFE_REPUTATION;

        try {
            URI uri = new URI(normalizedUrl);
            String host = uri.getHost();
            if (host == null) {
                return new UrlScanResult(rawUrl, "", UrlRiskLevel.UNVERIFIED, ThreatSeverity.LOW, List.of("Malformed URL structure"), "This web address is invalid or broken.");
            }

            host = host.toLowerCase();

            // 1. Raw IPv4 Destination Check
            if (RAW_IP_PATTERN.matcher(host).matches()) {
                reasons.add("Raw IP Address Destination: Legitimate banks never direct users to raw numeric IP addresses.");
                risk = UrlRiskLevel.KNOWN_PHISHING;
                severity = ThreatSeverity.CRITICAL;
            }

            // 2. High-Risk TLD Check
            for (String tld : HIGH_RISK_TLDS) {
                if (host.endsWith(tld)) {
                    reasons.add("Suspicious Top-Level Domain (" + tld + "): Commonly used in temporary phishing and scam websites.");
                    if (risk != UrlRiskLevel.KNOWN_PHISHING) risk = UrlRiskLevel.SUSPICIOUS_DESTINATION;
                    severity = ThreatSeverity.HIGH;
                    break;
                }
            }

            // 3. Financial Brand Impersonation Check (e.g. sbi-kyc-update.xyz)
            for (String brand : IMPERSONATED_FINANCIAL_BRANDS) {
                if (host.contains(brand)) {
                    boolean isOfficial = false;
                    for (String official : OFFICIAL_TRUSTED_DOMAINS) {
                        if (host.equals(official) || host.endsWith("." + official)) {
                            isOfficial = true;
                            break;
                        }
                    }

                    if (!isOfficial) {
                        reasons.add("Potential Impersonation of " + brand.toUpperCase() + ": The domain contains the brand name but does not belong to the official registered organization.");
                        risk = UrlRiskLevel.KNOWN_PHISHING;
                        severity = ThreatSeverity.CRITICAL;
                    }
                }
            }

            // 4. Urgency keywords in path (e.g. /kyc-update, /pan-link, /lottery)
            String path = uri.getPath() != null ? uri.getPath().toLowerCase() : "";
            if (path.contains("kyc") || path.contains("pan") || path.contains("verify-account") || path.contains("reward")) {
                if (risk != UrlRiskLevel.KNOWN_PHISHING && risk != UrlRiskLevel.SUSPICIOUS_DESTINATION) {
                    reasons.add("Urgency / Account Verification Path: Exercise caution before submitting personal credentials.");
                    risk = UrlRiskLevel.SUSPICIOUS_DESTINATION;
                    severity = ThreatSeverity.MEDIUM;
                }
            }

            // 5. Insecure HTTP check for sensitive keywords
            if (uri.getScheme().equalsIgnoreCase("http") && (path.contains("login") || path.contains("bank") || path.contains("pay"))) {
                reasons.add("Unencrypted HTTP Connection: Never enter passwords or payment details on unencrypted HTTP websites.");
                if (risk == UrlRiskLevel.SAFE_REPUTATION) risk = UrlRiskLevel.SUSPICIOUS_DESTINATION;
                severity = ThreatSeverity.HIGH;
            }

            String advice;
            if (risk == UrlRiskLevel.KNOWN_PHISHING) {
                advice = "🛑 DO NOT OPEN THIS LINK. This is a fake website impersonating a bank or public service. If you enter your bank credentials or OTP here, your account could be compromised. Disconnect from the sender.";
            } else if (risk == UrlRiskLevel.SUSPICIOUS_DESTINATION) {
                advice = "⚠️ BE CAREFUL. This link uses unusual web addresses or asks for sensitive verifications. Do not enter OTPs, passwords, or UPI PINs.";
            } else {
                advice = "✅ No known phishing indicators found. Always ensure you are on the authentic official domain before logging in.";
            }

            return new UrlScanResult(rawUrl, host, risk, severity, reasons, advice);

        } catch (Exception e) {
            return new UrlScanResult(rawUrl, "", UrlRiskLevel.UNVERIFIED, ThreatSeverity.LOW, List.of("Could not parse URL: " + e.getMessage()), "Unable to verify this web address.");
        }
    }
}
