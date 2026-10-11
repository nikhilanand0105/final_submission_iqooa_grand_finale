package dev.guardianai.shield.network.url;

import dev.guardianai.model.ScanVerdict;
import dev.guardianai.model.ThreatSeverity;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Local heuristic analysis engine evaluating structural and syntax indicators directly from parsed input.
 * Does not select canned outcomes. Treats all checks as observable heuristics rather than definitive proof.
 */
public class LocalUrlAnalyzer {

    // High-risk TLDs historically associated with disposable abuse and bulk throwaway registrations
    private static final Set<String> HIGH_RISK_TLDS = new HashSet<>(Arrays.asList(
            ".top", ".xyz", ".buzz", ".click", ".live", ".fit", ".rest", ".tk", ".ml", ".ga", ".cf", ".gq", ".work", ".bar"
    ));

    // Common Cyrillic and Greek characters visually identical to Latin characters
    private static final Map<Character, Character> HOMOGLYPH_MAP = Map.ofEntries(
            Map.entry('\u0430', 'a'), // Cyrillic small letter a
            Map.entry('\u0441', 'c'), // Cyrillic small letter es
            Map.entry('\u0435', 'e'), // Cyrillic small letter ie
            Map.entry('\u0456', 'i'), // Cyrillic small letter byelorussian-ukrainian i
            Map.entry('\u0458', 'j'), // Cyrillic small letter je
            Map.entry('\u043E', 'o'), // Cyrillic small letter o
            Map.entry('\u0440', 'p'), // Cyrillic small letter er
            Map.entry('\u0455', 's'), // Cyrillic small letter dze
            Map.entry('\u0443', 'y'), // Cyrillic small letter u
            Map.entry('\u0445', 'x'), // Cyrillic small letter ha
            Map.entry('\u03BF', 'o'), // Greek small letter omicron
            Map.entry('\u03C1', 'p')  // Greek small letter rho
    );

    // Keywords associated with authentication, credentials, and payment
    private static final Set<String> CREDENTIAL_KEYWORDS = new HashSet<>(Arrays.asList(
            "login", "signin", "auth", "verify", "password", "pin", "otp", "bank", "card", "pay", "checkout"
    ));

    // Urgency lures and social engineering terms
    private static final Set<String> URGENCY_LURE_KEYWORDS = new HashSet<>(Arrays.asList(
            "kyc", "pan", "aadhaar", "electricity", "bijli", "challan", "disconnection",
            "reward", "lottery", "claim", "refund", "suspend", "unblock", "free-uc", "diamonds"
    ));

    // Institutional brands targeted in cyber fraud
    private static final Map<String, List<String>> KNOWN_INSTITUTIONS = Map.ofEntries(
            Map.entry("sbi", List.of("sbi.co.in", "onlinesbi.sbi")),
            Map.entry("hdfc", List.of("hdfcbank.com")),
            Map.entry("icici", List.of("icicibank.com")),
            Map.entry("axis", List.of("axisbank.com")),
            Map.entry("paytm", List.of("paytm.com")),
            Map.entry("phonepe", List.of("phonepe.com")),
            Map.entry("incometax", List.of("incometax.gov.in")),
            Map.entry("epfo", List.of("epfindia.gov.in")),
            Map.entry("uidai", List.of("uidai.gov.in")),
            Map.entry("parivahan", List.of("parivahan.gov.in"))
    );

    public List<UrlIndicator> analyze(ParsedUrl parsedUrl) {
        if (parsedUrl == null) return Collections.emptyList();
        List<UrlIndicator> indicators = new ArrayList<>();

        // 1. Numeric IP Host
        checkNumericIpHost(parsedUrl, indicators);

        // 2. User-info tricks (e.g. https://google.com@evil.com)
        checkUserInfoDeception(parsedUrl, indicators);

        // 3. Lookalike / Homoglyph / Punycode domains
        checkHomoglyphsAndPunycode(parsedUrl, indicators);

        // 4. Deceptive Subdomain and Institutional Impersonation
        checkDeceptiveSubdomains(parsedUrl, indicators);

        // 5. High-Risk Disposable Top-Level Domain
        checkHighRiskTld(parsedUrl, indicators);

        // 6. Insecure HTTP on Credential or Banking pages
        checkInsecureTransport(parsedUrl, indicators);

        // 7. Non-standard web ports
        checkNonStandardPort(parsedUrl, indicators);

        // 8. Excessive / obfuscated percent-encoding
        checkEncodingAnomalies(parsedUrl, indicators);

        // 9. Deceptive path and open redirect structures
        checkDeceptivePathRedirect(parsedUrl, indicators);

        // 10. Urgency lures in path or query
        checkUrgencyLures(parsedUrl, indicators);

        return indicators;
    }

    public ScanVerdict determineVerdict(List<UrlIndicator> indicators) {
        if (indicators.isEmpty()) {
            return ScanVerdict.NO_KNOWN_THREAT_DETECTED;
        }

        boolean hasCritical = false;
        int highCount = 0;
        int mediumCount = 0;

        for (UrlIndicator ind : indicators) {
            if (ind.getSeverity() == ThreatSeverity.CRITICAL) {
                hasCritical = true;
            } else if (ind.getSeverity() == ThreatSeverity.HIGH) {
                highCount++;
            } else if (ind.getSeverity() == ThreatSeverity.MEDIUM) {
                mediumCount++;
            }
        }

        if (hasCritical) {
            return ScanVerdict.KNOWN_MALICIOUS;
        }
        if (highCount >= 2 || (highCount >= 1 && mediumCount >= 1)) {
            return ScanVerdict.HIGH_RISK;
        }
        if (highCount == 1 || mediumCount >= 1) {
            return ScanVerdict.CAUTION;
        }

        return ScanVerdict.NO_KNOWN_THREAT_DETECTED;
    }

    public ThreatSeverity determineOverallSeverity(List<UrlIndicator> indicators) {
        if (indicators.isEmpty()) return ThreatSeverity.INFO;
        ThreatSeverity max = ThreatSeverity.INFO;
        for (UrlIndicator ind : indicators) {
            if (ind.getSeverity().getWeight() > max.getWeight()) {
                max = ind.getSeverity();
            }
        }
        return max;
    }

    // ==========================================
    // Heuristic Check Implementations
    // ==========================================

    private void checkNumericIpHost(ParsedUrl url, List<UrlIndicator> indicators) {
        if (url.isIpAddress()) {
            String ipType = url.getIpAddressType() != null ? url.getIpAddressType() : "NUMERIC_IP";
            ThreatSeverity sev = "OBFUSCATED_NUMERIC".equals(ipType) ? ThreatSeverity.CRITICAL : ThreatSeverity.HIGH;
            indicators.add(new UrlIndicator(
                    "IND_NUMERIC_IP_HOST",
                    "STRUCTURAL_ANOMALY",
                    "Raw Numeric IP Address Destination",
                    "The destination hostname is a numeric IP (" + ipType + ") instead of a registered domain.",
                    url.getAsciiHost(),
                    "The address points directly to a raw server IP address (" + url.getAsciiHost() + ") rather than a registered domain name.",
                    "Legitimate banking, government, and consumer portals use verified domain names with TLS certificates. Raw numeric IPs bypass domain registration accountability and are typical of rogue servers.",
                    sev
            ));
        }
    }

    private void checkUserInfoDeception(ParsedUrl url, List<UrlIndicator> indicators) {
        if (url.hasUserInfo()) {
            indicators.add(new UrlIndicator(
                    "IND_USER_INFO_TRICK",
                    "DECEPTIVE_SYNTAX",
                    "User-Info Authority Deception ('@' Trick)",
                    "URL contains an '@' delimiter preceding the destination host.",
                    url.getUserInfo() + "@" + url.getAsciiHost(),
                    "The web address uses the '@' symbol to place a deceptive name ('" + url.getUserInfo() + "') before the true server ('" + url.getAsciiHost() + "').",
                    "Browsers treat everything before '@' as login credentials and navigate to the server following it. Attackers exploit this to make a link look like a trusted site.",
                    ThreatSeverity.CRITICAL
            ));
        }
    }

    private void checkHomoglyphsAndPunycode(ParsedUrl url, List<UrlIndicator> indicators) {
        if (url.isPunycode()) {
            indicators.add(new UrlIndicator(
                    "IND_PUNYCODE_DOMAIN",
                    "LOOKALIKE_DOMAINS",
                    "Internationalized Punycode Domain ('xn--')",
                    "Domain uses the 'xn--' Punycode prefix to encode non-ASCII characters.",
                    "ASCII: " + url.getAsciiHost() + " (Unicode: " + url.getUnicodeHost() + ")",
                    "This website address uses international characters that render visually as '" + url.getUnicodeHost() + "'.",
                    "Punycode encoding is frequently used in IDN homograph attacks where characters from non-Latin alphabets visually impersonate Latin letters.",
                    ThreatSeverity.HIGH
            ));
        }

        // Inspect raw Unicode host for mixed-script homoglyphs
        String unicodeHost = url.getUnicodeHost();
        List<String> detectedHomoglyphs = new ArrayList<>();
        for (int i = 0; i < unicodeHost.length(); i++) {
            char c = unicodeHost.charAt(i);
            if (HOMOGLYPH_MAP.containsKey(c)) {
                detectedHomoglyphs.add("'" + c + "' (mimics Latin '" + HOMOGLYPH_MAP.get(c) + "')");
            }
        }

        if (!detectedHomoglyphs.isEmpty()) {
            indicators.add(new UrlIndicator(
                    "IND_HOMOGLYPH_LOOKALIKE",
                    "LOOKALIKE_DOMAINS",
                    "Visual Homoglyph Character Substitution",
                    "Host contains characters from non-Latin scripts that visually mimic Latin letters.",
                    String.join(", ", detectedHomoglyphs),
                    "The web address contains international characters designed to visually imitate standard English letters.",
                    "Homoglyphs are used to build near-identical clones of banking and login portals that fool human inspection.",
                    ThreatSeverity.CRITICAL
            ));
        }
    }

    private void checkDeceptiveSubdomains(ParsedUrl url, List<UrlIndicator> indicators) {
        String host = url.getAsciiHost();
        String registrable = url.getRegistrableDomain();

        for (Map.Entry<String, List<String>> entry : KNOWN_INSTITUTIONS.entrySet()) {
            String brand = entry.getKey();
            List<String> officialDomains = entry.getValue();

            boolean hostMatchesBrand = host.contains(brand);
            if (!hostMatchesBrand) continue;

            // Check if this domain is legitimately owned by the institution
            boolean isOfficial = false;
            for (String official : officialDomains) {
                if (registrable.equalsIgnoreCase(official) || host.equalsIgnoreCase(official) || host.endsWith("." + official)) {
                    isOfficial = true;
                    break;
                }
            }

            if (!isOfficial) {
                indicators.add(new UrlIndicator(
                        "IND_DECEPTIVE_BRAND_HOST",
                        "IMPERSONATION",
                        "Institutional Brand Impersonation (" + brand.toUpperCase() + ")",
                        "Host includes brand keyword '" + brand + "' but registered domain '" + registrable + "' is not owned by the institution.",
                        "Observed: " + host + " (Registered Domain: " + registrable + ")",
                        "The link contains the brand name '" + brand.toUpperCase() + "', but the actual registered website owner is '" + registrable + "'.",
                        "Attackers place familiar bank or utility names in subdomains or domain labels to create a false sense of security while hosting fake login forms.",
                        ThreatSeverity.CRITICAL
                ));
            }
        }
    }

    private void checkHighRiskTld(ParsedUrl url, List<UrlIndicator> indicators) {
        String tld = url.getTopLevelDomain().toLowerCase(Locale.ROOT);
        if (HIGH_RISK_TLDS.contains(tld)) {
            indicators.add(new UrlIndicator(
                    "IND_HIGH_RISK_TLD",
                    "REPUTATION_HEURISTIC",
                    "Disposable / High-Risk Top-Level Domain (" + tld + ")",
                    "The domain uses a TLD with a statistically elevated rate of phishing and fraud campaigns.",
                    "TLD: " + tld + " on host " + url.getAsciiHost(),
                    "The website ends with '" + tld + "', an extension commonly used for cheap, temporary fraud pages.",
                    "This is a structural heuristic, not conclusive proof that the site is malicious. However, major public utilities and banks do not operate primary customer portals on disposable TLDs.",
                    ThreatSeverity.MEDIUM
            ));
        }
    }

    private void checkInsecureTransport(ParsedUrl url, List<UrlIndicator> indicators) {
        if ("http".equalsIgnoreCase(url.getScheme())) {
            String combined = (url.getPath() + "?" + url.getQuery()).toLowerCase(Locale.ROOT);
            boolean hasCredentialTarget = false;
            for (String kw : CREDENTIAL_KEYWORDS) {
                if (combined.contains(kw)) {
                    hasCredentialTarget = true;
                    break;
                }
            }

            if (hasCredentialTarget) {
                indicators.add(new UrlIndicator(
                        "IND_INSECURE_HTTP_CREDENTIAL",
                        "TRANSPORT_SECURITY",
                        "Cleartext HTTP on Sensitive Account Target",
                        "Unencrypted 'http://' scheme combined with authentication or payment keywords.",
                        "Scheme: http with path: " + url.getPath(),
                        "The link uses an unencrypted (HTTP) connection while referencing login, banking, or account verification.",
                        "Data sent over unencrypted HTTP can be intercepted, read, or modified by attackers on public Wi-Fi or cellular networks.",
                        ThreatSeverity.HIGH
                ));
            } else {
                indicators.add(new UrlIndicator(
                        "IND_INSECURE_HTTP_GENERAL",
                        "TRANSPORT_SECURITY",
                        "Unencrypted Web Protocol (HTTP)",
                        "Web address uses unencrypted 'http://' rather than modern HTTPS.",
                        "Scheme: http://",
                        "This link does not use encrypted HTTPS communication.",
                        "Modern websites use HTTPS to safeguard privacy and guarantee that web traffic is not tampered with in transit.",
                        ThreatSeverity.LOW
                ));
            }
        }
    }

    private void checkNonStandardPort(ParsedUrl url, List<UrlIndicator> indicators) {
        if (url.isNonStandardPort()) {
            indicators.add(new UrlIndicator(
                    "IND_NON_STANDARD_PORT",
                    "NETWORK_STRUCTURAL",
                    "Non-Standard Web Port (" + url.getPort() + ")",
                    "Destination port is not standard HTTP (80) or HTTPS (443).",
                    "Port: " + url.getPort(),
                    "The web address directs traffic to an uncommon port (" + url.getPort() + ") instead of standard web ports.",
                    "Standard public services operate on default ports 80/443. Non-standard ports are frequently associated with test environments, compromised endpoints, or rogue proxies.",
                    ThreatSeverity.LOW
            ));
        }
    }

    private void checkEncodingAnomalies(ParsedUrl url, List<UrlIndicator> indicators) {
        if (url.hasExcessiveEncoding()) {
            indicators.add(new UrlIndicator(
                    "IND_EXCESSIVE_ENCODING",
                    "OBFUSCATION",
                    "Obfuscated Percent-Encoding Sequences",
                    "URL contains double-percent encoding (%25), null bytes (%00), or encoded slashes/dots.",
                    url.getOriginalInput(),
                    "The link uses nested or abnormal percent-encoding to hide its structure.",
                    "Attackers use multi-layered character encoding to evade automated web security scanners and URL inspection filters.",
                    ThreatSeverity.MEDIUM
            ));
        }
    }

    private void checkDeceptivePathRedirect(ParsedUrl url, List<UrlIndicator> indicators) {
        String path = url.getPath();
        String query = url.getQuery().toLowerCase(Locale.ROOT);

        // Check for double slashes in path
        if (path.contains("//")) {
            indicators.add(new UrlIndicator(
                    "IND_DOUBLE_SLASH_PATH",
                    "PATH_STRUCTURAL",
                    "Double-Slash Path Obfuscation",
                    "Path contains '//' sequence which can be interpreted differently across server software.",
                    "Path: " + path,
                    "The path format contains multiple consecutive slashes.",
                    "Consecutive slashes are used in URL path-traversal attacks and URL parser confusion exploits.",
                    ThreatSeverity.LOW
            ));
        }

        // Check for open-redirect target parameters
        if (query.contains("url=http") || query.contains("redirect=http") || query.contains("dest=http")
                || query.contains("link=http") || query.contains("target=http")) {
            indicators.add(new UrlIndicator(
                    "IND_OPEN_REDIRECT_PARAMETER",
                    "DECEPTIVE_PATH",
                    "Embedded Redirect Target in Query",
                    "Query string contains an embedded web address parameter.",
                    "Query: " + query,
                    "The link contains instructions to redirect your browser to a different website.",
                    "Open redirects are abused to send users from an apparently trusted domain to an untrusted phishing site.",
                    ThreatSeverity.MEDIUM
            ));
        }
    }

    private void checkUrgencyLures(ParsedUrl url, List<UrlIndicator> indicators) {
        String combined = (url.getPath() + " " + url.getQuery()).toLowerCase(Locale.ROOT);
        List<String> foundLures = new ArrayList<>();
        for (String lure : URGENCY_LURE_KEYWORDS) {
            if (combined.contains(lure)) {
                foundLures.add(lure);
            }
        }

        if (!foundLures.isEmpty()) {
            indicators.add(new UrlIndicator(
                    "IND_URGENCY_LURE",
                    "SOCIAL_ENGINEERING",
                    "Account Urgency or Compliance Lure",
                    "Path or query contains high-risk urgency tokens: " + String.join(", ", foundLures),
                    "Tokens: " + String.join(", ", foundLures),
                    "The link claims to involve urgent matters such as '" + String.join(", ", foundLures) + "'.",
                    "Scammers create artificial urgency regarding bank accounts, electricity disconnections, or free prizes to rush users into acting before verifying authenticity.",
                    ThreatSeverity.MEDIUM
            ));
        }
    }
}
