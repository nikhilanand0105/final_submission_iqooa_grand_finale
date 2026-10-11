/**
 * Saathi Personal — Phase 8: Real Threat Intelligence Cloud Integration
 *
 * Secure Firebase Cloud Functions proxy for:
 * 1. Google Web Risk API v1 (URL Reputation for commercial applications)
 * 2. VirusTotal Intelligence API v3 (Cryptographic SHA-256 APK Hash Reputation)
 *
 * Privacy & Security Guarantees:
 * - Server-side secret storage (Google Cloud Secret Manager / environment secrets)
 * - Zero APK binaries uploaded — strict 64-character SHA-256 hash lookup only
 * - Automatic stripping of sensitive URL query parameters prior to logging/lookup
 * - Sliding window in-memory rate limiting to protect paid quotas
 * - Deterministic typed verdicts; errors/timeouts NEVER coerced into "clean"
 */

const functions = require("firebase-functions");
const admin = require("firebase-admin");
const https = require("https");
const { URL } = require("url");

if (!admin.apps.length) {
    admin.initializeApp();
}

// ============================================================================
// 1. IN-MEMORY RATE LIMITER
// ============================================================================
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const MAX_REQUESTS_PER_WINDOW = 30;     // 30 requests / minute / IP
const clientRequestCounts = new Map();

function isRateLimited(ip) {
    const now = Date.now();
    const clientRecord = clientRequestCounts.get(ip) || { count: 0, resetTime: now + RATE_LIMIT_WINDOW_MS };

    if (now > clientRecord.resetTime) {
        clientRecord.count = 1;
        clientRecord.resetTime = now + RATE_LIMIT_WINDOW_MS;
        clientRequestCounts.set(ip, clientRecord);
        return false;
    }

    clientRecord.count++;
    clientRequestCounts.set(ip, clientRecord);
    return clientRecord.count > MAX_REQUESTS_PER_WINDOW;
}

// Cleanup rate-limiting map periodically
setInterval(() => {
    const now = Date.now();
    for (const [ip, record] of clientRequestCounts.entries()) {
        if (now > record.resetTime) {
            clientRequestCounts.delete(ip);
        }
    }
}, 5 * 60 * 1000);

// ============================================================================
// 2. PRIVACY & SANITIZATION HELPERS
// ============================================================================
const SENSITIVE_QUERY_PARAMS = new Set([
    "token", "auth", "key", "apikey", "password", "pwd", "secret",
    "otp", "code", "session", "sessionid", "sid", "user", "username",
    "email", "phone", "mobile", "aadhaar", "pan", "account", "card"
]);

function sanitizeAndCanonicalizeUrl(rawUrl) {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        throw new Error("Only http and https protocols are supported");
    }

    // Strip sensitive query parameters to prevent PII leakage
    const searchParams = parsed.searchParams;
    const keysToDelete = [];
    for (const key of searchParams.keys()) {
        if (SENSITIVE_QUERY_PARAMS.has(key.toLowerCase())) {
            keysToDelete.push(key);
        }
    }
    keysToDelete.forEach(k => searchParams.delete(k));

    parsed.hash = ""; // Strip client-side fragments
    return parsed.toString();
}

function httpsGetJson(url, headers = {}, timeoutMs = 4000) {
    return new Promise((resolve, reject) => {
        const parsedUrl = new URL(url);
        const options = {
            hostname: parsedUrl.hostname,
            path: parsedUrl.pathname + parsedUrl.search,
            method: "GET",
            headers: {
                "Accept": "application/json",
                ...headers
            },
            timeout: timeoutMs
        };

        const req = https.request(options, (res) => {
            let body = "";
            res.on("data", (chunk) => { body += chunk; });
            res.on("end", () => {
                resolve({ statusCode: res.statusCode, body });
            });
        });

        req.on("timeout", () => {
            req.destroy(new Error("Upstream threat provider request timed out after " + timeoutMs + "ms"));
        });

        req.on("error", (err) => {
            reject(err);
        });

        req.end();
    });
}

// ============================================================================
// 3. CLOUD FUNCTION: checkUrlReputation (Google Web Risk API v1)
// ============================================================================
exports.checkUrlReputation = functions.https.onRequest(async (req, res) => {
    // CORS headers for web/app clients
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
    if (req.method === "OPTIONS") {
        res.status(204).send("");
        return;
    }

    if (req.method !== "POST") {
        res.status(405).json({
            state: "invalid_input",
            message: "Method not allowed. Use POST with JSON payload."
        });
        return;
    }

    const clientIp = req.headers["x-forwarded-for"] || req.connection.remoteAddress || "unknown";
    if (isRateLimited(clientIp)) {
        res.status(429).json({
            state: "provider_unavailable",
            message: "Rate limit exceeded (HTTP 429). Live threat checks temporarily paused."
        });
        return;
    }

    const { url } = req.body || {};
    if (!url || typeof url !== "string" || url.trim().length === 0) {
        res.status(400).json({
            state: "invalid_input",
            message: "Request must include a non-empty 'url' string."
        });
        return;
    }

    let canonicalUrl;
    try {
        canonicalUrl = sanitizeAndCanonicalizeUrl(url.trim());
    } catch (err) {
        res.status(400).json({
            state: "invalid_input",
            message: "Malformed URL syntax: " + err.message
        });
        return;
    }

    // Retrieve server secret (Google Cloud Secret Manager or environment config)
    const webRiskApiKey = process.env.WEB_RISK_API_KEY || functions.config().webrisk?.key;

    if (!webRiskApiKey) {
        // Safe unconfigured fallback: report provider unavailable without throwing uncaught errors
        res.status(200).json({
            state: "provider_unavailable",
            provider: "Google Web Risk",
            statusMessage: "Live reputation unavailable: Google Web Risk API key is not configured on the server.",
            checkedAt: Date.now()
        });
        return;
    }

    const startTime = Date.now();
    try {
        // Query Google Web Risk API v1 for commercial threat lists
        // Supported threatTypes: MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE
        const webRiskEndpoint = "https://webrisk.googleapis.com/v1/uris:search?"
            + "uri=" + encodeURIComponent(canonicalUrl)
            + "&threatTypes=MALWARE"
            + "&threatTypes=SOCIAL_ENGINEERING"
            + "&threatTypes=UNWANTED_SOFTWARE"
            + "&key=" + webRiskApiKey;

        const response = await httpsGetJson(webRiskEndpoint, {}, 3500);
        const durationMs = Date.now() - startTime;

        if (response.statusCode === 429) {
            res.status(429).json({
                state: "provider_unavailable",
                provider: "Google Web Risk",
                statusMessage: "Provider rate limit or quota exceeded (HTTP 429)",
                responseTimeMs: durationMs
            });
            return;
        }

        if (response.statusCode === 401 || response.statusCode === 403) {
            functions.logger.error("Web Risk API authentication failure", { statusCode: response.statusCode });
            res.status(503).json({
                state: "provider_unavailable",
                provider: "Google Web Risk",
                statusMessage: "Threat provider credentials invalid or expired",
                responseTimeMs: durationMs
            });
            return;
        }

        if (response.statusCode !== 200) {
            res.status(502).json({
                state: "provider_unavailable",
                provider: "Google Web Risk",
                statusMessage: "Upstream provider error (HTTP " + response.statusCode + ")",
                responseTimeMs: durationMs
            });
            return;
        }

        let resultJson;
        try {
            resultJson = JSON.parse(response.body);
        } catch (parseErr) {
            res.status(502).json({
                state: "provider_unavailable",
                provider: "Google Web Risk",
                statusMessage: "Malformed JSON received from Web Risk provider",
                responseTimeMs: durationMs
            });
            return;
        }

        // Web Risk returns { threat: { threatTypes: [...] } } on match, or {} on clean
        if (resultJson.threat && Array.isArray(resultJson.threat.threatTypes) && resultJson.threat.threatTypes.length > 0) {
            const types = resultJson.threat.threatTypes;
            res.status(200).json({
                state: "threat_match",
                threat: true,
                clean: false,
                provider: "Google Web Risk",
                threatTypes: types,
                threatType: types[0],
                statusMessage: "Google Web Risk confirmed threat match: " + types.join(", "),
                checkedAt: Date.now(),
                responseTimeMs: durationMs,
                attribution: "Data provided by Google Web Risk"
            });
        } else {
            res.status(200).json({
                state: "no_known_threat_match",
                threat: false,
                clean: true,
                provider: "Google Web Risk",
                threatTypes: [],
                statusMessage: "No known threat match found in Google Web Risk database",
                checkedAt: Date.now(),
                responseTimeMs: durationMs,
                attribution: "Data provided by Google Web Risk"
            });
        }

    } catch (err) {
        const durationMs = Date.now() - startTime;
        const isTimeout = err.message && err.message.includes("timed out");
        res.status(504).json({
            state: isTimeout ? "timeout_network_error" : "provider_unavailable",
            provider: "Google Web Risk",
            statusMessage: isTimeout ? "Provider lookup timed out after 3500ms" : ("Provider error: " + err.message),
            checkedAt: Date.now(),
            responseTimeMs: durationMs
        });
    }
});

// ============================================================================
// 4. CLOUD FUNCTION: checkApkHashReputation (VirusTotal API v3)
// ============================================================================
const SHA256_HEX_REGEX = /^[a-fA-F0-9]{64}$/;

exports.checkApkHashReputation = functions.https.onRequest(async (req, res) => {
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
    if (req.method === "OPTIONS") {
        res.status(204).send("");
        return;
    }

    if (req.method !== "POST") {
        res.status(405).json({
            state: "invalid_input",
            message: "Method not allowed. Use POST with JSON payload."
        });
        return;
    }

    // Safety Invariant: Check if client accidentally sent a file upload multipart body
    const contentType = req.headers["content-type"] || "";
    if (contentType.toLowerCase().includes("multipart/form-data") || req.body?.file) {
        res.status(400).json({
            state: "invalid_input",
            message: "Privacy policy violation: Binary file uploads are prohibited. Only SHA-256 cryptographic hashes may be queried."
        });
        return;
    }

    const clientIp = req.headers["x-forwarded-for"] || req.connection.remoteAddress || "unknown";
    if (isRateLimited(clientIp)) {
        res.status(429).json({
            state: "provider_unavailable",
            message: "Rate limit exceeded (HTTP 429). Live hash checks temporarily paused."
        });
        return;
    }

    const { sha256 } = req.body || {};
    if (!sha256 || typeof sha256 !== "string" || !SHA256_HEX_REGEX.test(sha256.trim())) {
        res.status(400).json({
            state: "invalid_input",
            message: "Invalid input: 'sha256' must be an exact 64-character hexadecimal SHA-256 string."
        });
        return;
    }

    const normalizedHash = sha256.trim().toLowerCase();
    const vtApiKey = process.env.VIRUSTOTAL_API_KEY || functions.config().virustotal?.key;

    if (!vtApiKey) {
        // Safe unconfigured fallback: report provider unavailable without throwing uncaught errors
        res.status(200).json({
            state: "provider_unavailable",
            provider: "VirusTotal Threat Cloud",
            sha256: normalizedHash,
            statusMessage: "Live hash reputation unavailable: VirusTotal API key is not configured on the server.",
            checkedAt: Date.now()
        });
        return;
    }

    const startTime = Date.now();
    try {
        const vtEndpoint = "https://www.virustotal.com/api/v3/files/" + normalizedHash;
        const response = await httpsGetJson(vtEndpoint, { "x-apikey": vtApiKey }, 4000);
        const durationMs = Date.now() - startTime;

        if (response.statusCode === 429) {
            res.status(429).json({
                state: "provider_unavailable",
                provider: "VirusTotal Threat Cloud",
                sha256: normalizedHash,
                statusMessage: "VirusTotal rate limit exceeded (HTTP 429)",
                responseTimeMs: durationMs
            });
            return;
        }

        if (response.statusCode === 401 || response.statusCode === 403) {
            functions.logger.error("VirusTotal API authentication failure", { statusCode: response.statusCode });
            res.status(503).json({
                state: "provider_unavailable",
                provider: "VirusTotal Threat Cloud",
                sha256: normalizedHash,
                statusMessage: "VirusTotal API credentials invalid or expired",
                responseTimeMs: durationMs
            });
            return;
        }

        if (response.statusCode === 404) {
            // Hash not found in VT dataset -> No known threat record
            res.status(200).json({
                state: "no_known_threat_match",
                clean: true,
                malicious: 0,
                total: 0,
                provider: "VirusTotal Threat Cloud",
                sha256: normalizedHash,
                statusMessage: "Hash not observed in global threat database (no malicious detections)",
                checkedAt: Date.now(),
                responseTimeMs: durationMs
            });
            return;
        }

        if (response.statusCode !== 200) {
            res.status(502).json({
                state: "provider_unavailable",
                provider: "VirusTotal Threat Cloud",
                sha256: normalizedHash,
                statusMessage: "Upstream threat service returned HTTP " + response.statusCode,
                responseTimeMs: durationMs
            });
            return;
        }

        const data = JSON.parse(response.body);
        const stats = data.data?.attributes?.last_analysis_stats || {};
        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;
        const total = (stats.harmless || 0) + (stats.undetected || 0) + malicious + suspicious;
        const classification = data.data?.attributes?.popular_threat_classification?.suggested_threat_label || "";

        if (malicious > 0 || suspicious > 1) {
            res.status(200).json({
                state: "threat_match",
                threat: true,
                clean: false,
                malicious: malicious,
                total: total,
                threatFamily: classification || "Trojan/Malware",
                provider: "VirusTotal Threat Cloud",
                sha256: normalizedHash,
                statusMessage: "Known malicious APK hash detected (" + malicious + "/" + total + " security engines)",
                checkedAt: Date.now(),
                responseTimeMs: durationMs
            });
        } else {
            res.status(200).json({
                state: "no_known_threat_match",
                threat: false,
                clean: true,
                malicious: 0,
                total: total,
                provider: "VirusTotal Threat Cloud",
                sha256: normalizedHash,
                statusMessage: "0 malicious detections across " + total + " threat engines",
                checkedAt: Date.now(),
                responseTimeMs: durationMs
            });
        }

    } catch (err) {
        const durationMs = Date.now() - startTime;
        const isTimeout = err.message && err.message.includes("timed out");
        res.status(504).json({
            state: isTimeout ? "timeout_network_error" : "provider_unavailable",
            provider: "VirusTotal Threat Cloud",
            sha256: normalizedHash,
            statusMessage: isTimeout ? "Provider lookup timed out after 4000ms" : ("Provider error: " + err.message),
            checkedAt: Date.now(),
            responseTimeMs: durationMs
        });
    }
});
