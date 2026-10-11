package dev.saathi.shield.url;

import dev.saathi.net.AuthTokenSource;
import dev.saathi.net.HttpTransport;
import dev.saathi.util.Json;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Reputation lookup through the Saathi backend's {@code checkUrl} endpoint, which calls Google Cloud Web Risk
 * (uris.search) server-side. The Web Risk API key lives only in the backend's secret store, never on the device.
 *
 * Request:  POST {baseUrl}/checkUrl  Authorization: Bearer <Firebase ID token>  {"url": "<sanitized url>"}
 * Response: {"result":"THREAT_MATCH","threatTypes":["SOCIAL_ENGINEERING"]} | {"result":"NO_MATCH"}
 * Any other response is treated as PROVIDER_UNAVAILABLE.
 */
public class BackendUrlReputationProvider implements UrlReputationProvider {

    public static final int DEFAULT_TIMEOUT_MS = 4000;
    private static final Set<String> KNOWN_TYPES = new HashSet<>(Arrays.asList(
            "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "SOCIAL_ENGINEERING_EXTENDED_COVERAGE"));

    private final String baseUrl;
    private final AuthTokenSource auth;
    private final HttpTransport http;
    private final int timeoutMs;

    public BackendUrlReputationProvider(String baseUrl, AuthTokenSource auth, HttpTransport http, int timeoutMs) {
        this.baseUrl = baseUrl == null ? "" : baseUrl.trim().replaceAll("/+$", "");
        this.auth = auth;
        this.http = http;
        this.timeoutMs = timeoutMs > 0 ? timeoutMs : DEFAULT_TIMEOUT_MS;
    }

    @Override
    public boolean isConfigured() {
        return baseUrl.startsWith("https://") && auth != null && http != null;
    }

    @Override
    public String getName() {
        return "Google Web Risk (via Saathi server)";
    }

    @Override
    public String getDisclosure() {
        return "To check the online safety list, the website part of the link (for example https://example.com/page) "
                + "is sent to the Saathi server, which asks Google Web Risk. Anything after '?' and any login text before '@' "
                + "is removed first. Saathi does not store the link on the server.";
    }

    @Override
    public ReputationResult check(ParsedUrl url) {
        if (!isConfigured()) return ReputationResult.notChecked("Online safety service is not configured");
        if (url == null || !url.isValid()) return ReputationResult.notChecked("Invalid address");
        String token;
        try {
            token = auth.getIdToken();
        } catch (AuthTokenSource.AuthException e) {
            return e.network ? ReputationResult.timeout("Could not sign in (no connection)")
                    : ReputationResult.unavailable("Could not sign in to the Saathi server");
        }
        Map<String, String> h = new HashMap<>();
        h.put("Authorization", "Bearer " + token);
        h.put("Content-Type", "application/json");
        String body = Json.write(Json.map("url", url.getSanitizedUrl()));
        HttpTransport.Response r;
        try {
            r = http.execute("POST", baseUrl + "/checkUrl", h, body, timeoutMs);
        } catch (HttpTransport.TimeoutException e) {
            return ReputationResult.timeout("The online check timed out");
        } catch (HttpTransport.NetworkException e) {
            return ReputationResult.timeout("No internet connection");
        }
        if (r.code == 401 || r.code == 403) {
            auth.invalidate();
            return ReputationResult.unavailable("The Saathi server refused the request (HTTP " + r.code + ")");
        }
        if (r.code != 200) return ReputationResult.unavailable("The Saathi server returned HTTP " + r.code);
        return parse(r.body);
    }

    static ReputationResult parse(String body) {
        Map<String, Object> o;
        try {
            o = Json.parseObject(body);
        } catch (Json.ParseException e) {
            return ReputationResult.unavailable("Unreadable answer from the safety service");
        }
        String res = Json.str(o, "result");
        if ("NO_MATCH".equals(res)) return ReputationResult.noMatch();
        if ("THREAT_MATCH".equals(res)) {
            List<String> types = Json.strList(o, "threatTypes");
            if (types == null || types.isEmpty()) return ReputationResult.unavailable("Threat answer had no threat type");
            List<String> clean = new ArrayList<>();
            for (String t : types) if (KNOWN_TYPES.contains(t)) clean.add(t);
            if (clean.isEmpty()) return ReputationResult.unavailable("Threat answer had unknown threat types");
            return ReputationResult.threat(clean);
        }
        return ReputationResult.unavailable("Unexpected answer from the safety service");
    }
}
