package dev.guardianai.family;

import dev.guardianai.net.AuthTokenSource;
import dev.guardianai.net.HttpTransport;
import dev.guardianai.util.Json;

import java.util.HashMap;
import java.util.Map;

/**
 * Authenticated JSON-over-HTTPS client for the GuardianAi backend ({@code api} Cloud Function).
 * Maps every outcome to a typed {@link Result}; never throws for network or server problems.
 */
public class BackendClient {

    public enum Failure { NONE, NOT_CONFIGURED, OFFLINE, TIMEOUT, AUTH, SERVER_ERROR, BAD_RESPONSE, API_ERROR }

    public static final class Result {
        public final Failure failure;
        public final int httpCode;
        public final String errorCode;   // backend error code, e.g. EXPIRED_CODE
        public final String message;
        public final Map<String, Object> body;

        Result(Failure f, int code, String errorCode, String message, Map<String, Object> body) {
            this.failure = f;
            this.httpCode = code;
            this.errorCode = errorCode;
            this.message = message == null ? "" : message;
            this.body = body;
        }

        public boolean ok() { return failure == Failure.NONE; }

        /** True when the request may or may not have reached the server (outcome unknown). */
        public boolean outcomeUnknown() { return failure == Failure.TIMEOUT; }
    }

    public static final int DEFAULT_TIMEOUT_MS = 10_000;

    private final String baseUrl;
    private final AuthTokenSource auth;
    private final HttpTransport http;
    private final int timeoutMs;

    public BackendClient(String baseUrl, AuthTokenSource auth, HttpTransport http, int timeoutMs) {
        this.baseUrl = baseUrl == null ? "" : baseUrl.trim().replaceAll("/+$", "");
        this.auth = auth;
        this.http = http;
        this.timeoutMs = timeoutMs > 0 ? timeoutMs : DEFAULT_TIMEOUT_MS;
    }

    public boolean isConfigured() {
        return baseUrl.startsWith("https://") && auth != null && http != null;
    }

    public String getUserId() {
        return auth == null ? null : auth.getUserId();
    }

    public Result call(String path, Map<String, Object> payload) {
        if (!isConfigured()) return new Result(Failure.NOT_CONFIGURED, 0, null, "The GuardianAi family service is not set up in this build", null);
        for (int attempt = 0; attempt < 2; attempt++) {
            String token;
            try {
                token = auth.getIdToken();
            } catch (AuthTokenSource.AuthException e) {
                return new Result(e.network ? Failure.OFFLINE : Failure.AUTH, 0, null, e.getMessage(), null);
            }
            Map<String, String> h = new HashMap<>();
            h.put("Authorization", "Bearer " + token);
            h.put("Content-Type", "application/json");
            HttpTransport.Response r;
            try {
                r = http.execute("POST", baseUrl + path, h, Json.write(payload == null ? new HashMap<String, Object>() : payload), timeoutMs);
            } catch (HttpTransport.TimeoutException e) {
                return new Result(Failure.TIMEOUT, 0, null, "The server didn't answer in time", null);
            } catch (HttpTransport.NetworkException e) {
                return new Result(Failure.OFFLINE, 0, null, "No internet connection", null);
            }
            if (r.code == 401 && attempt == 0) {
                auth.invalidate();
                continue;
            }
            Map<String, Object> body = null;
            try {
                if (!r.body.isEmpty()) body = Json.parseObject(r.body);
            } catch (Json.ParseException e) {
                return new Result(r.code >= 500 ? Failure.SERVER_ERROR : Failure.BAD_RESPONSE, r.code, null, "Unreadable server response", null);
            }
            if (r.code == 200) {
                if (body == null) return new Result(Failure.BAD_RESPONSE, r.code, null, "Empty server response", null);
                return new Result(Failure.NONE, 200, null, "", body);
            }
            Map<String, Object> err = body == null ? null : Json.obj(body, "error");
            String code = err == null ? null : Json.str(err, "code");
            String msg = err == null ? null : Json.str(err, "message");
            if (r.code == 401) return new Result(Failure.AUTH, r.code, code, msg == null ? "Not signed in" : msg, body);
            if (r.code >= 500) return new Result(Failure.SERVER_ERROR, r.code, code, msg == null ? "Server error" : msg, body);
            return new Result(Failure.API_ERROR, r.code, code == null ? "HTTP_" + r.code : code, msg == null ? "Request refused" : msg, body);
        }
        return new Result(Failure.AUTH, 401, null, "Not signed in", null);
    }
}
