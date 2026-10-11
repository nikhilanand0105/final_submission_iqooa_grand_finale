package dev.saathi.net;

import dev.saathi.util.Json;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Firebase Authentication over its documented REST API (no Firebase SDK, no google-services plugin):
 * - sign up anonymously: POST identitytoolkit.googleapis.com/v1/accounts:signUp?key=WEB_API_KEY
 * - refresh:             POST securetoken.googleapis.com/v1/token?key=WEB_API_KEY
 * The Web API key identifies the Firebase project and is not a secret; access control is enforced by the
 * backend, which verifies the resulting ID token. The refresh token is kept in app-private storage via {@link Store}.
 */
public class FirebaseAnonymousAuth implements AuthTokenSource {

    /** Persists the refresh token and uid in app-private storage. */
    public interface Store {
        String get(String key);
        void put(String key, String value);
    }

    private static final String K_REFRESH = "fb_refresh_token";
    private static final String K_UID = "fb_uid";
    private static final int TIMEOUT_MS = 8000;

    private final String apiKey;
    private final HttpTransport http;
    private final Store store;
    private final Clock clock;

    private String idToken;
    private long expiresAtMs;

    public interface Clock { long now(); }

    public FirebaseAnonymousAuth(String apiKey, HttpTransport http, Store store) {
        this(apiKey, http, store, System::currentTimeMillis);
    }

    public FirebaseAnonymousAuth(String apiKey, HttpTransport http, Store store, Clock clock) {
        this.apiKey = apiKey == null ? "" : apiKey.trim();
        this.http = http;
        this.store = store;
        this.clock = clock;
    }

    public boolean isConfigured() {
        return !apiKey.isEmpty();
    }

    @Override
    public synchronized String getUserId() {
        return store.get(K_UID);
    }

    @Override
    public synchronized void invalidate() {
        idToken = null;
        expiresAtMs = 0;
    }

    @Override
    public synchronized String getIdToken() throws AuthException {
        if (!isConfigured()) throw new AuthException("Firebase is not configured in this build", false);
        if (idToken != null && clock.now() < expiresAtMs - 60_000) return idToken;
        String refresh = store.get(K_REFRESH);
        if (refresh != null) {
            try {
                refresh(refresh);
                return idToken;
            } catch (AuthException e) {
                if (e.network) throw e;
                // refresh token revoked/expired: fall through to a new anonymous account would orphan pairing,
                // so surface the error instead of silently creating a new identity.
                throw new AuthException("Sign-in expired. Pair again with your family.", false);
            }
        }
        signUp();
        return idToken;
    }

    private void signUp() throws AuthException {
        Map<String, Object> r = post("https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=" + enc(apiKey),
                "application/json", "{\"returnSecureToken\":true}");
        String tok = Json.str(r, "idToken");
        String rt = Json.str(r, "refreshToken");
        String uid = Json.str(r, "localId");
        if (tok == null || rt == null || uid == null) throw new AuthException("Unexpected sign-in response", false);
        accept(tok, rt, uid, Json.str(r, "expiresIn"));
    }

    private void refresh(String refreshToken) throws AuthException {
        Map<String, Object> r = post("https://securetoken.googleapis.com/v1/token?key=" + enc(apiKey),
                "application/x-www-form-urlencoded", "grant_type=refresh_token&refresh_token=" + enc(refreshToken));
        String tok = Json.str(r, "id_token");
        String rt = Json.str(r, "refresh_token");
        String uid = Json.str(r, "user_id");
        if (tok == null || rt == null) throw new AuthException("Unexpected token refresh response", false);
        accept(tok, rt, uid != null ? uid : store.get(K_UID), Json.str(r, "expires_in"));
    }

    private void accept(String tok, String rt, String uid, String expiresIn) {
        long secs = 3600;
        try {
            if (expiresIn != null) secs = Long.parseLong(expiresIn);
        } catch (NumberFormatException ignored) {
            // keep default
        }
        idToken = tok;
        expiresAtMs = clock.now() + secs * 1000;
        store.put(K_REFRESH, rt);
        if (uid != null) store.put(K_UID, uid);
    }

    private Map<String, Object> post(String url, String type, String body) throws AuthException {
        Map<String, String> h = new HashMap<>();
        h.put("Content-Type", type);
        HttpTransport.Response r;
        try {
            r = http.execute("POST", url, h, body, TIMEOUT_MS);
        } catch (HttpTransport.TimeoutException | HttpTransport.NetworkException e) {
            throw new AuthException("No connection to sign-in service", true);
        }
        if (r.code != 200) throw new AuthException("Sign-in service returned HTTP " + r.code, false);
        try {
            return Json.parseObject(r.body);
        } catch (Json.ParseException e) {
            throw new AuthException("Unreadable sign-in response", false);
        }
    }

    private static String enc(String s) {
        try {
            return URLEncoder.encode(s, StandardCharsets.UTF_8.name());
        } catch (java.io.UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }
}
