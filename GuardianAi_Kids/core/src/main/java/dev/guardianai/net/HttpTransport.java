package dev.guardianai.net;

import java.util.Map;

/**
 * Minimal HTTP abstraction so network-backed providers can be unit-tested with
 * fakes (timeouts, offline, malformed bodies) and so the app never hard-wires
 * a particular client library into the pure-Java core.
 */
public interface HttpTransport {

    final class Response {
        public final int code;
        public final String body;

        public Response(int code, String body) {
            this.code = code;
            this.body = body != null ? body : "";
        }
    }

    /** Thrown when the request did not complete within its time budget. */
    class TimeoutException extends Exception {
        public TimeoutException(String msg) {
            super(msg);
        }
    }

    /** Thrown when no connection could be made (offline, DNS, TLS, refused). */
    class NetworkException extends Exception {
        public NetworkException(String msg) {
            super(msg);
        }
    }

    /**
     * Executes a request.
     *
     * @param method  "GET" or "POST"
     * @param url     absolute HTTPS URL
     * @param headers request headers (may be empty)
     * @param body    request body for POST, or null
     */
    Response execute(String method, String url, Map<String, String> headers, String body, int timeoutMillis)
            throws TimeoutException, NetworkException;
}
