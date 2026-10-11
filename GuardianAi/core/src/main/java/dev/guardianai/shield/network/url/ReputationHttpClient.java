package dev.guardianai.shield.network.url;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import javax.net.ssl.HttpsURLConnection;

/**
 * Injectable network transport layer for threat reputation lookups.
 * Enforces secure HTTPS, strict timeouts, error mapping, and avoids logging full URLs.
 */
public interface ReputationHttpClient {

    class HttpResponse {
        public final int statusCode;
        public final String body;
        public final Map<String, String> headers;

        public HttpResponse(int statusCode, String body, Map<String, String> headers) {
            this.statusCode = statusCode;
            this.body = body != null ? body : "";
            this.headers = headers != null ? headers : Map.of();
        }

        public boolean isSuccess() {
            return statusCode >= 200 && statusCode < 300;
        }

        public boolean isRateLimited() {
            return statusCode == 429;
        }

        public boolean isServerError() {
            return statusCode >= 500 && statusCode < 600;
        }
    }

    HttpResponse executePost(String endpointUrl, Map<String, String> headers, String jsonBody, int timeoutMs) throws IOException;

    HttpResponse executeGet(String endpointUrl, Map<String, String> headers, int timeoutMs) throws IOException;

    /**
     * Default secure HTTPS client implementation using standard Java HttpURLConnection.
     */
    class DefaultHttpsClient implements ReputationHttpClient {

        @Override
        public HttpResponse executePost(String endpointUrl, Map<String, String> headers, String jsonBody, int timeoutMs) throws IOException {
            if (!endpointUrl.toLowerCase().startsWith("https://")) {
                throw new SecurityException("Insecure HTTP transport rejected. Only HTTPS is permitted for threat reputation queries.");
            }

            URL url = new URL(endpointUrl);
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(timeoutMs);
            conn.setReadTimeout(timeoutMs);
            conn.setDoOutput(true);
            conn.setInstanceFollowRedirects(false); // Disallow cross-protocol or open redirects
            conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
            conn.setRequestProperty("User-Agent", "GuardianAi-Security-Client/1.0");

            if (headers != null) {
                for (Map.Entry<String, String> entry : headers.entrySet()) {
                    conn.setRequestProperty(entry.getKey(), entry.getValue());
                }
            }

            if (jsonBody != null) {
                byte[] bytes = jsonBody.getBytes(StandardCharsets.UTF_8);
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(bytes);
                    os.flush();
                }
            }

            int code = conn.getResponseCode();
            InputStream is = (code >= 200 && code < 400) ? conn.getInputStream() : conn.getErrorStream();
            String responseBody = "";
            if (is != null) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        sb.append(line).append('\n');
                    }
                    responseBody = sb.toString().trim();
                }
            }

            conn.disconnect();
            return new HttpResponse(code, responseBody, Map.of());
        }

        @Override
        public HttpResponse executeGet(String endpointUrl, Map<String, String> headers, int timeoutMs) throws IOException {
            if (!endpointUrl.toLowerCase().startsWith("https://")) {
                throw new SecurityException("Insecure HTTP transport rejected. Only HTTPS is permitted for threat reputation queries.");
            }

            URL url = new URL(endpointUrl);
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(timeoutMs);
            conn.setReadTimeout(timeoutMs);
            conn.setInstanceFollowRedirects(false);
            conn.setRequestProperty("User-Agent", "GuardianAi-Security-Client/1.0");

            if (headers != null) {
                for (Map.Entry<String, String> entry : headers.entrySet()) {
                    conn.setRequestProperty(entry.getKey(), entry.getValue());
                }
            }

            int code = conn.getResponseCode();
            InputStream is = (code >= 200 && code < 400) ? conn.getInputStream() : conn.getErrorStream();
            String responseBody = "";
            if (is != null) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        sb.append(line).append('\n');
                    }
                    responseBody = sb.toString().trim();
                }
            }

            conn.disconnect();
            return new HttpResponse(code, responseBody, Map.of());
        }
    }
}
