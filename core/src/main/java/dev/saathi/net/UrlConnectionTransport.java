package dev.saathi.net;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * HttpURLConnection-backed transport. Refuses non-HTTPS URLs and caps response size.
 * Never logs URLs or bodies.
 */
public class UrlConnectionTransport implements HttpTransport {

    private static final int MAX_RESPONSE_BYTES = 256 * 1024;

    @Override
    public Response execute(String method, String url, Map<String, String> headers, String body, int timeoutMillis)
            throws TimeoutException, NetworkException {
        if (url == null || !url.startsWith("https://")) {
            throw new NetworkException("Only HTTPS endpoints are allowed");
        }
        HttpURLConnection c = null;
        try {
            c = (HttpURLConnection) URI.create(url).toURL().openConnection();
            c.setRequestMethod(method);
            c.setConnectTimeout(timeoutMillis);
            c.setReadTimeout(timeoutMillis);
            c.setInstanceFollowRedirects(false);
            c.setUseCaches(false);
            if (headers != null) {
                for (Map.Entry<String, String> h : headers.entrySet()) c.setRequestProperty(h.getKey(), h.getValue());
            }
            if (body != null) {
                c.setDoOutput(true);
                byte[] b = body.getBytes(StandardCharsets.UTF_8);
                c.setFixedLengthStreamingMode(b.length);
                try (OutputStream os = c.getOutputStream()) {
                    os.write(b);
                }
            }
            int code = c.getResponseCode();
            InputStream in = code >= 400 ? c.getErrorStream() : c.getInputStream();
            return new Response(code, in == null ? "" : readCapped(in));
        } catch (SocketTimeoutException e) {
            throw new TimeoutException("Request timed out");
        } catch (IOException | IllegalArgumentException e) {
            throw new NetworkException(e.getClass().getSimpleName());
        } finally {
            if (c != null) c.disconnect();
        }
    }

    private static String readCapped(InputStream in) throws IOException {
        try (InputStream is = in) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) != -1) {
                if (out.size() + n > MAX_RESPONSE_BYTES) throw new IOException("response too large");
                out.write(buf, 0, n);
            }
            return new String(out.toByteArray(), StandardCharsets.UTF_8);
        }
    }
}
