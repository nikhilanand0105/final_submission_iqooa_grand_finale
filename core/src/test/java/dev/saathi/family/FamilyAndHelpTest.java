package dev.saathi.family;

import dev.saathi.help.HelpRequest;
import dev.saathi.help.HelpRequestService;
import dev.saathi.help.HelpRequestStatus;
import dev.saathi.net.AuthTokenSource;
import dev.saathi.net.FirebaseAnonymousAuth;
import dev.saathi.net.HttpTransport;
import org.junit.jupiter.api.Test;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

public class FamilyAndHelpTest {

    /** Scripted transport: queue of responses (Response | "TIMEOUT" | "OFFLINE"), records requests. */
    static class Script implements HttpTransport {
        final Deque<Object> q = new ArrayDeque<>();
        final List<String> urls = new ArrayList<>();
        final List<String> bodies = new ArrayList<>();
        final List<Map<String, String>> headers = new ArrayList<>();
        CountDownLatch block;

        Script add(int code, String body) { q.add(new Response(code, body)); return this; }
        Script add(String failure) { q.add(failure); return this; }

        public Response execute(String m, String url, Map<String, String> h, String body, int t) throws TimeoutException, NetworkException {
            urls.add(url);
            bodies.add(body);
            headers.add(h);
            if (block != null) {
                try { block.await(); } catch (InterruptedException ignored) { }
            }
            Object o = q.isEmpty() ? "OFFLINE" : q.poll();
            if ("TIMEOUT".equals(o)) throw new TimeoutException("t");
            if ("OFFLINE".equals(o)) throw new NetworkException("n");
            return (Response) o;
        }
    }

    static class Auth implements AuthTokenSource {
        int invalidations;
        boolean fail;
        public String getIdToken() throws AuthException { if (fail) throw new AuthException("no", true); return "tok" + invalidations; }
        public String getUserId() { return "child-uid"; }
        public void invalidate() { invalidations++; }
    }

    private static BackendClient client(Script s, Auth a) {
        return new BackendClient("https://api.example.test", a, s, 1000);
    }

    // ---------------- pairing ----------------

    @Test
    void codeNormalisation() {
        assertEquals("AB12CD34", PairingService.normalizeCode("ab12-cd34"));
        assertEquals("0011AB2C", PairingService.normalizeCode("OOIL AB2C"));
        assertNull(PairingService.normalizeCode("ABC"));
        assertNull(PairingService.normalizeCode("AB12CD3U"));
        assertNull(PairingService.normalizeCode(null));
        assertNotNull(PairingService.validateDisplayName(""));
        assertNotNull(PairingService.validateDisplayName("<script>"));
        assertNull(PairingService.validateDisplayName("Riya S."));
    }

    @Test
    void invalidCodeNeverHitsServer() {
        Script s = new Script();
        PairingService.RedeemResult r = new PairingService(client(s, new Auth())).redeem("12", "Riya");
        assertFalse(r.ok);
        assertEquals("INVALID_CODE", r.errorCode);
        assertTrue(s.urls.isEmpty());
    }

    @Test
    void successfulRedeemIsPendingUntilAdultConfirms() {
        Script s = new Script().add(200, "{\"status\":\"pending_parent_confirmation\",\"pairingId\":\"p1\",\"familyDisplayName\":\"Sharma family\",\"adults\":[]}");
        PairingService.RedeemResult r = new PairingService(client(s, new Auth())).redeem("ab12-cd34", "Riya");
        assertTrue(r.ok);
        assertEquals(FamilyStatus.State.PENDING_CONFIRMATION, r.status.state);
        assertTrue(r.status.helpRecipients().isEmpty());
        assertEquals("{\"code\":\"AB12CD34\",\"childDisplayName\":\"Riya\"}", s.bodies.get(0));
        assertEquals("Bearer tok0", s.headers.get(0).get("Authorization"));
        assertTrue(s.urls.get(0).endsWith("/pairing/redeem"));
    }

    @Test
    void serverErrorsMapped() {
        String[][] cases = {{"404", "INVALID_CODE"}, {"410", "EXPIRED_CODE"}, {"409", "CODE_USED"}, {"429", "RATE_LIMITED"}};
        for (String[] c : cases) {
            Script s = new Script().add(Integer.parseInt(c[0]), "{\"error\":{\"code\":\"" + c[1] + "\",\"message\":\"x\"}}");
            PairingService.RedeemResult r = new PairingService(client(s, new Auth())).redeem("AB12CD34", "Riya");
            assertFalse(r.ok);
            assertEquals(c[1], r.errorCode);
            assertFalse(r.message.isEmpty());
        }
        Script off = new Script().add("OFFLINE");
        assertEquals("OFFLINE", new PairingService(client(off, new Auth())).redeem("AB12CD34", "Riya").errorCode);
    }

    @Test
    void statusComesFromServerOnly() {
        Script s = new Script()
                .add(200, "{\"status\":\"active\",\"pairingId\":\"p1\",\"familyDisplayName\":\"Sharma family\",\"adults\":[{\"uid\":\"a1\",\"displayName\":\"Mum\",\"canReceiveHelp\":true},{\"uid\":\"a2\",\"displayName\":\"Dad\",\"canReceiveHelp\":false}]}")
                .add(200, "{\"status\":\"revoked\",\"pairingId\":\"p1\"}")
                .add("TIMEOUT")
                .add(200, "{\"status\":\"paired\"}")
                .add(500, "oops");
        PairingService ps = new PairingService(client(s, new Auth()));
        FamilyStatus a = ps.fetchStatus();
        assertEquals(FamilyStatus.State.ACTIVE, a.state);
        assertEquals(1, a.helpRecipients().size());
        assertEquals("a1", a.helpRecipients().get(0).uid);
        FamilyStatus rv = ps.fetchStatus();
        assertEquals(FamilyStatus.State.REVOKED, rv.state);
        assertTrue(rv.helpRecipients().isEmpty());
        assertEquals(FamilyStatus.State.UNREACHABLE, ps.fetchStatus().state);
        assertEquals(FamilyStatus.State.ERROR, ps.fetchStatus().state); // unknown status string is not trusted
        assertEquals(FamilyStatus.State.ERROR, ps.fetchStatus().state);
    }

    @Test
    void notConfigured() {
        PairingService ps = new PairingService(new BackendClient("", new Auth(), new Script(), 1000));
        assertEquals(FamilyStatus.State.NOT_CONFIGURED, ps.fetchStatus().state);
        assertEquals("NOT_CONFIGURED", ps.redeem("AB12CD34", "Riya").errorCode);
    }

    @Test
    void expiredTokenRefreshedOnce() {
        Script s = new Script().add(401, "{\"error\":{\"code\":\"UNAUTHENTICATED\"}}").add(200, "{\"status\":\"none\"}");
        Auth a = new Auth();
        FamilyStatus st = new PairingService(client(s, a)).fetchStatus();
        assertEquals(FamilyStatus.State.NOT_PAIRED, st.state);
        assertEquals(1, a.invalidations);
        assertEquals("Bearer tok1", s.headers.get(1).get("Authorization"));
    }

    // ---------------- help requests ----------------

    private static HelpRequest draft() {
        return HelpRequestService.confirmDraft("a1", "Mum", "unsafe", "  ", HelpRequest.LocationChoice.NOT_SHARED, null, 1L);
    }

    @Test
    void draftValidation() {
        assertThrows(IllegalArgumentException.class, () -> HelpRequestService.confirmDraft("", "x", "unsafe", null, null, null, 1));
        assertThrows(IllegalArgumentException.class, () -> HelpRequestService.confirmDraft("a1", "x", "made_up", null, null, null, 1));
        HelpRequest d = draft();
        assertNull(d.note);
        assertEquals(HelpRequestStatus.DRAFT, d.status);
        assertNotNull(d.idempotencyKey);
        HelpRequest withLoc = HelpRequestService.confirmDraft("a1", "Mum", "unsafe", null, HelpRequest.LocationChoice.PERMISSION_DENIED,
                new HelpRequest.Location(1, 2, 3, 4), 1);
        assertNull(withLoc.location, "location must not be kept unless the child chose to share it");
    }

    @Test
    void acceptedIsNotDelivered() {
        Script s = new Script().add(200, "{\"requestId\":\"r1\",\"status\":\"notification_queued\"}");
        HelpRequest r = new HelpRequestService(client(s, new Auth())).submit(draft());
        assertEquals(HelpRequestStatus.NOTIFICATION_QUEUED, r.status);
        assertEquals("r1", r.serverRequestId);
        assertFalse(r.status.childLabel().toLowerCase().contains("delivered"));
        assertTrue(r.status.childLabel().contains("not seen"));
        assertFalse(s.bodies.get(0).contains("location\":{"), "no location unless shared");
        assertFalse(s.bodies.get(0).contains("note"));
    }

    @Test
    void acknowledgementOnlyFromRecipientState() {
        Script s = new Script()
                .add(200, "{\"requestId\":\"r1\",\"status\":\"accepted\",\"recipientHasDevice\":false}")
                .add(200, "{\"requestId\":\"r1\",\"status\":\"acknowledged\",\"acknowledgedAt\":123}");
        HelpRequestService svc = new HelpRequestService(client(s, new Auth()));
        HelpRequest r = svc.submit(draft());
        assertEquals(HelpRequestStatus.ACCEPTED_BY_SERVER, r.status);
        assertTrue(r.failureReason.contains("hasn't set up notifications"));
        r = svc.refresh(r);
        assertEquals(HelpRequestStatus.ACKNOWLEDGED, r.status);
        assertTrue(s.bodies.get(1).contains("\"requestId\":\"r1\""));
    }

    @Test
    void timeoutIsDeliveryUnknownAndManualRetryReusesKey() {
        Script s = new Script().add("TIMEOUT").add(200, "{\"requestId\":\"r1\",\"status\":\"notification_queued\",\"deduplicated\":true}");
        HelpRequestService svc = new HelpRequestService(client(s, new Auth()));
        HelpRequest d = draft();
        HelpRequest r = svc.submit(d);
        assertEquals(HelpRequestStatus.DELIVERY_UNKNOWN, r.status);
        assertNull(r.serverRequestId);
        HelpRequest r2 = svc.submit(r);
        assertEquals(HelpRequestStatus.NOTIFICATION_QUEUED, r2.status);
        String key = "\"idempotencyKey\":\"" + d.idempotencyKey + "\"";
        assertTrue(s.bodies.get(0).contains(key) && s.bodies.get(1).contains(key));
    }

    @Test
    void offlineAndServerFailures() {
        HelpRequestService off = new HelpRequestService(client(new Script().add("OFFLINE"), new Auth()));
        assertEquals(HelpRequestStatus.FAILED, off.submit(draft()).status);
        HelpRequestService s500 = new HelpRequestService(client(new Script().add(500, "{}"), new Auth()));
        assertEquals(HelpRequestStatus.DELIVERY_UNKNOWN, s500.submit(draft()).status);
        HelpRequestService bad = new HelpRequestService(client(new Script().add(200, "{\"status\":\"accepted\"}"), new Auth()));
        assertEquals(HelpRequestStatus.DELIVERY_UNKNOWN, bad.submit(draft()).status);
        HelpRequestService junk = new HelpRequestService(client(new Script().add(200, "{\"requestId\":\"r\",\"status\":\"delivered\"}"), new Auth()));
        assertEquals(HelpRequestStatus.DELIVERY_UNKNOWN, junk.submit(draft()).status, "unknown server states never become success");
        Auth noAuth = new Auth();
        noAuth.fail = true;
        assertEquals(HelpRequestStatus.FAILED, new HelpRequestService(client(new Script(), noAuth)).submit(draft()).status);
        assertEquals(HelpRequestStatus.FAILED, new HelpRequestService(new BackendClient("", new Auth(), new Script(), 1)).submit(draft()).status);
    }

    @Test
    void recipientAuthorisationAndRevokedPairing() {
        Script s = new Script()
                .add(403, "{\"error\":{\"code\":\"RECIPIENT_NOT_AUTHORIZED\"}}")
                .add(403, "{\"error\":{\"code\":\"PAIRING_REVOKED\"}}");
        HelpRequestService svc = new HelpRequestService(client(s, new Auth()));
        HelpRequest a = svc.submit(draft());
        assertEquals(HelpRequestStatus.FAILED, a.status);
        assertTrue(a.failureReason.contains("can't receive"));
        HelpRequest b = svc.submit(draft());
        assertTrue(b.failureReason.contains("turned off"));
    }

    @Test
    void duplicateTapsSendOnce() throws Exception {
        Script s = new Script().add(200, "{\"requestId\":\"r1\",\"status\":\"accepted\"}");
        s.block = new CountDownLatch(1);
        HelpRequestService svc = new HelpRequestService(client(s, new Auth()));
        HelpRequest d = draft();
        AtomicInteger sends = new AtomicInteger();
        Thread t1 = new Thread(() -> { if (svc.submit(d).status != HelpRequestStatus.DRAFT) sends.incrementAndGet(); });
        t1.start();
        while (s.urls.isEmpty()) Thread.sleep(5);
        HelpRequest second = svc.submit(d);       // while first is in flight
        assertEquals(HelpRequestStatus.DRAFT, second.status);
        s.block.countDown();
        t1.join();
        assertEquals(1, s.urls.size());
        assertEquals(1, sends.get());
    }

    @Test
    void cancellation() {
        HelpRequestService svc = new HelpRequestService(client(new Script().add(200, "{\"requestId\":\"r1\",\"status\":\"cancelled\"}"), new Auth()));
        assertEquals(HelpRequestStatus.CANCELLED, svc.cancel(draft()).status); // local draft: no network
        HelpRequest sent = draft().with(HelpRequestStatus.NOTIFICATION_QUEUED, "r1", null, 2);
        assertEquals(HelpRequestStatus.CANCELLED, svc.cancel(sent).status);
        HelpRequest acked = draft().with(HelpRequestStatus.ACKNOWLEDGED, "r1", null, 2);
        assertEquals(HelpRequestStatus.ACKNOWLEDGED, svc.cancel(acked).status);
        assertEquals(HelpRequestStatus.CANCELLED, svc.submit(draft().with(HelpRequestStatus.CANCELLED, null, null, 3)).status);
    }

    @Test
    void statusCheckForUnknownRequest() {
        Script s = new Script().add(404, "{\"error\":{\"code\":\"NOT_FOUND\"}}");
        HelpRequest unknown = draft().with(HelpRequestStatus.DELIVERY_UNKNOWN, null, null, 2);
        HelpRequest r = new HelpRequestService(client(s, new Auth())).refresh(unknown);
        assertEquals(HelpRequestStatus.FAILED, r.status);
        assertTrue(s.bodies.get(0).contains("idempotencyKey"));
    }

    // ---------------- anonymous auth ----------------

    static class MapStore implements FirebaseAnonymousAuth.Store {
        final Map<String, String> m = new HashMap<>();
        public String get(String k) { return m.get(k); }
        public void put(String k, String v) { m.put(k, v); }
    }

    @Test
    void anonymousAuthSignUpRefreshAndErrors() throws Exception {
        Script s = new Script()
                .add(200, "{\"idToken\":\"id1\",\"refreshToken\":\"rt1\",\"expiresIn\":\"3600\",\"localId\":\"uid1\"}")
                .add(200, "{\"id_token\":\"id2\",\"refresh_token\":\"rt2\",\"expires_in\":\"3600\",\"user_id\":\"uid1\"}");
        MapStore store = new MapStore();
        long[] now = {0};
        FirebaseAnonymousAuth auth = new FirebaseAnonymousAuth("webkey", s, store, () -> now[0]);
        assertEquals("id1", auth.getIdToken());
        assertEquals("uid1", auth.getUserId());
        assertEquals("id1", auth.getIdToken()); // cached
        assertEquals(1, s.urls.size());
        now[0] = 3_600_000;
        assertEquals("id2", auth.getIdToken());
        assertTrue(s.urls.get(1).startsWith("https://securetoken.googleapis.com/v1/token?key=webkey"));
        assertEquals("grant_type=refresh_token&refresh_token=rt1", s.bodies.get(1));
        assertEquals("rt2", store.get("fb_refresh_token"));

        FirebaseAnonymousAuth offline = new FirebaseAnonymousAuth("k", new Script().add("OFFLINE"), new MapStore());
        AuthTokenSource.AuthException e = assertThrows(AuthTokenSource.AuthException.class, offline::getIdToken);
        assertTrue(e.network);
        assertThrows(AuthTokenSource.AuthException.class, () -> new FirebaseAnonymousAuth("", new Script(), new MapStore()).getIdToken());
        FirebaseAnonymousAuth badJson = new FirebaseAnonymousAuth("k", new Script().add(200, "nope"), new MapStore());
        assertFalse(assertThrows(AuthTokenSource.AuthException.class, badJson::getIdToken).network);
    }

    @Test
    void trustedAdultValidation() {
        assertNull(TrustedAdultValidator.validate("Asha Aunty", "Aunt", "+91 98765 43210"));
        assertNull(TrustedAdultValidator.validate("Mr. D'Souza", "", ""));
        assertNotNull(TrustedAdultValidator.validate("", "Aunt", ""));
        assertNotNull(TrustedAdultValidator.validate("A".repeat(41), "", ""));
        assertNotNull(TrustedAdultValidator.validate("<b>x</b>", "", ""));
        assertNotNull(TrustedAdultValidator.validate("Asha", "Aunt", "call me"));
        assertNotNull(TrustedAdultValidator.validate("Asha", "Aunt", "12345"));
        assertEquals("+919876543210", TrustedAdultValidator.dialable("+91 98765-43210"));
    }
}
