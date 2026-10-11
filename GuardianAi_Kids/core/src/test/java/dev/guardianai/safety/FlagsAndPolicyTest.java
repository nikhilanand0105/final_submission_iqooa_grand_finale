package dev.guardianai.safety;

import dev.guardianai.ai.explain.ModelState;
import dev.guardianai.safety.SafetyEvent.Flag;
import dev.guardianai.safety.SafetyEvent.Level;
import dev.guardianai.safety.SafetyEvent.Review;
import dev.guardianai.safety.SafetyTypes.SourceType;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class FlagsAndPolicyTest {

    private final SafetyPipeline rulesOnly = new SafetyPipeline(null);

    private SafetyClassification classify(String s) {
        return rulesOnly.analyze(SourceType.NOTIFICATION, s, null, null).classification;
    }

    // ---------------- flags, dedupe, alerts ----------------

    @Test
    void threatAndSelfHarmLevelsAndAlerts() {
        FlagEngine.Decision t = FlagEngine.decide(classify("Send me 5000 rupees or I'll post your photos everywhere"), "NOT_AVAILABLE",
                SourceType.NOTIFICATION, "Chat", "k1", null, 1000);
        assertEquals(Flag.THREATS, t.event.flag);
        assertEquals(Level.ACTIVE, t.event.level);
        assertEquals(FlagEngine.AlertKind.THREAT_ALERT, t.alert);
        assertEquals(SafetyEvent.Alert.PENDING, t.event.alert);
        assertTrue(t.event.evidence.size() <= SafetyEvent.MAX_EVIDENCE);

        FlagEngine.Decision s = FlagEngine.decide(classify("I want to die, nobody cares about me"), "NOT_AVAILABLE",
                SourceType.NOTIFICATION, "Chat", "k2", null, 1000);
        assertEquals(Flag.SELF_HARM, s.event.flag);
        assertEquals(FlagEngine.AlertKind.SELF_HARM_SUPPORT, s.alert);

        FlagEngine.Decision low = FlagEngine.decide(classify("I'm going to kill you in the next round 😂"), "NOT_AVAILABLE",
                SourceType.NOTIFICATION, "Game", "k3", null, 1000);
        assertEquals(Level.NEEDS_REVIEW, low.event.level);
        assertEquals(FlagEngine.AlertKind.REVIEW_NOTICE, low.alert);

        assertNull(FlagEngine.decide(classify("Research project on suicide prevention statistics"), "", SourceType.NOTIFICATION, "a", "k4", null, 1).event,
                "educational content raises no flag and stores nothing");
    }

    @Test
    void duplicatesUpdateWithoutRepeatAlertButEscalationAlerts() {
        SafetyClassification c = classify("If you don't send more pics I will share your chats with your school");
        String key = FlagEngine.dedupeKey(SourceType.NOTIFICATION, "Chat", "same text");
        assertEquals(key, FlagEngine.dedupeKey(SourceType.NOTIFICATION, "Chat", "  SAME   text "));
        assertNotEquals(key, FlagEngine.dedupeKey(SourceType.NOTIFICATION, "Other", "same text"));
        FlagEngine.Decision first = FlagEngine.decide(c, "", SourceType.NOTIFICATION, "Chat", key, null, 1000);
        FlagEngine.Decision again = FlagEngine.decide(c, "", SourceType.NOTIFICATION, "Chat", key, first.event.withAlert(SafetyEvent.Alert.DELIVERED, 1001), 2000);
        assertTrue(again.isUpdate);
        assertEquals(first.event.eventId, again.event.eventId);
        assertEquals(FlagEngine.AlertKind.NONE, again.alert);
        assertEquals(SafetyEvent.Alert.DELIVERED, again.event.alert);

        SafetyClassification weak = classify("I'm going to kill you in the next round 😂");
        FlagEngine.Decision w = FlagEngine.decide(weak, "", SourceType.NOTIFICATION, "Chat", "kw", null, 1000);
        SafetyClassification strong = classify("I know where you live. I'll hurt you if you tell anyone");
        FlagEngine.Decision esc = FlagEngine.decide(strong, "", SourceType.NOTIFICATION, "Chat", "kw", w.event, 2000);
        assertEquals(w.event.eventId, esc.event.eventId);
        assertEquals(FlagEngine.AlertKind.THREAT_ALERT, esc.alert, "new stronger evidence alerts once");

        FlagEngine.Decision later = FlagEngine.decide(c, "", SourceType.NOTIFICATION, "Chat", key, first.event, 1000 + FlagEngine.DEDUPE_WINDOW_MS + 1);
        assertFalse(later.isUpdate, "outside the window it is a new event");
    }

    @Test
    void flagStateFromEventsAndReview() {
        SafetyEvent a = FlagEngine.decide(classify("Send me 5000 rupees or I'll post your photos everywhere"), "", SourceType.NOTIFICATION, "x", "a", null, 10).event;
        SafetyEvent b = FlagEngine.decide(classify("I'm going to kill you in the next round 😂"), "", SourceType.NOTIFICATION, "x", "b", null, 20).event;
        SafetyEvent c = FlagEngine.decide(classify("I want to die, nobody cares about me"), "", SourceType.NOTIFICATION, "x", "c", null, 30).event;
        List<SafetyEvent> all = new ArrayList<>(Arrays.asList(a, b, c));
        assertEquals(Level.ACTIVE, FlagEngine.compute(Flag.THREATS, all).level);
        assertEquals(2, FlagEngine.compute(Flag.THREATS, all).openEvents);
        assertEquals(Level.ACTIVE, FlagEngine.compute(Flag.SELF_HARM, all).level);
        all.set(0, a.withReview(Review.REVIEWED, 40));
        assertEquals(Level.NEEDS_REVIEW, FlagEngine.compute(Flag.THREATS, all).level, "reviewing the active event lowers the flag");
        all.set(1, b.withReview(Review.DISMISSED, 50));
        assertEquals(Level.CLEAR, FlagEngine.compute(Flag.THREATS, all).level);
        assertEquals(Level.ACTIVE, FlagEngine.compute(Flag.SELF_HARM, all).level, "flags are independent");
        assertEquals(Level.CLEAR, FlagEngine.compute(Flag.SELF_HARM, new ArrayList<SafetyEvent>()).level);
    }

    @Test
    void unavailableAnalysisIsRecordedNotSafe() {
        SafetyClassification u = SafetyClassification.unavailable(SourceType.NOTIFICATION, SafetyTypes.Status.UNAVAILABLE, "queue full");
        FlagEngine.Decision d = FlagEngine.decide(u, "", SourceType.NOTIFICATION, "Chat", "u", null, 1);
        assertEquals(SafetyEvent.Category.UNAVAILABLE, d.event.category);
        assertEquals(Flag.NONE, d.event.flag);
    }

    @Test
    void evidenceIsTrimmed() {
        SafetyEvent e = new SafetyEvent("id", "k", 1, 1, SourceType.NOTIFICATION, "a", SafetyEvent.Category.THREAT, Flag.THREATS, Level.ACTIVE,
                "HIGH", "HIGH", SafetyTypes.Status.COMPLETE, SafetyTypes.Source.RULES_FALLBACK, "", Arrays.asList(
                "x".repeat(300), "second", "third"), "e", null, Review.NEW, SafetyEvent.Alert.PENDING);
        assertEquals(2, e.evidence.size());
        assertTrue(e.evidence.get(0).length() <= SafetyEvent.MAX_EVIDENCE_CHARS + 1);
    }

    // ---------------- notification policy ----------------

    private static NotificationPolicy.Input n(String pkg, String title, String text) {
        NotificationPolicy.Input i = new NotificationPolicy.Input();
        i.packageName = pkg;
        i.title = title;
        i.text = text;
        i.key = pkg + "|1";
        return i;
    }

    @Test
    void notificationEligibility() {
        assertEquals(NotificationPolicy.Decision.SKIP, NotificationPolicy.evaluate(n("dev.guardianai.kids", "x", "y"), "dev.guardianai.kids").decision);
        NotificationPolicy.Input ongoing = n("com.music", "Song", "Playing");
        ongoing.ongoing = true;
        assertEquals(NotificationPolicy.Decision.SKIP, NotificationPolicy.evaluate(ongoing, "dev.guardianai.kids").decision);
        NotificationPolicy.Input summary = n("com.chat", "Chat", "3 new messages");
        summary.groupSummary = true;
        assertEquals(NotificationPolicy.Decision.SKIP, NotificationPolicy.evaluate(summary, "dev.guardianai.kids").decision);
        NotificationPolicy.Input progress = n("com.dl", "Downloading", "45%");
        progress.category = "progress";
        assertEquals(NotificationPolicy.Decision.SKIP, NotificationPolicy.evaluate(progress, "dev.guardianai.kids").decision);

        NotificationPolicy.Result ok = NotificationPolicy.evaluate(n("com.chat", "Ravi", "send the otp now"), "dev.guardianai.kids");
        assertEquals(NotificationPolicy.Decision.ANALYSE, ok.decision);
        assertEquals(Arrays.asList("send the otp now"), ok.lines);

        NotificationPolicy.Input big = n("com.chat", "Ravi", "short preview");
        big.bigText = "short preview and the full longer message text";
        assertEquals("short preview and the full longer message text", NotificationPolicy.evaluate(big, "x").lines.get(0));
    }

    @Test
    void redactedOrMissingContentIsUnavailable() {
        for (String hidden : new String[]{"Contents hidden", "New message", "2 new messages", "Sensitive notification content hidden"}) {
            NotificationPolicy.Result r = NotificationPolicy.evaluate(n("com.chat", "Chat", hidden), "dev.guardianai.kids");
            assertEquals(NotificationPolicy.Decision.CONTENT_UNAVAILABLE, r.decision, hidden);
        }
        assertEquals(NotificationPolicy.Decision.CONTENT_UNAVAILABLE, NotificationPolicy.evaluate(n("com.chat", "Ravi", null), "x").decision);
        assertEquals(NotificationPolicy.Decision.SKIP, NotificationPolicy.evaluate(n("com.chat", null, null), "x").decision);
    }

    @Test
    void messagingStyleAndDeltaTracking() {
        NotificationPolicy.Input m = n("com.chat", "Group", "2 messages");
        m.messageLines.add("Ravi: hi");
        m.messageLines.add("Ravi: send pics or else");
        NotificationPolicy.Result r = NotificationPolicy.evaluate(m, "x");
        assertEquals(2, r.lines.size());
        NotificationPolicy.DeltaTracker d = new NotificationPolicy.DeltaTracker(2);
        assertEquals(2, d.newLines("k", r.lines).size());
        List<String> updated = new ArrayList<>(r.lines);
        updated.add("Ravi: last warning");
        assertEquals(Arrays.asList("Ravi: last warning"), d.newLines("k", updated), "updates only analyse new lines");
        assertTrue(d.newLines("k", updated).isEmpty(), "exact repeat within cooldown is a duplicate");
        d.newLines("a", Arrays.asList("x"));
        d.newLines("b", Arrays.asList("y"));
        assertEquals(3, d.newLines("k", updated).size(), "bounded LRU forgot the oldest key");

        // Cooldown expiration allows repeated notification messages to be re-analysed
        NotificationPolicy.DeltaTracker cd = new NotificationPolicy.DeltaTracker(5);
        List<String> msg = Arrays.asList("Urgent threat message");
        assertEquals(1, cd.newLines("k1", msg, 1000).size());
        assertTrue(cd.newLines("k1", msg, 2000).isEmpty(), "rapid repost within 5s cooldown is suppressed");
        assertEquals(1, cd.newLines("k1", msg, 2000 + NotificationPolicy.DeltaTracker.COOLDOWN_MS + 100).size(),
                "after cooldown expires, repeated notification line is returned for analysis");
    }

    @Test
    void repeatedThreatsAndSelfHarmAlertEveryTime() {
        // Problem B regression test: verify subsequent threat and self-harm events trigger alerts
        long t0 = 1000;
        String key1 = FlagEngine.dedupeKey(SourceType.NOTIFICATION, "Chat", "threat one");
        String key2 = FlagEngine.dedupeKey(SourceType.NOTIFICATION, "Chat", "threat two");

        SafetyClassification c1 = classify("Send me 50000 rupees or I will hurt you");
        SafetyClassification c2 = classify("I know where you live. I will hurt you if you tell anyone");
        SafetyClassification sh1 = classify("I want to die, nobody cares about me");
        SafetyClassification sh2 = classify("I have no reason to live anymore, goodbye");

        // Event 1: First threat
        FlagEngine.Decision d1 = FlagEngine.decide(c1, "NOT_AVAILABLE", SourceType.NOTIFICATION, "Chat", key1, null, t0);
        assertEquals(FlagEngine.AlertKind.THREAT_ALERT, d1.alert);
        assertEquals(Level.ACTIVE, d1.event.level);
        assertFalse(d1.isUpdate);

        // Event 2: Second distinct threat
        FlagEngine.Decision d2 = FlagEngine.decide(c2, "NOT_AVAILABLE", SourceType.NOTIFICATION, "Chat", key2, null, t0 + 5000);
        assertEquals(FlagEngine.AlertKind.THREAT_ALERT, d2.alert, "second distinct threat must trigger alert");
        assertEquals(Level.ACTIVE, d2.event.level);
        assertNotEquals(d1.event.eventId, d2.event.eventId);
        assertFalse(d2.isUpdate);

        // Event 3: Rapid duplicate of event 2 within cooldown window (15s) -> suppressed
        FlagEngine.Decision d2dup = FlagEngine.decide(c2, "NOT_AVAILABLE", SourceType.NOTIFICATION, "Chat", key2, d2.event, t0 + 6000);
        assertTrue(d2dup.isUpdate);
        assertEquals(FlagEngine.AlertKind.NONE, d2dup.alert, "rapid OS repost within 15s cooldown does not trigger repeat alert");

        // Event 4: Repeated threat with same text as Event 1 AFTER cooldown window (>15s) -> triggers alert!
        FlagEngine.Decision d3 = FlagEngine.decide(c1, "NOT_AVAILABLE", SourceType.NOTIFICATION, "Chat", key1, d1.event,
                t0 + FlagEngine.RAPID_DUPLICATE_COOLDOWN_MS + 1000);
        assertFalse(d3.isUpdate, "repeated event after cooldown is treated as a distinct event");
        assertEquals(FlagEngine.AlertKind.THREAT_ALERT, d3.alert, "repeated threat after cooldown must trigger alert");
        assertNotEquals(d1.event.eventId, d3.event.eventId);

        // Verify FlagState computes all open events
        List<SafetyEvent> threatEvents = Arrays.asList(d1.event, d2.event, d3.event);
        FlagEngine.FlagState st = FlagEngine.compute(Flag.THREATS, threatEvents);
        assertEquals(Level.ACTIVE, st.level);
        assertEquals(3, st.openEvents, "all 3 distinct threat events must be open and counted");

        // Repeated Self-Harm events
        FlagEngine.Decision shD1 = FlagEngine.decide(sh1, "NOT_AVAILABLE", SourceType.NOTIFICATION, "Chat", "sh1", null, t0);
        assertEquals(FlagEngine.AlertKind.SELF_HARM_SUPPORT, shD1.alert);
        FlagEngine.Decision shD2 = FlagEngine.decide(sh2, "NOT_AVAILABLE", SourceType.NOTIFICATION, "Chat", "sh2", null, t0 + 5000);
        assertEquals(FlagEngine.AlertKind.SELF_HARM_SUPPORT, shD2.alert, "second self-harm event must trigger alert");

        // Interleaved flags remain independent
        List<SafetyEvent> allEvents = new ArrayList<>(threatEvents);
        allEvents.add(shD1.event);
        allEvents.add(shD2.event);
        assertEquals(3, FlagEngine.compute(Flag.THREATS, allEvents).openEvents);
        assertEquals(2, FlagEngine.compute(Flag.SELF_HARM, allEvents).openEvents);
    }

    // ---------------- monitoring status ----------------

    @Test
    void monitoringStatusIsDerivedFromRealInputs() {
        MonitoringStatus.Inputs in = new MonitoringStatus.Inputs();
        assertEquals(MonitoringStatus.Overall.PERMISSION_REQUIRED, MonitoringStatus.compute(in).overall);
        assertEquals(MonitoringStatus.CapState.PERMISSION_REQUIRED, MonitoringStatus.compute(in).item(MonitoringStatus.Capability.NOTIFICATION_MONITORING).state);
        in.notificationAccessGranted = true;
        assertEquals(MonitoringStatus.Overall.MONITORING_INTERRUPTED, MonitoringStatus.compute(in).overall);
        in.listenerConnected = true;
        assertEquals(MonitoringStatus.Overall.PARTIALLY_ACTIVE, MonitoringStatus.compute(in).overall);
        in.postNotificationsAllowed = true;
        MonitoringStatus s = MonitoringStatus.compute(in);
        assertEquals(MonitoringStatus.Overall.ACTIVE, s.overall);
        assertEquals(MonitoringStatus.CapState.MODEL_NOT_INSTALLED, s.item(MonitoringStatus.Capability.GEMMA_MODEL).state);
        assertEquals(MonitoringStatus.CapState.NOT_IMPLEMENTED, s.item(MonitoringStatus.Capability.NETWORK_PROTECTION).state);
        in.modelState = ModelState.READY;
        assertEquals(MonitoringStatus.CapState.MODEL_READY, MonitoringStatus.compute(in).item(MonitoringStatus.Capability.GEMMA_MODEL).state);
        in.modelState = ModelState.RESOURCE_CONSTRAINED;
        assertEquals(MonitoringStatus.CapState.FALLBACK_ACTIVE, MonitoringStatus.compute(in).item(MonitoringStatus.Capability.GEMMA_MODEL).state);
        in.pendingAnalyses = 3;
        assertEquals(MonitoringStatus.CapState.ANALYSIS_PENDING, MonitoringStatus.compute(in).item(MonitoringStatus.Capability.NOTIFICATION_MONITORING).state);
        in.storageHealthy = false;
        assertEquals(MonitoringStatus.Overall.PROTECTION_UNAVAILABLE, MonitoringStatus.compute(in).overall);
        in.notificationAccessGranted = false; // revoked
        in.storageHealthy = true;
        assertEquals(MonitoringStatus.Overall.PERMISSION_REQUIRED, MonitoringStatus.compute(in).overall);
    }
}
