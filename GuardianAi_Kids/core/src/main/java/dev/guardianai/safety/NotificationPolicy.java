package dev.guardianai.safety;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Which posted notifications are analysed, and what text is taken from them. Documented policy:
 * - only text Android exposes in the notification (title, text, big text, messaging-style lines);
 * - skipped: GuardianAi's own notifications, ongoing/foreground/non-clearable ones, group summaries, system UI, and
 *   categories that carry no message text (progress, transport, alarm, call, navigation, service, status, stopwatch);
 * - redacted/hidden previews are recorded as "content unavailable", never guessed.
 */
public final class NotificationPolicy {

    /** Plain data copied from a StatusBarNotification by the Android service (keeps this class testable). */
    public static final class Input {
        public String packageName = "";
        public String key = "";
        public boolean ongoing, clearable = true, groupSummary;
        public String category;
        public String title, text, bigText, subText;
        public List<String> messageLines = new ArrayList<>(); // "Sender: text" from MessagingStyle, oldest first
    }

    public enum Decision { ANALYSE, SKIP, CONTENT_UNAVAILABLE }

    public static final class Result {
        public final Decision decision;
        public final String reason;
        public final List<String> lines; // content lines to consider (before delta filtering)

        Result(Decision d, String r, List<String> lines) {
            decision = d;
            reason = r;
            this.lines = lines;
        }
    }

    private static final Set<String> SKIP_CATEGORIES = new HashSet<>(Arrays.asList(
            "progress", "transport", "alarm", "call", "navigation", "service", "status", "sys", "stopwatch", "location_sharing",
            "workout", "missed_call", "car_emergency", "car_warning"));

    private static final Set<String> SKIP_PACKAGES = new HashSet<>(Arrays.asList(
            "android", "com.android.systemui", "com.android.providers.downloads", "com.android.vending", "com.google.android.gms"));

    private static final Pattern REDACTED = Pattern.compile(
            "(?i)^(?:contents? hidden|sensitive notification content hidden|new messages?|\\d+ new messages?|message|notification"
                    + "|you have (?:a )?new messages?|tap to view|hidden|\\u2022+|\\*+)$");

    private NotificationPolicy() {}

    public static Result evaluate(Input n, String ownPackage) {
        if (n.packageName.equals(ownPackage)) return skip("GuardianAi's own notification");
        if (SKIP_PACKAGES.contains(n.packageName)) return skip("System notification");
        if (n.ongoing || !n.clearable) return skip("Ongoing or system-pinned notification");
        if (n.groupSummary) return skip("Group summary (individual messages are checked instead)");
        if (n.category != null && SKIP_CATEGORIES.contains(n.category.toLowerCase(Locale.ROOT))) return skip("Category without message text");

        List<String> lines = new ArrayList<>();
        if (!n.messageLines.isEmpty()) {
            for (String l : n.messageLines) if (usable(l)) lines.add(l.trim());
        } else {
            String body = usable(n.bigText) ? n.bigText : n.text;
            if (usable(body)) lines.add(body.trim());
        }
        if (lines.isEmpty()) {
            boolean hadSomething = usable(n.title) || n.text != null || n.bigText != null;
            return new Result(hadSomething ? Decision.CONTENT_UNAVAILABLE : Decision.SKIP,
                    hadSomething ? "The notification didn't show the message text" : "No text", Collections.<String>emptyList());
        }
        return new Result(Decision.ANALYSE, "", lines);
    }

    private static boolean usable(String s) {
        if (s == null) return false;
        String t = s.trim();
        if (t.isEmpty()) return false;
        String body = t.contains(": ") ? t.substring(t.indexOf(": ") + 2) : t;
        return !REDACTED.matcher(t).matches() && !REDACTED.matcher(body).matches();
    }

    private static Result skip(String why) {
        return new Result(Decision.SKIP, why, Collections.<String>emptyList());
    }

    /**
     * Remembers recently analysed lines per notification key so rapid repeated updates of a conversation notification
     * within a short cooldown only analyse new lines, while distinct repeated events after cooldown are analysed.
     * Bounded LRU; in memory only (content is never persisted).
     */
    public static final class DeltaTracker {
        public static final long COOLDOWN_MS = 5000L;
        private final int maxKeys;

        private static final class Entry {
            long lastSeenMs;
            final Set<String> lines = new HashSet<>();
        }

        private final Map<String, Entry> seen;

        public DeltaTracker(int maxKeys) {
            this.maxKeys = maxKeys;
            this.seen = new LinkedHashMap<String, Entry>(16, 0.75f, true) {
                @Override protected boolean removeEldestEntry(Map.Entry<String, Entry> e) { return size() > DeltaTracker.this.maxKeys; }
            };
        }

        /** Returns the lines not seen before for this key, and records them. */
        public synchronized List<String> newLines(String key, List<String> lines) {
            return newLines(key, lines, System.currentTimeMillis());
        }

        public synchronized List<String> newLines(String key, List<String> lines, long now) {
            Entry e = seen.get(key);
            if (e == null) {
                e = new Entry();
                seen.put(key, e);
            }
            boolean expired = (now - e.lastSeenMs) >= COOLDOWN_MS;
            e.lastSeenMs = now;
            if (expired) {
                e.lines.clear();
            }
            List<String> out = new ArrayList<>();
            for (String l : lines) {
                if (e.lines.add(l)) out.add(l);
            }
            if (e.lines.size() > 200) e.lines.clear(); // bound memory for very long conversations
            return out;
        }

        public synchronized void forget(String key) {
            seen.remove(key);
        }
    }
}
