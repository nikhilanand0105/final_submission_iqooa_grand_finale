package dev.saathi.help;

/**
 * Truthful lifecycle of a help request. Only ACKNOWLEDGED means a person confirmed it in the recipient app.
 * A server acceptance or a push-message id does not mean anyone has seen the request.
 */
public enum HelpRequestStatus {
    DRAFT("Not sent yet", false),
    CANCELLED("Cancelled", true),
    SENDING("Sending…", false),
    ACCEPTED_BY_SERVER("Received by the Saathi server — not seen by anyone yet", false),
    NOTIFICATION_QUEUED("Notification sent to their phone — not seen yet", false),
    ACKNOWLEDGED("Your adult opened it and pressed 'I've seen this'", true),
    FAILED("Not sent", true),
    DELIVERY_UNKNOWN("We don't know if it was sent", false);

    private final String childLabel;
    private final boolean terminal;

    HelpRequestStatus(String childLabel, boolean terminal) {
        this.childLabel = childLabel;
        this.terminal = terminal;
    }

    public String childLabel() { return childLabel; }

    public boolean isTerminal() { return terminal; }

    /** Server status string -> enum. Unknown values map to DELIVERY_UNKNOWN, never to a success state. */
    public static HelpRequestStatus fromServer(String s) {
        if (s == null) return DELIVERY_UNKNOWN;
        switch (s) {
            case "accepted": return ACCEPTED_BY_SERVER;
            case "notification_queued": return NOTIFICATION_QUEUED;
            case "notification_failed": return ACCEPTED_BY_SERVER;
            case "acknowledged": return ACKNOWLEDGED;
            case "cancelled": return CANCELLED;
            default: return DELIVERY_UNKNOWN;
        }
    }
}
