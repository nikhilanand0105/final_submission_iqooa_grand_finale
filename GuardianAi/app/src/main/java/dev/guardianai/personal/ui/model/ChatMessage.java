package dev.guardianai.personal.ui.model;

import java.util.Date;

public class ChatMessage {
    public final boolean isUser;
    public final String text;
    public final Date timestamp;
    public final String badge; // e.g., "AI Guardian", "You"

    public ChatMessage(boolean isUser, String text, String badge) {
        this.isUser = isUser;
        this.text = text;
        this.timestamp = new Date();
        this.badge = badge;
    }
}
