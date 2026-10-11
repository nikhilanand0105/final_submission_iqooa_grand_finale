package dev.saathi.kids.ui.components;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import dev.saathi.kids.safety.SupportResources;
import dev.saathi.kids.storage.SafetyEventStore;
import dev.saathi.kids.ui.Ui;
import dev.saathi.safety.FlagEngine;
import dev.saathi.safety.SafetyEvent;

import java.text.DateFormat;
import java.util.Date;
import java.util.List;

/** Shows the two safety flags, the stored events behind them, and one event in detail with next steps. */
public class SafetyEventsOverlay {

    public interface Host {
        void dismissOverlay();
        void showSosFlow();
    }

    private final Activity activity;
    private final FrameLayout container;
    private final Host host;
    private final SafetyEventStore store;
    private String openEventId;

    public SafetyEventsOverlay(Activity activity, FrameLayout container, Host host) {
        this.activity = activity;
        this.container = container;
        this.host = host;
        this.store = SafetyEventStore.get(activity);
    }

    public void showList() {
        openEventId = null;
        container.setVisibility(View.VISIBLE);
        render();
    }

    public void showEvent(String id) {
        openEventId = id;
        container.setVisibility(View.VISIBLE);
        render();
    }

    /** Back: from detail to list, otherwise close. */
    public boolean onBack() {
        if (openEventId != null) {
            openEventId = null;
            render();
            return true;
        }
        return false;
    }

    private void render() {
        container.removeAllViews();
        ScrollView sv = new ScrollView(activity);
        sv.setBackgroundColor(Ui.BG);
        LinearLayout root = new LinearLayout(activity);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(Ui.dp(activity, 22), Ui.dp(activity, 30), Ui.dp(activity, 22), Ui.dp(activity, 36));
        sv.addView(root);
        LinearLayout top = Ui.row(activity);
        top.addView(Ui.text(activity, openEventId == null ? "Safety alerts" : "Alert details", 22f, Ui.INK, true), Ui.weight(1f));
        Button close = new Button(activity);
        close.setText("✕");
        close.setBackgroundColor(Color.TRANSPARENT);
        close.setOnClickListener(v -> host.dismissOverlay());
        top.addView(close);
        root.addView(top);
        SafetyEvent e = openEventId == null ? null : store.byId(openEventId);
        if (openEventId != null && e == null) root.addView(Ui.body(activity, "This alert is no longer saved on this phone."));
        else if (e != null) detail(root, e);
        else list(root);
        container.addView(sv);
    }

    private void list(LinearLayout root) {
        root.addView(flagCard(SafetyEvent.Flag.THREATS, "⚠️ Threats", "Blackmail, threats, or pressure to pay or share codes or photos"));
        root.addView(flagCard(SafetyEvent.Flag.SELF_HARM, "💚 Feeling unsafe or very sad", "Messages or searches that sound like someone may want to hurt themselves"));
        List<SafetyEvent> all = store.all();
        TextView h = Ui.text(activity, "Recent alerts", 14f, Ui.INK, true);
        h.setPadding(0, Ui.dp(activity, 12), 0, Ui.dp(activity, 6));
        root.addView(h);
        if (all.isEmpty()) root.addView(Ui.body(activity, "No alerts saved. Saathi only saves something here when it finds a concern."));
        DateFormat df = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT);
        int n = 0;
        for (SafetyEvent e : all) {
            if (n++ == 50) break;
            Button b = Ui.secondary(activity, title(e) + "\n" + df.format(new Date(e.updatedAt)) + " • " + where(e)
                    + (e.review == SafetyEvent.Review.NEW ? "" : " • " + e.review.name().toLowerCase()), v -> showEvent(e.eventId));
            b.setGravity(Gravity.START | Gravity.CENTER_VERTICAL);
            b.setTextSize(12.5f);
            root.addView(b);
        }
        if (!store.isHealthy()) root.addView(Ui.text(activity, "Saathi couldn't save some results on this phone.", 12f, Ui.RED, true));
        root.addView(Ui.note(activity, "Alerts are kept on this phone for 30 days. They are not sent to anyone unless you choose to ask for help."));
    }

    private View flagCard(SafetyEvent.Flag f, String name, String what) {
        FlagEngine.FlagState st = store.flag(f);
        LinearLayout c = Ui.vcard(activity);
        c.addView(Ui.text(activity, name, 15f, Ui.INK, true));
        c.addView(Ui.note(activity, what));
        String label;
        int color;
        switch (st.level) {
            case ACTIVE: label = "Raised — " + st.openEvents + " alert(s) to look at"; color = f == SafetyEvent.Flag.SELF_HARM ? Ui.GREEN : Ui.RED; break;
            case NEEDS_REVIEW: label = "Something may need a second look (" + st.openEvents + ")"; color = Ui.AMBER; break;
            default: label = "Not raised"; color = Ui.FAINT; break;
        }
        c.addView(Ui.text(activity, label, 13f, color, true));
        List<String[]> hist = store.flagHistory(f);
        if (!hist.isEmpty()) {
            String[] last = hist.get(0);
            c.addView(Ui.note(activity, "Last change: " + last[1].toLowerCase().replace('_', ' ') + " on "
                    + DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(new Date(Long.parseLong(last[3])))));
        }
        return c;
    }

    private void detail(LinearLayout root, SafetyEvent e) {
        boolean selfHarm = e.flag == SafetyEvent.Flag.SELF_HARM;
        LinearLayout c = Ui.vcard(activity);
        if (selfHarm) c.setBackground(Ui.card(activity, Color.parseColor("#EAF3ED"), Color.parseColor("#CFE3D7"), 16));
        c.addView(Ui.text(activity, title(e), 16f, Ui.INK, true));
        c.addView(Ui.note(activity, where(e) + " • " + DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(new Date(e.createdAt))));
        if (selfHarm) {
            c.addView(Ui.body(activity, e.sourceType == dev.saathi.safety.SafetyTypes.SourceType.NOTIFICATION
                    ? "A message you received sounded like someone is going through something really hard. If it's about you or a friend, you don't have to handle it alone."
                    : "It sounds like things might be really hard right now. You don't have to handle this alone."));
        }
        if (!e.explanation.isEmpty()) c.addView(Ui.body(activity, e.explanation));
        if (!e.evidence.isEmpty()) {
            c.addView(Ui.text(activity, "What Saathi noticed:", 12.5f, Ui.AMBER, true));
            for (String ev : e.evidence) c.addView(Ui.body(activity, "“" + ev + "”"));
        }
        if (!e.actions.isEmpty()) {
            c.addView(Ui.text(activity, "What you can do:", 12.5f, Ui.GREEN, true));
            for (String a : e.actions) c.addView(Ui.body(activity, "✔ " + a));
        }
        c.addView(Ui.note(activity, "Checked by: " + e.analysisSource.label()
                + (e.status == dev.saathi.safety.SafetyTypes.Status.NEEDS_REVIEW ? " • Saathi isn't sure — this needs a person to look at it" : "")
                + (e.confidence != null ? " • confidence " + e.confidence.toLowerCase() : "")));
        c.addView(Ui.note(activity, "Alert: " + alertLabel(e.alert)));
        c.addView(Ui.note(activity, "This is a warning sign, not proof about any person."));
        root.addView(c);

        root.addView(Ui.primary(activity, "Ask a trusted adult for help", v -> host.showSosFlow()));
        if (selfHarm) {
            root.addView(Ui.secondary(activity, "📞 " + SupportResources.TELE_MANAS_LABEL, v -> dial(SupportResources.TELE_MANAS_NUMBER)));
            root.addView(Ui.secondary(activity, "📞 " + SupportResources.EMERGENCY_LABEL, v -> dial(SupportResources.EMERGENCY_NUMBER)));
            root.addView(Ui.note(activity, SupportResources.SOURCE_NOTE + " Saathi is not a replacement for a person or emergency help."));
        }
        if (e.review == SafetyEvent.Review.NEW) {
            root.addView(Ui.secondary(activity, "I've looked at this", v -> {
                store.setReview(e.eventId, SafetyEvent.Review.REVIEWED);
                render();
            }));
            root.addView(Ui.secondary(activity, "This wasn't a problem", v -> {
                store.setReview(e.eventId, SafetyEvent.Review.DISMISSED);
                render();
            }));
        }
        root.addView(Ui.secondary(activity, "← All alerts", v -> {
            openEventId = null;
            render();
        }));
    }

    private void dial(String n) {
        try {
            activity.startActivity(new Intent(Intent.ACTION_DIAL, Uri.parse("tel:" + n)));
        } catch (ActivityNotFoundException ignored) {
            // no dialer
        }
    }

    static String title(SafetyEvent e) {
        boolean review = e.level == SafetyEvent.Level.NEEDS_REVIEW;
        switch (e.category) {
            case THREAT: return review ? "A message may need a second look" : "A message looks like a threat";
            case SELF_HARM: return review ? "A message mentioned self-harm" : "Something sounded really hard";
            case SCAM: return "A message has scam warning signs";
            case WEBSITE: return "A website may be fake or dangerous";
            case AGE_SUITABILITY: return "A website may not be right for kids";
            default: return "Some messages couldn't be checked";
        }
    }

    static String where(SafetyEvent e) {
        switch (e.sourceType) {
            case NOTIFICATION: return e.sourceApp.isEmpty() ? "Notification" : "Notification from " + e.sourceApp;
            case MANUAL_MESSAGE: return "Your message check";
            case MANUAL_LINK: return "Your link check";
            case BROWSER_SEARCH: return "Safe Browser search";
            default: return e.sourceApp.isEmpty() ? "Safe Browser" : "Safe Browser • " + e.sourceApp;
        }
    }

    static String alertLabel(SafetyEvent.Alert a) {
        switch (a) {
            case DELIVERED: return "notification sent to Android (Android decides how it's shown)";
            case SHOWN_IN_APP: return "shown in Saathi";
            case NOT_PERMITTED: return "not shown — notifications are turned off for Saathi";
            case FAILED: return "couldn't be shown";
            case PENDING: return "being sent";
            case NOT_NEEDED: return "no alert needed";
            default: return "unknown";
        }
    }
}
