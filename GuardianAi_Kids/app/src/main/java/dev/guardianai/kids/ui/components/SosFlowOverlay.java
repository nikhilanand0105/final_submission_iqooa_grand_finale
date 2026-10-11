package dev.guardianai.kids.ui.components;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.text.InputFilter;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import dev.guardianai.family.FamilyStatus;
import dev.guardianai.family.TrustedAdultValidator;
import dev.guardianai.help.HelpRequest;
import dev.guardianai.help.HelpRequestService;
import dev.guardianai.help.HelpRequestStatus;
import dev.guardianai.kids.KidsServices;
import dev.guardianai.kids.ui.Ui;
import dev.guardianai.kids.ui.model.TrustedAdult;

import java.text.DateFormat;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Help request flow: reason → recipient → (optional) location → preview → confirm → real send → real status.
 * Only adults paired through GuardianAi Personal (confirmed by the server) can receive a request. Status shown is
 * exactly what the server reports; "seen" is only shown after the adult acknowledges in their app.
 */
public class SosFlowOverlay {

    public interface Host {
        void dismissOverlay();
        /** Asks Android for ACCESS_COARSE_LOCATION; calls back with the result. */
        void requestCoarseLocation(Runnable onGranted, Runnable onDenied);
    }

    private static final String[][] REASONS = {
            {"someone_mean", "Someone is being mean to me"},
            {"pressure", "Someone is pressuring me"},
            {"shared_by_mistake", "I clicked or shared something by mistake"},
            {"unsafe", "I feel uncomfortable or unsafe"},
            {"something_else", "Something else is confusing me"},
    };

    private final Activity activity;
    private final FrameLayout container;
    private final Host host;
    private final KidsServices svc;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();

    private int step = 0;
    private String reason;
    private String note = "";
    private FamilyStatus family;
    private FamilyStatus.Adult recipient;
    private boolean wantLocation;
    private HelpRequest.LocationChoice locationChoice = HelpRequest.LocationChoice.NOT_SHARED;
    private HelpRequest.Location location;
    private HelpRequest current;
    private boolean busy;

    public SosFlowOverlay(Activity activity, FrameLayout container, Host host) {
        this.activity = activity;
        this.container = container;
        this.host = host;
        this.svc = KidsServices.get(activity);
    }

    public void show() {
        container.setVisibility(View.VISIBLE);
        step = 0;
        render();
    }

    /** Android Back: go to the previous step; returns false when the overlay should close. */
    public boolean onBack() {
        if (busy) return true;
        if (step > 0 && step < 4) {
            step--;
            render();
            return true;
        }
        return false;
    }

    private int dp(int v) {
        return Ui.dp(activity, v);
    }

    private void render() {
        container.removeAllViews();
        ScrollView scroll = new ScrollView(activity);
        scroll.setBackgroundColor(Ui.BG);
        LinearLayout root = new LinearLayout(activity);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(24), dp(32), dp(24), dp(36));
        scroll.addView(root);

        LinearLayout top = Ui.row(activity);
        top.addView(Ui.text(activity, "Ask for help 🤝", 22f, Ui.INK, true), Ui.weight(1f));
        Button close = new Button(activity);
        close.setText("✕");
        close.setBackgroundColor(Color.TRANSPARENT);
        close.setOnClickListener(v -> { if (!busy) host.dismissOverlay(); });
        top.addView(close);
        root.addView(top);
        TextView reassure = Ui.text(activity, "You are never in trouble for asking for help.", 14f, Ui.GREEN, false);
        reassure.setBackgroundColor(Color.parseColor("#EAF3ED"));
        reassure.setPadding(dp(12), dp(8), dp(12), dp(8));
        root.addView(reassure);
        View gap = new View(activity);
        root.addView(gap, new LinearLayout.LayoutParams(1, dp(16)));

        switch (step) {
            case 0: stepReason(root); break;
            case 1: stepRecipient(root); break;
            case 2: stepLocation(root); break;
            case 3: stepPreview(root); break;
            default: stepResult(root); break;
        }
        container.addView(scroll);
    }

    // ---------------------------------------------------------------- step 0: reason

    private void stepReason(LinearLayout root) {
        root.addView(Ui.title(activity, "Step 1 of 4: What's happening?"));
        for (String[] r : REASONS) {
            boolean on = r[0].equals(reason);
            Button b = Ui.secondary(activity, (on ? "●  " : "○  ") + r[1], v -> {
                reason = r[0];
                render();
            });
            b.setGravity(Gravity.START | Gravity.CENTER_VERTICAL);
            if (on) {
                b.setTextColor(Color.WHITE);
                b.setBackground(Ui.solid(activity, Ui.INK, 10));
            }
            root.addView(b);
        }
        root.addView(Ui.note(activity, "Want to add a few words? (optional)"));
        EditText et = new EditText(activity);
        et.setText(note);
        et.setHint("You don't have to write anything");
        et.setFilters(new InputFilter[]{new InputFilter.LengthFilter(HelpRequestService.MAX_NOTE)});
        root.addView(et);
        root.addView(Ui.primary(activity, "Next: choose who →", v -> {
            if (reason == null) {
                Toast.makeText(activity, "Pick the closest option above", Toast.LENGTH_SHORT).show();
                return;
            }
            note = et.getText() == null ? "" : et.getText().toString();
            family = null;
            step = 1;
            render();
        }));
        addEarlierRequests(root);
    }

    // ---------------------------------------------------------------- step 1: recipient

    private void stepRecipient(LinearLayout root) {
        root.addView(Ui.title(activity, "Step 2 of 4: Who do you want to tell?"));
        if (family == null) {
            root.addView(Ui.body(activity, "Checking your family connection…"));
            root.addView(new ProgressBar(activity));
            worker.execute(() -> {
                FamilyStatus fs = svc.pairing.fetchStatus();
                activity.runOnUiThread(() -> {
                    family = fs;
                    if (step == 1) render();
                });
            });
            return;
        }
        List<FamilyStatus.Adult> adults = family.helpRecipients();
        if (!adults.isEmpty()) {
            root.addView(Ui.note(activity, "These adults are connected through GuardianAi Personal and can receive your request:"));
            for (FamilyStatus.Adult a : adults) {
                boolean on = recipient != null && recipient.uid.equals(a.uid);
                Button b = Ui.secondary(activity, (on ? "●  " : "○  ") + a.displayName, v -> {
                    recipient = a;
                    render();
                });
                b.setGravity(Gravity.START | Gravity.CENTER_VERTICAL);
                if (on) {
                    b.setTextColor(Color.WHITE);
                    b.setBackground(Ui.solid(activity, Ui.INK, 10));
                }
                root.addView(b);
            }
            Button next = Ui.primary(activity, "Next →", v -> {
                if (recipient == null) {
                    Toast.makeText(activity, "Choose an adult first", Toast.LENGTH_SHORT).show();
                    return;
                }
                step = 2;
                render();
            });
            root.addView(next);
        } else {
            LinearLayout warn = Ui.vcard(activity);
            warn.setBackground(Ui.card(activity, Color.parseColor("#FFF6E5"), Color.parseColor("#F0E0C0"), 12));
            warn.addView(Ui.text(activity, "GuardianAi can't send a request right now", 14f, Ui.AMBER, true));
            warn.addView(Ui.body(activity, whyNoRecipients(family)));
            root.addView(warn);
            if (family.state == FamilyStatus.State.UNREACHABLE || family.state == FamilyStatus.State.ERROR) {
                root.addView(Ui.secondary(activity, "Try again", v -> {
                    family = null;
                    render();
                }));
            }
        }
        addOtherWays(root);
        root.addView(Ui.secondary(activity, "← Back", v -> {
            step = 0;
            render();
        }));
    }

    private static String whyNoRecipients(FamilyStatus f) {
        switch (f.state) {
            case NOT_CONFIGURED: return "Sending help requests isn't set up in this version of the app. Please use one of the other ways below.";
            case NOT_PAIRED: return "This phone isn't connected to a family yet. An adult can set this up with GuardianAi Personal (Settings → Family connection).";
            case PENDING_CONFIRMATION: return "Your adult still needs to confirm the family connection in GuardianAi Personal.";
            case REVOKED: return "The family connection was turned off.";
            case UNREACHABLE: return "There's no internet connection, so a request can't be sent.";
            case ACTIVE: return "No connected adult can receive requests yet.";
            default: return "The GuardianAi server didn't give a usable answer.";
        }
    }

    /** Real alternatives: the phone's dialer (the child presses call) and talking to someone nearby. */
    private void addOtherWays(LinearLayout root) {
        TextView t = Ui.text(activity, "Other ways to get help now", 13f, Ui.INK, true);
        t.setPadding(0, dp(16), 0, 0);
        root.addView(t);
        root.addView(Ui.body(activity, "• Tell an adult who is near you — a parent, teacher or relative."));
        List<TrustedAdult> saved = svc.repo.getTrustedAdults();
        for (TrustedAdult a : saved) {
            if (a.getPhone().isEmpty()) continue;
            root.addView(Ui.secondary(activity, "📞  Call " + a.label(), v -> dial(TrustedAdultValidator.dialable(a.getPhone()))));
        }
        root.addView(Ui.secondary(activity, "📞  Call 1098 (CHILDLINE India, free, 24×7)", v -> dial("1098")));
        root.addView(Ui.secondary(activity, "📞  Call 112 (Emergency)", v -> dial("112")));
        root.addView(Ui.note(activity, "These buttons open your phone's dialer with the number filled in. You decide whether to press call. GuardianAi doesn't call or text anyone for you."));
    }

    private void dial(String number) {
        try {
            activity.startActivity(new Intent(Intent.ACTION_DIAL, Uri.parse("tel:" + number)));
        } catch (ActivityNotFoundException e) {
            Toast.makeText(activity, "This device can't make phone calls. Please ask someone nearby.", Toast.LENGTH_LONG).show();
        }
    }

    // ---------------------------------------------------------------- step 2: location

    private void stepLocation(LinearLayout root) {
        root.addView(Ui.title(activity, "Step 3 of 4: Share where you are? (optional)"));
        root.addView(Ui.body(activity, "If you turn this on, your approximate area (about 100 m or more) is added to this one request so "
                + recipient.displayName + " can find you. It is not tracked or updated afterwards."));
        LinearLayout r = Ui.row(activity);
        r.addView(Ui.text(activity, "Share my approximate location", 14f, Ui.INK, false), Ui.weight(1f));
        Switch sw = new Switch(activity);
        sw.setChecked(wantLocation);
        r.addView(sw);
        root.addView(r);
        TextView state = Ui.note(activity, locationLabel());
        root.addView(state);
        sw.setOnCheckedChangeListener((b, on) -> {
            wantLocation = on;
            location = null;
            locationChoice = HelpRequest.LocationChoice.NOT_SHARED;
            if (!on) {
                state.setText(locationLabel());
                return;
            }
            state.setText("Getting your approximate location…");
            Runnable fetch = () -> ApproxLocation.get(activity, 10_000, (choice, loc) -> {
                locationChoice = choice;
                location = loc;
                if (step == 2) state.setText(locationLabel());
            });
            if (ApproxLocation.hasPermission(activity)) fetch.run();
            else host.requestCoarseLocation(fetch, () -> {
                locationChoice = HelpRequest.LocationChoice.PERMISSION_DENIED;
                if (step == 2) state.setText(locationLabel());
            });
        });
        root.addView(Ui.primary(activity, "Next: check what will be sent →", v -> {
            step = 3;
            render();
        }));
        root.addView(Ui.secondary(activity, "← Back", v -> {
            step = 1;
            render();
        }));
    }

    private String locationLabel() {
        switch (locationChoice) {
            case SHARED: return String.format(java.util.Locale.US, "Approximate location ready (%.3f, %.3f)", location.lat, location.lng);
            case PERMISSION_DENIED: return "Location permission was not given, so the request will be sent without location.";
            case UNAVAILABLE: return wantLocation ? "Location isn't available right now, so the request will be sent without it." : "Location will not be shared.";
            default: return "Location will not be shared.";
        }
    }

    // ---------------------------------------------------------------- step 3: preview + confirm

    private void stepPreview(LinearLayout root) {
        root.addView(Ui.title(activity, "Step 4 of 4: Check and send"));
        LinearLayout card = Ui.vcard(activity);
        card.addView(Ui.text(activity, "To: " + recipient.displayName + " (in GuardianAi Personal)", 14f, Ui.INK, true));
        card.addView(Ui.body(activity, "What happened: " + reasonLabel(reason)));
        String n = note.trim();
        card.addView(Ui.body(activity, "Your words: " + (n.isEmpty() ? "(none)" : "\"" + n + "\"")));
        card.addView(Ui.body(activity, "Location: " + (locationChoice == HelpRequest.LocationChoice.SHARED ? "approximate area" : "not shared")));
        String name = svc.repo.getChildDisplayName();
        card.addView(Ui.body(activity, "From: " + (name.isEmpty() ? "your name in the family" : name)));
        root.addView(card);
        root.addView(Ui.note(activity, "Only the lines above are sent. Your checks, messages, contacts and lessons are not sent."));
        root.addView(Ui.primary(activity, "Confirm and send", v -> confirmAndSend()));
        root.addView(Ui.secondary(activity, "← Change something", v -> {
            step = 2;
            render();
        }));
        root.addView(Ui.secondary(activity, "Cancel — don't send", v -> host.dismissOverlay()));
    }

    private void confirmAndSend() {
        if (busy) return; // repeated taps
        busy = true;
        current = HelpRequestService.confirmDraft(recipient.uid, recipient.displayName, reason, note,
                locationChoice, location, System.currentTimeMillis()).with(HelpRequestStatus.SENDING, null, null, System.currentTimeMillis());
        svc.repo.saveHelpRequest(current);
        step = 4;
        render();
        send(current);
    }

    private void send(HelpRequest r) {
        busy = true;
        worker.execute(() -> {
            HelpRequest res = svc.help.submit(r);
            activity.runOnUiThread(() -> {
                busy = false;
                current = res;
                svc.repo.saveHelpRequest(res);
                if (step == 4) render();
            });
        });
    }

    // ---------------------------------------------------------------- step 4: result

    private void stepResult(LinearLayout root) {
        HelpRequest r = current;
        if (r == null) {
            host.dismissOverlay();
            return;
        }
        HelpRequestStatus s = r.status;
        int fg = s == HelpRequestStatus.ACKNOWLEDGED ? Ui.GREEN : (s == HelpRequestStatus.FAILED ? Ui.RED : Ui.AMBER);
        root.addView(Ui.badge(activity, s.childLabel(), fg, Color.parseColor("#F3F3F0")));
        if (s == HelpRequestStatus.SENDING) {
            root.addView(Ui.body(activity, "Sending your request to " + r.recipientName + "…"));
            root.addView(new ProgressBar(activity));
            return;
        }
        if (r.failureReason != null) root.addView(Ui.body(activity, r.failureReason));
        switch (s) {
            case ACCEPTED_BY_SERVER:
            case NOTIFICATION_QUEUED:
                root.addView(Ui.body(activity, "GuardianAi will show here when " + r.recipientName + " opens it and presses \"I've seen this\". "
                        + "Until then, we don't know if they have seen it — if you need help now, tell someone nearby or call."));
                break;
            case ACKNOWLEDGED:
                root.addView(Ui.body(activity, r.recipientName + " has seen your request in GuardianAi Personal."));
                break;
            case DELIVERY_UNKNOWN:
                root.addView(Ui.body(activity, "Tap \"Check status\" to ask the server, or send again — sending again won't create a second request."));
                break;
            case FAILED:
                root.addView(Ui.body(activity, "Your request was not sent. Please use one of the other ways below."));
                break;
            default:
                break;
        }
        if (s != HelpRequestStatus.FAILED && s != HelpRequestStatus.CANCELLED) {
            root.addView(Ui.secondary(activity, "Check status", v -> refresh(r)));
        }
        if (s == HelpRequestStatus.FAILED || s == HelpRequestStatus.DELIVERY_UNKNOWN) {
            root.addView(Ui.primary(activity, "Send again", v -> {
                current = r.with(HelpRequestStatus.SENDING, null, null, System.currentTimeMillis());
                svc.repo.saveHelpRequest(current);
                render();
                send(current);
            }));
        }
        if (s == HelpRequestStatus.ACCEPTED_BY_SERVER || s == HelpRequestStatus.NOTIFICATION_QUEUED || s == HelpRequestStatus.DELIVERY_UNKNOWN) {
            root.addView(Ui.secondary(activity, "Cancel this request", v -> {
                busy = true;
                worker.execute(() -> {
                    HelpRequest c = svc.help.cancel(r);
                    activity.runOnUiThread(() -> {
                        busy = false;
                        current = c;
                        svc.repo.saveHelpRequest(c);
                        if (c.status != HelpRequestStatus.CANCELLED) {
                            Toast.makeText(activity, "Couldn't cancel right now", Toast.LENGTH_SHORT).show();
                        }
                        render();
                    });
                });
            }));
        }
        if (s != HelpRequestStatus.ACKNOWLEDGED) addOtherWays(root);
        root.addView(Ui.primary(activity, "Done", v -> host.dismissOverlay()));
    }

    private void refresh(HelpRequest r) {
        busy = true;
        worker.execute(() -> {
            HelpRequest u = svc.help.refresh(r);
            activity.runOnUiThread(() -> {
                busy = false;
                current = u;
                svc.repo.saveHelpRequest(u);
                render();
            });
        });
    }

    private void addEarlierRequests(LinearLayout root) {
        List<HelpRequest> list = svc.repo.getHelpRequests();
        if (list.isEmpty()) return;
        TextView t = Ui.text(activity, "Earlier requests", 13f, Ui.INK, true);
        t.setPadding(0, dp(20), 0, dp(4));
        root.addView(t);
        DateFormat df = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT);
        int n = 0;
        for (HelpRequest r : list) {
            if (n++ == 5) break;
            Button b = Ui.secondary(activity, df.format(new Date(r.createdAt)) + " → " + r.recipientName + "\n" + r.status.childLabel(), v -> {
                current = r;
                step = 4;
                render();
            });
            b.setGravity(Gravity.START | Gravity.CENTER_VERTICAL);
            b.setTextSize(12f);
            root.addView(b);
        }
    }

    private static String reasonLabel(String key) {
        for (String[] r : REASONS) if (r[0].equals(key)) return r[1];
        return key;
    }

    public void release() {
        worker.shutdown();
    }
}
