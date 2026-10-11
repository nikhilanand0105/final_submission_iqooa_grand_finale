package dev.guardianai.kids.ui.screens;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Color;
import android.graphics.Typeface;
import android.text.InputType;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import dev.guardianai.ai.explain.ModelState;
import dev.guardianai.family.BackendClient;
import dev.guardianai.family.FamilyStatus;
import dev.guardianai.family.PairingService;
import dev.guardianai.kids.BuildConfig;
import dev.guardianai.kids.KidsServices;
import dev.guardianai.kids.ui.Ui;
import dev.guardianai.kids.ui.model.TrustedAdult;

import java.text.DateFormat;
import java.util.Date;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Settings & privacy: what is shared and stored, family connection (server-backed), trusted adults (local),
 * on-device AI status, language and text size, and data deletion. Every switch here changes persisted state
 * that another part of the app reads.
 */
public class SettingsScreenController {

    public interface Host {
        /** Re-creates the activity so a new text size applies everywhere. */
        void applyTextSize();
        void requestNotificationPermission();
        void openNotificationAccessSettings();
        void openSafeBrowser();
        void openSafetyAlerts();
    }

    private final Activity activity;
    private final Host host;
    private final KidsServices svc;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();

    private ScrollView root;
    private LinearLayout protectionCard, familyCard, adultsCard, aiCard, prefsCard, dataCard;
    private FamilyStatus family;
    private boolean familyLoading;
    private final Runnable localListener = this::renderLocal;
    private final Runnable aiListener = this::renderAi;

    public SettingsScreenController(Activity activity, Host host) {
        this.activity = activity;
        this.host = host;
        this.svc = KidsServices.get(activity);
        build();
        svc.repo.addListener(localListener);
        svc.model.addListener(aiListener);
        dev.guardianai.kids.storage.SafetyEventStore.get(activity).addListener(localListener);
    }

    public View getView() {
        return root;
    }

    private int dp(int v) {
        return Ui.dp(activity, v);
    }

    private void build() {
        root = new ScrollView(activity);
        root.setFillViewport(true);
        root.setBackgroundColor(Ui.BG);
        LinearLayout l = new LinearLayout(activity);
        l.setOrientation(LinearLayout.VERTICAL);
        l.setPadding(dp(20), dp(20), dp(20), dp(60));
        root.addView(l);

        TextView h = Ui.text(activity, "Settings & Privacy ⚙️", 24f, Ui.INK, true);
        h.setTypeface(Typeface.create("sans-serif-black", Typeface.BOLD));
        l.addView(h);
        TextView sub = Ui.text(activity, "What GuardianAi keeps, what it shares, and who can help you.", 13.5f, Color.parseColor("#555555"), false);
        sub.setPadding(0, dp(4), 0, dp(14));
        l.addView(sub);

        l.addView(privacyCard());
        protectionCard = Ui.vcard(activity);
        l.addView(protectionCard);
        familyCard = Ui.vcard(activity);
        adultsCard = Ui.vcard(activity);
        aiCard = Ui.vcard(activity);
        prefsCard = Ui.vcard(activity);
        dataCard = Ui.vcard(activity);
        l.addView(familyCard);
        l.addView(adultsCard);
        l.addView(aiCard);
        l.addView(prefsCard);
        l.addView(dataCard);
        l.addView(Ui.note(activity, "GuardianAi Kids " + BuildConfig.VERSION_NAME));
        render();
    }

    public void render() {
        renderProtection();
        renderLocal();
        renderAi();
        if (family == null && !familyLoading) refreshFamily();
        else renderFamily();
    }

    private void renderLocal() {
        renderAdults();
        renderPrefs();
        renderData();
    }

    private View privacyCard() {
        LinearLayout c = Ui.vcard(activity);
        c.addView(Ui.title(activity, "How your information is handled 🔒"));
        c.addView(Ui.body(activity, "✅ Message checks and file checks run only on this phone."));
        c.addView(Ui.body(activity, "✅ Link checks run on this phone. The website part of a link is sent to the online safety list only if you turn that on in the Link tab."));
        c.addView(Ui.body(activity, "✅ GuardianAi never reads your chats, contacts or browsing by itself. You choose what to check."));
        c.addView(Ui.body(activity, "✅ Check history keeps only the result type and time — not the message, link or file name."));
        c.addView(Ui.body(activity, "✅ If you connect with your family, they only get help requests you choose to send."));
        c.addView(Ui.body(activity, "✅ Location is only added to a help request if you switch it on for that request."));
        return c;
    }

    // ---------------------------------------------------------------- background protection (real Android state)

    private void renderProtection() {
        LinearLayout c = protectionCard;
        if (c == null) return;
        c.removeAllViews();
        c.addView(Ui.title(activity, "Background protection 🛡️"));
        dev.guardianai.safety.MonitoringStatus st = dev.guardianai.kids.safety.MonitoringState.compute(activity);
        String overall;
        int color;
        switch (st.overall) {
            case ACTIVE: overall = "● On — checking notifications even when GuardianAi is closed"; color = Ui.GREEN; break;
            case PARTIALLY_ACTIVE: overall = "◐ Partly on — see below"; color = Ui.AMBER; break;
            case PERMISSION_REQUIRED: overall = "○ Off — notification access is needed"; color = Ui.FAINT; break;
            case MONITORING_INTERRUPTED: overall = "◐ Interrupted — Android isn't running the listener right now"; color = Ui.AMBER; break;
            default: overall = "○ Unavailable — see below"; color = Ui.RED; break;
        }
        c.addView(Ui.text(activity, overall, 12.5f, color, true));
        for (dev.guardianai.safety.MonitoringStatus.Item i : st.items) {
            String name;
            switch (i.capability) {
                case NOTIFICATION_MONITORING: name = "Notification checks"; break;
                case ALERT_DELIVERY: name = "Safety alerts"; break;
                case GEMMA_MODEL: name = "AI model (Gemma)"; break;
                case SAFE_BROWSER: name = "Safe Browser"; break;
                case NETWORK_PROTECTION: name = "Other browsers"; break;
                default: name = "Saved results"; break;
            }
            c.addView(Ui.text(activity, name + ": " + i.state.name().toLowerCase().replace('_', ' '), 12.5f, Ui.INK, true));
            c.addView(Ui.note(activity, i.detail + (i.fix.isEmpty() ? "" : " → " + i.fix)));
        }
        android.content.SharedPreferences stats = dev.guardianai.kids.safety.SafetyEventProcessor.get(activity).stats();
        long last = stats.getLong("last_processed_at", 0);
        c.addView(Ui.note(activity, "Notifications checked: " + stats.getInt("processed", 0)
                + (last > 0 ? " (last " + DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(new Date(last)) + ")" : "")
                + " • text hidden by the app: " + stats.getInt("content_unavailable", 0)
                + " • not checked (too many at once): " + stats.getInt("dropped", 0)));
        c.addView(Ui.note(activity, "What GuardianAi can see: only the text that apps show in their notifications. It can't see messages without a "
                + "notification, hidden previews, or what you type and send. Only websites opened in GuardianAi Safe Browser are checked."));
        if (!dev.guardianai.kids.safety.MonitoringState.notificationAccessGranted(activity)) {
            c.addView(Ui.primary(activity, "Turn on notification checks", v -> new AlertDialog.Builder(activity)
                    .setTitle("Let GuardianAi check notifications?")
                    .setMessage("Android will show a settings screen. If you turn on access for GuardianAi Kids, GuardianAi can read the text in notifications "
                            + "on this phone to look for threats, scams or signs that someone needs help. It checks on this phone; nothing is uploaded. "
                            + "Results are saved here for 30 days and only shared if you ask for help. You can turn it off any time.")
                    .setPositiveButton("Open settings", (d, w) -> host.openNotificationAccessSettings())
                    .setNegativeButton("Not now", null)
                    .show()));
        } else {
            c.addView(Ui.secondary(activity, "Turn off notification checks", v -> host.openNotificationAccessSettings()));
        }
        if (!dev.guardianai.kids.safety.SafetyEventProcessor.get(activity).alerts().canPostNotifications()) {
            c.addView(Ui.secondary(activity, "Allow GuardianAi to show alerts", v -> host.requestNotificationPermission()));
        }
        c.addView(Ui.secondary(activity, "Open GuardianAi Safe Browser", v -> host.openSafeBrowser()));
        c.addView(Ui.secondary(activity, "See safety alerts", v -> host.openSafetyAlerts()));
    }

    // ---------------------------------------------------------------- family (server-backed)

    private void refreshFamily() {
        familyLoading = true;
        renderFamily();
        worker.execute(() -> {
            FamilyStatus fs = svc.pairing.fetchStatus();
            activity.runOnUiThread(() -> {
                family = fs;
                familyLoading = false;
                renderFamily();
            });
        });
    }

    private void renderFamily() {
        LinearLayout c = familyCard;
        c.removeAllViews();
        c.addView(Ui.title(activity, "Family connection 👨‍👩‍👧"));
        if (familyLoading || family == null) {
            c.addView(Ui.body(activity, "Checking with the GuardianAi server…"));
            return;
        }
        String label;
        int color;
        switch (family.state) {
            case ACTIVE: label = "● Connected with " + family.familyDisplayName + " (confirmed by the server)"; color = Ui.GREEN; break;
            case PENDING_CONFIRMATION: label = "◐ Waiting for your adult to confirm in GuardianAi Personal"; color = Ui.AMBER; break;
            case NOT_PAIRED: label = "○ Not connected"; color = Ui.FAINT; break;
            case REVOKED: label = "○ Connection was turned off"; color = Ui.FAINT; break;
            case NOT_CONFIGURED: label = "Not available in this version (server not configured)"; color = Ui.FAINT; break;
            case UNREACHABLE: label = "Can't reach the server right now — connection status unknown"; color = Ui.AMBER; break;
            default: label = "The server returned an error — connection status unknown"; color = Ui.AMBER; break;
        }
        c.addView(Ui.text(activity, label, 12.5f, color, true));
        if (!family.message.isEmpty()) c.addView(Ui.note(activity, family.message));
        if (family.state == FamilyStatus.State.ACTIVE) {
            for (FamilyStatus.Adult a : family.adults) {
                c.addView(Ui.body(activity, "• " + a.displayName + (a.canReceiveHelp ? " — can receive your help requests" : "")));
            }
        }
        c.addView(Ui.note(activity, "What's shared: only help requests you confirm (reason, optional note, optional approximate location). "
                + "Your checks, messages, lessons and contacts are never shared."));
        if (family.state == FamilyStatus.State.NOT_PAIRED || family.state == FamilyStatus.State.REVOKED) {
            c.addView(Ui.primary(activity, "Enter a code from GuardianAi Personal", v -> showRedeemDialog()));
        }
        if ((family.state == FamilyStatus.State.ACTIVE || family.state == FamilyStatus.State.PENDING_CONFIRMATION) && family.pairingId != null) {
            c.addView(Ui.secondary(activity, "Disconnect from family", v -> confirmUnpair(family.pairingId)));
        }
        if (family.state != FamilyStatus.State.NOT_CONFIGURED) {
            c.addView(Ui.secondary(activity, "Refresh status", v -> refreshFamily()));
        }
    }

    private void showRedeemDialog() {
        LinearLayout form = new LinearLayout(activity);
        form.setOrientation(LinearLayout.VERTICAL);
        form.setPadding(dp(20), dp(8), dp(20), dp(8));
        EditText code = new EditText(activity);
        code.setHint("Code, e.g. AB12-CD34");
        code.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_CAP_CHARACTERS | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        form.addView(code);
        EditText name = new EditText(activity);
        name.setHint("Your first name (shown to your family)");
        name.setText(svc.repo.getChildDisplayName());
        form.addView(name);
        TextView info = Ui.note(activity, "Ask your adult to create a code in GuardianAi Personal. Codes work once and expire after 10 minutes. "
                + "Your adult will need to confirm the connection.");
        form.addView(info);
        new AlertDialog.Builder(activity)
                .setTitle("Connect with your family")
                .setView(form)
                .setPositiveButton("Connect", (d, w) -> {
                    String c = code.getText().toString();
                    String n = name.getText().toString();
                    String nameErr = PairingService.validateDisplayName(n);
                    if (PairingService.normalizeCode(c) == null || nameErr != null) {
                        Toast.makeText(activity, nameErr != null ? nameErr : "That code should have 8 letters and numbers", Toast.LENGTH_LONG).show();
                        return;
                    }
                    familyLoading = true;
                    renderFamily();
                    worker.execute(() -> {
                        PairingService.RedeemResult r = svc.pairing.redeem(c, n);
                        activity.runOnUiThread(() -> {
                            familyLoading = false;
                            if (r.ok) {
                                svc.repo.setChildDisplayName(n);
                                family = r.status;
                            }
                            Toast.makeText(activity, r.message, Toast.LENGTH_LONG).show();
                            if (!r.ok) refreshFamily();
                            else renderFamily();
                        });
                    });
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void confirmUnpair(String pairingId) {
        new AlertDialog.Builder(activity)
                .setTitle("Disconnect from your family?")
                .setMessage("You won't be able to send help requests through GuardianAi until an adult connects you again.")
                .setPositiveButton("Disconnect", (d, w) -> worker.execute(() -> {
                    BackendClient.Result r = svc.pairing.revoke(pairingId);
                    activity.runOnUiThread(() -> {
                        Toast.makeText(activity, r.ok() ? "Disconnected" : "Couldn't disconnect: " + r.message, Toast.LENGTH_LONG).show();
                        refreshFamily();
                    });
                }))
                .setNegativeButton("Keep connected", null)
                .show();
    }

    // ---------------------------------------------------------------- trusted adults (local only)

    private void renderAdults() {
        LinearLayout c = adultsCard;
        c.removeAllViews();
        LinearLayout top = Ui.row(activity);
        top.addView(Ui.title(activity, "Trusted adults 👥"), Ui.weight(1f));
        Button add = new Button(activity);
        add.setText("+ Add");
        add.setAllCaps(false);
        add.setOnClickListener(v -> editAdultDialog(null));
        top.addView(add);
        c.addView(top);
        c.addView(Ui.note(activity, "Saved on this phone only, so you can find their number quickly. Saving someone doesn't tell them, "
                + "and they can't receive GuardianAi help requests unless they're connected through GuardianAi Personal."));
        if (svc.repo.didLoadFail()) c.addView(Ui.text(activity, "Saved data couldn't be loaded.", 12.5f, Ui.RED, true));
        if (svc.repo.getTrustedAdults().isEmpty()) {
            c.addView(Ui.body(activity, "No one saved yet. Add a parent, relative or teacher you trust."));
        }
        for (TrustedAdult a : svc.repo.getTrustedAdults()) {
            LinearLayout r = Ui.row(activity);
            r.setPadding(0, dp(6), 0, dp(6));
            LinearLayout col = new LinearLayout(activity);
            col.setOrientation(LinearLayout.VERTICAL);
            col.addView(Ui.text(activity, a.label(), 13.5f, Ui.INK, true));
            col.addView(Ui.note(activity, (a.getPhone().isEmpty() ? "No phone number" : a.getPhone()) + " • saved on this phone only"));
            r.addView(col, Ui.weight(1f));
            Button edit = new Button(activity);
            edit.setText("Edit");
            edit.setAllCaps(false);
            edit.setOnClickListener(v -> editAdultDialog(a));
            r.addView(edit);
            Button del = new Button(activity);
            del.setText("Remove");
            del.setAllCaps(false);
            del.setOnClickListener(v -> new AlertDialog.Builder(activity)
                    .setMessage("Remove " + a.getName() + " from this phone?")
                    .setPositiveButton("Remove", (d, w) -> svc.repo.removeTrustedAdult(a.getId()))
                    .setNegativeButton("Cancel", null).show());
            r.addView(del);
            c.addView(r);
        }
    }

    private void editAdultDialog(TrustedAdult existing) {
        LinearLayout form = new LinearLayout(activity);
        form.setOrientation(LinearLayout.VERTICAL);
        form.setPadding(dp(20), dp(8), dp(20), dp(8));
        EditText name = new EditText(activity);
        name.setHint("Name");
        EditText rel = new EditText(activity);
        rel.setHint("Relationship (e.g. Aunt, Teacher) — optional");
        EditText phone = new EditText(activity);
        phone.setHint("Phone number — optional");
        phone.setInputType(InputType.TYPE_CLASS_PHONE);
        if (existing != null) {
            name.setText(existing.getName());
            rel.setText(existing.getRelation());
            phone.setText(existing.getPhone());
        }
        TextView err = Ui.text(activity, "", 12f, Ui.RED, false);
        form.addView(name);
        form.addView(rel);
        form.addView(phone);
        form.addView(err);
        AlertDialog dlg = new AlertDialog.Builder(activity)
                .setTitle(existing == null ? "Add a trusted adult" : "Edit " + existing.getName())
                .setView(form)
                .setPositiveButton("Save", null)
                .setNegativeButton("Cancel", null)
                .create();
        dlg.setOnShowListener(d -> dlg.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            String n = name.getText().toString(), r = rel.getText().toString(), p = phone.getText().toString();
            String e = existing == null ? svc.repo.addTrustedAdult(n, r, p) : svc.repo.updateTrustedAdult(existing.getId(), n, r, p);
            if (e != null) {
                err.setText(e);
            } else {
                Toast.makeText(activity, "Saved on this phone. " + n.trim() + " hasn't been told.", Toast.LENGTH_LONG).show();
                dlg.dismiss();
            }
        }));
        dlg.show();
    }

    // ---------------------------------------------------------------- on-device AI

    private void renderAi() {
        LinearLayout c = aiCard;
        if (c == null) return;
        c.removeAllViews();
        c.addView(Ui.title(activity, "On-device AI explanations ✨"));
        ModelState st = svc.model.getState();
        c.addView(Ui.text(activity, "Status: " + st.getDescription(), 12.5f, st == ModelState.READY ? Ui.GREEN : Ui.MUTED, true));
        if (!svc.model.getModelId().isEmpty()) c.addView(Ui.body(activity, "Model file: " + svc.model.getModelId()));
        if (!svc.model.getIntegrityNote().isEmpty()) c.addView(Ui.body(activity, "Integrity: " + svc.model.getIntegrityNote()));
        if (!svc.model.getBackendUsed().isEmpty()) c.addView(Ui.body(activity, "Running on: " + svc.model.getBackendUsed()));
        if (svc.model.getLastLoadMs() >= 0) c.addView(Ui.body(activity, "Last load time: " + svc.model.getLastLoadMs() + " ms"));
        if (svc.model.getLastGenerationMs() >= 0) {
            c.addView(Ui.body(activity, "Last answer: " + svc.model.getLastGenerationMs() + " ms, " + svc.model.getLastOutputChars() + " characters"));
        }
        if (!svc.model.getLastError().isEmpty() && st != ModelState.READY) c.addView(Ui.note(activity, svc.model.getLastError()));
        c.addView(Ui.note(activity, "The AI only explains results that GuardianAi's checks already found. It runs on this phone, can't change a result, "
                + "and never contacts anyone. Without a model, GuardianAi shows clearly-labelled rules-based guidance instead."));
        if (st == ModelState.CLOSED || st == ModelState.FAILED || st == ModelState.RESOURCE_CONSTRAINED) {
            c.addView(Ui.secondary(activity, "Load model", v -> svc.model.loadAsync()));
        } else if (st == ModelState.READY) {
            c.addView(Ui.secondary(activity, "Release model (free memory)", v -> svc.model.release()));
        } else if (st == ModelState.UNAVAILABLE) {
            c.addView(Ui.secondary(activity, "Look for model file again", v -> svc.model.refreshAvailability()));
        }
    }

    // ---------------------------------------------------------------- preferences

    private void renderPrefs() {
        LinearLayout c = prefsCard;
        c.removeAllViews();
        c.addView(Ui.title(activity, "Language & text 🎨"));
        boolean hi = "hi".equals(svc.repo.getLanguage());
        LinearLayout r = Ui.row(activity);
        r.addView(Ui.text(activity, "Language: " + (hi ? "हिन्दी (Hindi)" : "English"), 13.5f, Ui.INK, false), Ui.weight(1f));
        Button t = new Button(activity);
        t.setAllCaps(false);
        t.setText(hi ? "Use English" : "हिन्दी चुनें");
        t.setOnClickListener(v -> svc.repo.setLanguage(hi ? "en" : "hi"));
        r.addView(t);
        c.addView(r);
        c.addView(Ui.note(activity, "Hindi is available for all lessons and for explanations. Other screens are still in English."));

        LinearLayout lt = Ui.row(activity);
        lt.addView(Ui.text(activity, "Larger text", 13.5f, Ui.INK, false), Ui.weight(1f));
        Switch sw = new Switch(activity);
        sw.setChecked(svc.repo.isLargeText());
        sw.setOnCheckedChangeListener((b, on) -> {
            svc.repo.setLargeText(on);
            host.applyTextSize();
        });
        lt.addView(sw);
        c.addView(lt);

        if (svc.urlAnalyzer.getProvider().isConfigured()) {
            LinearLayout ol = Ui.row(activity);
            ol.addView(Ui.text(activity, "Ask the online safety list when checking links", 13.5f, Ui.INK, false), Ui.weight(1f));
            Switch o = new Switch(activity);
            o.setChecked(svc.repo.isOnlineLinkCheckAllowed());
            o.setOnCheckedChangeListener((b, on) -> {
                if (!on) {
                    svc.repo.setOnlineLinkCheckAllowed(false);
                    return;
                }
                b.setChecked(false);
                new AlertDialog.Builder(activity)
                        .setTitle("Send links to the online safety list?")
                        .setMessage(svc.urlAnalyzer.getProvider().getDisclosure())
                        .setPositiveButton("Allow", (d, w) -> svc.repo.setOnlineLinkCheckAllowed(true))
                        .setNegativeButton("No", null)
                        .show();
            });
            ol.addView(o);
            c.addView(ol);
        }
    }

    // ---------------------------------------------------------------- data

    private void renderData() {
        LinearLayout c = dataCard;
        c.removeAllViews();
        c.addView(Ui.title(activity, "Your data on this phone 🗂️"));
        int checks = svc.repo.getCheckHistory().size();
        c.addView(Ui.body(activity, checks + " check result" + (checks == 1 ? "" : "s") + " saved (type, result and time only)."));
        if (checks > 0) {
            long last = svc.repo.getCheckHistory().get(0).getTimestamp();
            c.addView(Ui.note(activity, "Latest: " + DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(new Date(last))));
        }
        c.addView(Ui.secondary(activity, "Delete check history", v -> confirm("Delete all saved check results?", svc.repo::clearCheckHistory)));
        int lessons = svc.repo.getCompletedLessonIds().size();
        c.addView(Ui.body(activity, lessons + " lesson" + (lessons == 1 ? "" : "s") + " marked complete."));
        c.addView(Ui.secondary(activity, "Reset lesson progress", v -> confirm("Mark all lessons as not done? This can't be undone.", svc.repo::resetLessonProgress)));
        int alerts = dev.guardianai.kids.storage.SafetyEventStore.get(activity).all().size();
        c.addView(Ui.body(activity, alerts + " safety alert" + (alerts == 1 ? "" : "s") + " saved (kept 30 days)."));
        if (alerts > 0) {
            c.addView(Ui.secondary(activity, "Delete safety alerts", v -> confirm("Delete all saved safety alerts and clear both flags?",
                    () -> dev.guardianai.kids.storage.SafetyEventStore.get(activity).deleteAll())));
        }
        int help = svc.repo.getHelpRequests().size();
        if (help > 0) {
            c.addView(Ui.body(activity, help + " help request record" + (help == 1 ? "" : "s") + " on this phone."));
            c.addView(Ui.secondary(activity, "Delete help request history from this phone",
                    v -> confirm("Delete the list of your earlier help requests from this phone? (Requests already sent stay with the adult.)", svc.repo::clearHelpHistory)));
        }
    }

    private void confirm(String msg, Runnable action) {
        new AlertDialog.Builder(activity)
                .setMessage(msg)
                .setPositiveButton("Yes, delete", (d, w) -> {
                    action.run();
                    Toast.makeText(activity, "Done", Toast.LENGTH_SHORT).show();
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    public void onDestroy() {
        svc.repo.removeListener(localListener);
        svc.model.removeListener(aiListener);
        dev.guardianai.kids.storage.SafetyEventStore.get(activity).removeListener(localListener);
        worker.shutdownNow();
    }
}
