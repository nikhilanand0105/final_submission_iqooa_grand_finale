package dev.saathi.personal.ui.screens;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import dev.saathi.family.FamilyRepository;
import dev.saathi.family.PairingChallenge;
import dev.saathi.family.SosRequest;
import dev.saathi.personal.R;
import dev.saathi.personal.ui.model.SafetyReport;
import dev.saathi.personal.ui.state.AppState;
import dev.saathi.storage.TrustedHelper;

import java.text.SimpleDateFormat;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.Executors;

public class FamilyScreenController {

    private static final String PLACEHOLDER_FAMILY_ID = "local-family-" + android.os.Build.MODEL.replaceAll("[^a-zA-Z0-9]", "");
    private static final String PLACEHOLDER_DEVICE_ID  = "device-" + android.os.Build.MODEL.replaceAll("[^a-zA-Z0-9]", "");

    private final Activity activity;
    private final float density;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private ScrollView rootView;
    private LinearLayout contentLayout;

    // Pairing state
    private PairingChallenge currentChallenge;
    private LinearLayout pairingCodeContainer;
    private TextView tvPairingCode;
    private TextView tvPairingStatus;
    private TextView tvPairingExpiry;

    // SOS state
    private SosRequest lastSosRequest;
    private LinearLayout sosStatusContainer;
    private TextView tvSosStatus;

    public FamilyScreenController(Activity activity) {
        this.activity = activity;
        this.density  = activity.getResources().getDisplayMetrics().density;
        createView();
    }

    public View getView() { return rootView; }

    private void createView() {
        rootView = new ScrollView(activity);
        rootView.setLayoutParams(new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
        ));
        rootView.setFillViewport(true);
        rootView.setBackgroundColor(0xFFF7F7F5);

        contentLayout = new LinearLayout(activity);
        contentLayout.setOrientation(LinearLayout.VERTICAL);
        contentLayout.setPadding(dp(20), dp(16), dp(20), dp(100));
        rootView.addView(contentLayout);

        render();
    }

    public void render() {
        contentLayout.removeAllViews();
        boolean senior = AppState.get().isSeniorMode();
        FamilyRepository repo = AppState.get().getFamilyRepository();

        contentLayout.addView(buildHeader(senior));
        contentLayout.addView(buildPrivacyModelCard(senior));
        contentLayout.addView(buildBackendStatusBanner(repo));
        contentLayout.addView(buildPairingCodeCard(senior, repo));
        contentLayout.addView(buildSosSection(senior, repo));
        contentLayout.addView(buildSafetyReportsSection(senior));
        contentLayout.addView(buildTrustedContactsSection(senior));
    }

    // ──────────────────────────────────────────────────────────────────
    // Header
    // ──────────────────────────────────────────────────────────────────

    private View buildHeader(boolean senior) {
        LinearLayout h = new LinearLayout(activity);
        h.setOrientation(LinearLayout.VERTICAL);
        h.setPadding(0, 0, 0, dp(16));

        TextView tvTitle = new TextView(activity);
        tvTitle.setText(senior ? "FAMILY SAFETY NETWORK" : "FAMILY DIGITAL SAFETY & CONSENT");
        tvTitle.setTextSize(senior ? 24 : 22);
        tvTitle.setTextColor(0xFF141414);
        tvTitle.setTypeface(null, android.graphics.Typeface.BOLD);
        h.addView(tvTitle);

        TextView tvSub = new TextView(activity);
        tvSub.setText(senior
                ? "Protect your loved ones through mutual consent, safety agreements, and verified alerts."
                : "Transparent family administration — real pairing, honest SOS tracking, mutual consent");
        tvSub.setTextSize(senior ? 15 : 13);
        tvSub.setTextColor(0xFF666666);
        LinearLayout.LayoutParams sp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        sp.topMargin = dp(4);
        tvSub.setLayoutParams(sp);
        h.addView(tvSub);
        return h;
    }

    // ──────────────────────────────────────────────────────────────────
    // Privacy guarantee card (unchanged, important)
    // ──────────────────────────────────────────────────────────────────

    private View buildPrivacyModelCard(boolean senior) {
        LinearLayout card = buildCard(dp(16));

        LinearLayout topRow = new LinearLayout(activity);
        topRow.setOrientation(LinearLayout.HORIZONTAL);
        topRow.setGravity(Gravity.CENTER_VERTICAL);

        TextView label = new TextView(activity);
        label.setText("ZERO-COVERT-SURVEILLANCE GUARANTEE");
        label.setTextSize(senior ? 13 : 11);
        label.setTextColor(0xFF386B57);
        label.setTypeface(null, android.graphics.Typeface.BOLD);
        topRow.addView(label);
        topRow.addView(flexSpacer());

        TextView badge = new TextView(activity);
        badge.setText("CONSENT FIRST");
        badge.setTextSize(senior ? 11 : 9);
        badge.setTextColor(0xFF386B57);
        badge.setBackgroundResource(R.drawable.bg_pill_emerald);
        badge.setPadding(dp(8), dp(3), dp(8), dp(3));
        topRow.addView(badge);
        card.addView(topRow);

        TextView explanation = new TextView(activity);
        explanation.setText(
                "Saathi is built on trust, transparency, and family consent. Saathi Personal explicitly NEVER includes:\n" +
                "• No stealth background chat reading or call eavesdropping\n" +
                "• No hidden keylogger or screen recording spyware\n" +
                "• No covert location stalking without active notification\n\n" +
                "Family safety is achieved through mutual agreements, on-device app analysis, and child-initiated alerts.");
        explanation.setTextSize(senior ? 14 : 12);
        explanation.setTextColor(0xFF333333);
        explanation.setLineSpacing(0, 1.25f);
        LinearLayout.LayoutParams ep = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        ep.topMargin = dp(8);
        explanation.setLayoutParams(ep);
        card.addView(explanation);
        return card;
    }

    // ──────────────────────────────────────────────────────────────────
    // Backend status banner — honest disclosure
    // ──────────────────────────────────────────────────────────────────

    private View buildBackendStatusBanner(FamilyRepository repo) {
        LinearLayout banner = new LinearLayout(activity);
        banner.setOrientation(LinearLayout.VERTICAL);
        banner.setBackgroundResource(repo.isServerBacked() ? R.drawable.bg_pill_emerald : R.drawable.bg_pill_dark);
        banner.setPadding(dp(14), dp(10), dp(14), dp(10));
        LinearLayout.LayoutParams bp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        bp.bottomMargin = dp(16);
        banner.setLayoutParams(bp);

        TextView tvHead = new TextView(activity);
        tvHead.setText(repo.isServerBacked() ? "✅ BACKEND CONNECTED" : "⚠️ LOCAL-ONLY MODE — No Backend Configured");
        tvHead.setTextSize(12);
        tvHead.setTextColor(repo.isServerBacked() ? 0xFF386B57 : 0xFFB35900);
        tvHead.setTypeface(null, android.graphics.Typeface.BOLD);
        banner.addView(tvHead);

        TextView tvDetail = new TextView(activity);
        if (repo.isServerBacked()) {
            tvDetail.setText("Pairing codes are server-verified. SOS notifications are delivered via FCM.");
        } else {
            tvDetail.setText(
                    "Family features require Firebase configuration. In this mode:\n" +
                    "• Pairing codes are device-local and cannot be validated by another phone\n" +
                    "• SOS requests are saved locally — no notification is sent to anyone\n" +
                    "• Trusted contacts can still be called directly using the 📞 button\n\n" +
                    "To activate real family features, see FIREBASE_SETUP.md in the project root.");
        }
        tvDetail.setTextSize(11);
        tvDetail.setTextColor(0xFF555555);
        tvDetail.setLineSpacing(0, 1.2f);
        LinearLayout.LayoutParams dp2 = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        dp2.topMargin = dp(4);
        tvDetail.setLayoutParams(dp2);
        banner.addView(tvDetail);
        return banner;
    }

    // ──────────────────────────────────────────────────────────────────
    // Pairing code card — real cryptographic code, real lifecycle
    // ──────────────────────────────────────────────────────────────────

    private View buildPairingCodeCard(boolean senior, FamilyRepository repo) {
        LinearLayout card = buildCard(dp(16));

        TextView label = new TextView(activity);
        label.setText("PAIR A FAMILY MEMBER'S DEVICE");
        label.setTextSize(senior ? 13 : 11);
        label.setTextColor(0xFF888888);
        label.setTypeface(null, android.graphics.Typeface.BOLD);
        card.addView(label);

        // Code display container
        pairingCodeContainer = new LinearLayout(activity);
        pairingCodeContainer.setOrientation(LinearLayout.VERTICAL);
        pairingCodeContainer.setBackgroundResource(R.drawable.bg_pill_dark);
        pairingCodeContainer.setPadding(dp(14), dp(12), dp(14), dp(12));
        LinearLayout.LayoutParams ccp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        ccp.topMargin = dp(10);
        pairingCodeContainer.setLayoutParams(ccp);

        tvPairingCode = new TextView(activity);
        tvPairingCode.setText("—");
        tvPairingCode.setTextSize(senior ? 28 : 24);
        tvPairingCode.setTextColor(0xFF141414);
        tvPairingCode.setTypeface(android.graphics.Typeface.MONOSPACE, android.graphics.Typeface.BOLD);
        tvPairingCode.setLetterSpacing(0.12f);
        pairingCodeContainer.addView(tvPairingCode);

        tvPairingStatus = new TextView(activity);
        tvPairingStatus.setText("No active code. Tap below to generate one.");
        tvPairingStatus.setTextSize(senior ? 13 : 11);
        tvPairingStatus.setTextColor(0xFF666666);
        LinearLayout.LayoutParams psp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        psp.topMargin = dp(4);
        tvPairingStatus.setLayoutParams(psp);
        pairingCodeContainer.addView(tvPairingStatus);

        tvPairingExpiry = new TextView(activity);
        tvPairingExpiry.setTextSize(senior ? 12 : 10);
        tvPairingExpiry.setTextColor(0xFF888888);
        tvPairingExpiry.setVisibility(View.GONE);
        pairingCodeContainer.addView(tvPairingExpiry);

        card.addView(pairingCodeContainer);

        // Buttons row
        LinearLayout btnRow = new LinearLayout(activity);
        btnRow.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams brp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        brp.topMargin = dp(10);
        btnRow.setLayoutParams(brp);

        Button btnGenerate = new Button(activity);
        btnGenerate.setText("🔑 Generate New Code");
        btnGenerate.setBackgroundResource(R.drawable.bg_pill_black);
        btnGenerate.setTextColor(0xFFFFFFFF);
        btnGenerate.setTextSize(senior ? 13 : 11);
        btnGenerate.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams bgp = new LinearLayout.LayoutParams(0, dp(46), 1f);
        bgp.rightMargin = dp(6);
        btnGenerate.setLayoutParams(bgp);
        btnGenerate.setOnClickListener(v -> generateNewPairingCode(repo, senior));
        btnRow.addView(btnGenerate);

        Button btnCopy = new Button(activity);
        btnCopy.setText("📋 Copy");
        btnCopy.setBackgroundResource(R.drawable.bg_pill_dark);
        btnCopy.setTextColor(0xFF141414);
        btnCopy.setTextSize(senior ? 13 : 11);
        btnCopy.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams bcp = new LinearLayout.LayoutParams(0, dp(46), 0.5f);
        btnCopy.setLayoutParams(bcp);
        btnCopy.setOnClickListener(v -> {
            if (currentChallenge != null && currentChallenge.isValid()) {
                ClipboardManager cm = (ClipboardManager) activity.getSystemService(Context.CLIPBOARD_SERVICE);
                if (cm != null) cm.setPrimaryClip(ClipData.newPlainText("Saathi Pairing Code", currentChallenge.getCode()));
                Toast.makeText(activity, "Pairing code copied", Toast.LENGTH_SHORT).show();
            } else {
                Toast.makeText(activity, "Generate a code first", Toast.LENGTH_SHORT).show();
            }
        });
        btnRow.addView(btnCopy);
        card.addView(btnRow);

        // Instructions
        TextView instructions = new TextView(activity);
        instructions.setText(senior
                ? "Tap 'Generate New Code' to create a secure 8-character code. Give this code to the person joining your family circle. It is valid for 15 minutes and can only be used once."
                : "Share this 8-character code (expires in 15 min, single use). The joining device enters it in their Saathi app. If no Firebase is configured, this code is local-only and cannot be validated by another device.");
        instructions.setTextSize(senior ? 13 : 11);
        instructions.setTextColor(0xFF666666);
        instructions.setLineSpacing(0, 1.2f);
        LinearLayout.LayoutParams ip = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        ip.topMargin = dp(8);
        instructions.setLayoutParams(ip);
        card.addView(instructions);

        // If there's already a valid challenge from this session, show it
        if (currentChallenge != null && currentChallenge.isValid()) {
            refreshPairingCodeDisplay();
        }

        return card;
    }

    private void generateNewPairingCode(FamilyRepository repo, boolean senior) {
        // Cancel any previous valid challenge first
        if (currentChallenge != null && currentChallenge.isValid()) {
            repo.cancelChallenge(currentChallenge.getChallengeId(), new FamilyRepository.Callback<Void>() {
                @Override public void onSuccess(Void result) { /* old code cancelled */ }
                @Override public void onError(String errorMessage) { /* best-effort */ }
            });
        }

        tvPairingCode.setText("…");
        tvPairingStatus.setText("Generating…");
        tvPairingExpiry.setVisibility(View.GONE);

        Executors.newSingleThreadExecutor().execute(() ->
            repo.createPairingChallenge(PLACEHOLDER_FAMILY_ID, new FamilyRepository.Callback<PairingChallenge>() {
                @Override
                public void onSuccess(PairingChallenge challenge) {
                    currentChallenge = challenge;
                    mainHandler.post(() -> refreshPairingCodeDisplay());
                }

                @Override
                public void onError(String errorMessage) {
                    mainHandler.post(() -> {
                        tvPairingCode.setText("ERROR");
                        tvPairingStatus.setText("Failed to generate code: " + errorMessage);
                    });
                }
            })
        );
    }

    private void refreshPairingCodeDisplay() {
        if (currentChallenge == null) return;
        if (!currentChallenge.isValid()) {
            tvPairingCode.setText("EXPIRED");
            tvPairingStatus.setText("Code expired. Tap 'Generate New Code' for a fresh one.");
            tvPairingExpiry.setVisibility(View.GONE);
            return;
        }
        tvPairingCode.setText(currentChallenge.getCode());
        boolean isLocal = currentChallenge.getState() == PairingChallenge.ChallengeState.LOCAL_ONLY;
        tvPairingStatus.setText(isLocal
                ? "LOCAL CODE — valid on this device only (no backend configured)"
                : "Active — waiting for family member to enter this code");
        tvPairingExpiry.setText("Expires in " + currentChallenge.remainingMinutes() + " min  •  Single use");
        tvPairingExpiry.setVisibility(View.VISIBLE);

        // Refresh expiry countdown every minute
        mainHandler.postDelayed(this::refreshPairingCodeDisplay, 60_000);
    }

    // ──────────────────────────────────────────────────────────────────
    // SOS section — real lifecycle display
    // ──────────────────────────────────────────────────────────────────

    private View buildSosSection(boolean senior, FamilyRepository repo) {
        LinearLayout section = new LinearLayout(activity);
        section.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams sp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        sp.bottomMargin = dp(18);
        section.setLayoutParams(sp);

        TextView label = new TextView(activity);
        label.setText("🆘 HELP REQUEST (SOS)");
        label.setTextSize(senior ? 15 : 13);
        label.setTextColor(0xFF141414);
        label.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = dp(10);
        label.setLayoutParams(lp);
        section.addView(label);

        // Big SOS button
        Button btnSos = new Button(activity);
        btnSos.setText(senior ? "🆘 I NEED HELP — Send Alert to Family" : "🆘 Send Help Request");
        btnSos.setBackgroundResource(R.drawable.bg_pill_crimson);
        btnSos.setTextColor(0xFFA63232);
        btnSos.setTextSize(senior ? 18 : 15);
        btnSos.setTypeface(null, android.graphics.Typeface.BOLD);
        btnSos.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(56)));
        btnSos.setOnClickListener(v -> showSosConfirmDialog(senior, repo));
        section.addView(btnSos);

        // SOS status display
        sosStatusContainer = new LinearLayout(activity);
        sosStatusContainer.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams sscp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        sscp.topMargin = dp(12);
        sosStatusContainer.setLayoutParams(sscp);

        tvSosStatus = new TextView(activity);
        tvSosStatus.setTextSize(senior ? 13 : 11);
        tvSosStatus.setTextColor(0xFF555555);
        tvSosStatus.setLineSpacing(0, 1.2f);
        sosStatusContainer.addView(tvSosStatus);

        if (lastSosRequest != null) {
            refreshSosStatusDisplay();
        } else {
            tvSosStatus.setText("No help request sent this session.");
        }

        section.addView(sosStatusContainer);

        // Disclaimer
        TextView disclaimer = new TextView(activity);
        disclaimer.setText(
                "⚠️ Important: A help request notifies your trusted contacts through Saathi. " +
                (!repo.isServerBacked()
                        ? "Without Firebase, no notification is sent — call your contact directly using the 📞 button below."
                        : "Delivery is confirmed only when the recipient's device acknowledges the alert. Always follow up with a direct call if urgent."));
        disclaimer.setTextSize(senior ? 12 : 10);
        disclaimer.setTextColor(0xFF888888);
        disclaimer.setLineSpacing(0, 1.2f);
        LinearLayout.LayoutParams dp2 = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        dp2.topMargin = dp(8);
        disclaimer.setLayoutParams(dp2);
        section.addView(disclaimer);

        return section;
    }

    private void showSosConfirmDialog(boolean senior, FamilyRepository repo) {
        // Build reason selection
        LinearLayout form = new LinearLayout(activity);
        form.setOrientation(LinearLayout.VERTICAL);
        form.setPadding(dp(20), dp(12), dp(20), dp(12));

        TextView tvIntro = new TextView(activity);
        tvIntro.setText("What is happening? Choose the closest reason:");
        tvIntro.setTextSize(14);
        tvIntro.setTextColor(0xFF333333);
        form.addView(tvIntro);

        RadioGroup rg = new RadioGroup(activity);
        rg.setOrientation(RadioGroup.VERTICAL);
        LinearLayout.LayoutParams rgp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        rgp.topMargin = dp(10);
        rg.setLayoutParams(rgp);

        SosRequest.SosReason[] reasons = SosRequest.SosReason.values();
        for (int i = 0; i < reasons.length; i++) {
            RadioButton rb = new RadioButton(activity);
            rb.setText(reasons[i].displayLabel);
            rb.setId(i);
            rg.addView(rb);
        }
        rg.check(SosRequest.SosReason.NEED_HELP.ordinal());
        form.addView(rg);

        EditText etNote = new EditText(activity);
        etNote.setHint("Optional: add a short note (not shared automatically)");
        LinearLayout.LayoutParams np = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        np.topMargin = dp(10);
        etNote.setLayoutParams(np);
        form.addView(etNote);

        new AlertDialog.Builder(activity)
                .setTitle(senior ? "🆘 Send Help Request" : "Confirm Help Request")
                .setMessage(senior
                        ? "This will send an alert to your trusted family members. Please confirm."
                        : "This sends an SOS to your configured trusted contact. Confirm only if you need help.")
                .setView(form)
                .setPositiveButton("Send Help Request", (d, w) -> {
                    int selectedId = rg.getCheckedRadioButtonId();
                    SosRequest.SosReason reason = (selectedId >= 0 && selectedId < reasons.length)
                            ? reasons[selectedId] : SosRequest.SosReason.NEED_HELP;
                    String note = etNote.getText().toString().trim();
                    dispatchSosRequest(reason, note.isEmpty() ? null : note, senior, repo);
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void dispatchSosRequest(SosRequest.SosReason reason, String optionalNote, boolean senior, FamilyRepository repo) {
        List<TrustedHelper> helpers = AppState.get().getStorageRepository().getTrustedHelpers();
        String recipientId = helpers.isEmpty()
                ? "no-trusted-contact"
                : "trusted-" + helpers.get(0).getHelperId(); // first trusted helper

        SosRequest request = new SosRequest(
                UUID.randomUUID().toString(),
                PLACEHOLDER_DEVICE_ID,
                "This device",
                PLACEHOLDER_FAMILY_ID,
                recipientId,
                reason,
                null,          // createdAt = now
                optionalNote,  // only if user typed something
                false, 0, 0, 0, // no location: not asked, not included
                SosRequest.DeliveryStatus.DRAFT
        );

        lastSosRequest = request;
        refreshSosStatusDisplay();

        Executors.newSingleThreadExecutor().execute(() ->
            repo.submitSosRequest(request, new FamilyRepository.ProgressCallback<SosRequest>() {
                @Override
                public void onProgress(SosRequest item, String stageName) {
                    mainHandler.post(() -> refreshSosStatusDisplay());
                }

                @Override
                public void onComplete(SosRequest item) {
                    mainHandler.post(() -> {
                        refreshSosStatusDisplay();
                        if (item.getDeliveryStatus() == SosRequest.DeliveryStatus.LOCAL_ONLY) {
                            Toast.makeText(activity,
                                    "Help request saved locally. No notification sent — please call your contact directly.",
                                    Toast.LENGTH_LONG).show();
                        }
                    });
                }

                @Override
                public void onError(String errorMessage) {
                    mainHandler.post(() -> {
                        tvSosStatus.setText("❌ Error submitting request: " + errorMessage +
                                "\nPlease call your trusted contact directly.");
                    });
                }
            })
        );
    }

    private void refreshSosStatusDisplay() {
        if (lastSosRequest == null || tvSosStatus == null) return;

        SosRequest.DeliveryStatus status = lastSosRequest.getDeliveryStatus();
        String emoji = statusEmoji(status);
        tvSosStatus.setText(emoji + " Help Request Status: " + lastSosRequest.getDisplayStatus() +
                "\nReason: " + lastSosRequest.getReason().displayLabel +
                "\nID: " + lastSosRequest.getRequestId().substring(0, 8) + "…");
        tvSosStatus.setTextColor(status == SosRequest.DeliveryStatus.NOTIFICATION_FAILED ? 0xFFA63232
                : status == SosRequest.DeliveryStatus.DELIVERED ? 0xFF386B57 : 0xFF555555);
    }

    private String statusEmoji(SosRequest.DeliveryStatus status) {
        switch (status) {
            case DRAFT: return "📝";
            case CONFIRMED_BY_USER: return "⬆️";
            case BACKEND_ACCEPTED: return "☁️";
            case NOTIFICATION_QUEUED: return "📨";
            case DELIVERED: return "✅";
            case NOTIFICATION_FAILED: return "❌";
            case LOCAL_ONLY: return "💾";
            case CANCELLED_BEFORE_SEND: return "🚫";
            default: return "❓";
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // Safety reports — unchanged structure, removed hardcoded data note
    // ──────────────────────────────────────────────────────────────────

    private View buildSafetyReportsSection(boolean senior) {
        LinearLayout section = new LinearLayout(activity);
        section.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams sp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        sp.bottomMargin = dp(18);
        section.setLayoutParams(sp);

        TextView label = new TextView(activity);
        label.setText("CHILD & SENIOR INITIATED SAFETY REPORTS");
        label.setTextSize(senior ? 14 : 11);
        label.setTextColor(0xFF888888);
        label.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = dp(10);
        label.setLayoutParams(lp);
        section.addView(label);

        List<SafetyReport> reports = AppState.get().getSafetyReports();
        if (reports.isEmpty()) {
            TextView empty = new TextView(activity);
            empty.setText("No safety reports yet. These appear when a family member submits one.");
            empty.setTextSize(senior ? 13 : 11);
            empty.setTextColor(0xFF888888);
            section.addView(empty);
        } else {
            SimpleDateFormat sdf = new SimpleDateFormat("dd MMM, hh:mm a", Locale.getDefault());
            for (SafetyReport rep : reports) {
                section.addView(buildSafetyReportItem(rep, senior, sdf));
            }
        }

        // Note about demo data
        TextView note = new TextView(activity);
        note.setText("ℹ️ Reports shown above are seeded demonstration entries. Real child-submitted reports will appear here once the Kids app is connected.");
        note.setTextSize(senior ? 11 : 9);
        note.setTextColor(0xFF888888);
        LinearLayout.LayoutParams np = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        np.topMargin = dp(8);
        note.setLayoutParams(np);
        section.addView(note);

        return section;
    }

    private View buildSafetyReportItem(SafetyReport rep, boolean senior, SimpleDateFormat sdf) {
        LinearLayout item = new LinearLayout(activity);
        item.setOrientation(LinearLayout.VERTICAL);
        item.setBackgroundResource(R.drawable.bg_card_interactive);
        item.setPadding(dp(16), dp(14), dp(16), dp(14));
        LinearLayout.LayoutParams ip = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        ip.bottomMargin = dp(8);
        item.setLayoutParams(ip);

        LinearLayout row = new LinearLayout(activity);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);

        TextView tvCategory = new TextView(activity);
        tvCategory.setText(rep.getCategory() + " (" + rep.getSubmittedBy() + ")");
        tvCategory.setTextSize(senior ? 15 : 13);
        tvCategory.setTextColor(0xFF141414);
        tvCategory.setTypeface(null, android.graphics.Typeface.BOLD);
        row.addView(tvCategory);
        row.addView(flexSpacer());

        TextView tvDate = new TextView(activity);
        tvDate.setText(sdf.format(rep.getTimestamp()));
        tvDate.setTextSize(senior ? 12 : 10);
        tvDate.setTextColor(0xFF888888);
        row.addView(tvDate);
        item.addView(row);

        TextView tvExcerpt = new TextView(activity);
        tvExcerpt.setText("\"" + rep.getExcerpt() + "\"");
        tvExcerpt.setTextSize(senior ? 14 : 12);
        tvExcerpt.setTextColor(0xFF666666);
        LinearLayout.LayoutParams ep = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        ep.topMargin = dp(6);
        tvExcerpt.setLayoutParams(ep);
        item.addView(tvExcerpt);

        TextView tvAction = new TextView(activity);
        tvAction.setText("Action: " + rep.getActionTaken());
        tvAction.setTextSize(senior ? 13 : 11);
        tvAction.setTextColor(0xFF386B57);
        tvAction.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams ap = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        ap.topMargin = dp(4);
        tvAction.setLayoutParams(ap);
        item.addView(tvAction);
        return item;
    }

    // ──────────────────────────────────────────────────────────────────
    // Trusted contacts — persistent local management + real delete
    // ──────────────────────────────────────────────────────────────────

    private View buildTrustedContactsSection(boolean senior) {
        LinearLayout section = new LinearLayout(activity);
        section.setOrientation(LinearLayout.VERTICAL);
        section.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        LinearLayout row = new LinearLayout(activity);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams rp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        rp.bottomMargin = dp(10);
        row.setLayoutParams(rp);

        TextView label = new TextView(activity);
        label.setText("TRUSTED EMERGENCY HELPERS");
        label.setTextSize(senior ? 14 : 11);
        label.setTextColor(0xFF888888);
        label.setTypeface(null, android.graphics.Typeface.BOLD);
        row.addView(label);
        row.addView(flexSpacer());

        TextView btnAdd = new TextView(activity);
        btnAdd.setText("+ Add Helper");
        btnAdd.setTextSize(senior ? 14 : 12);
        btnAdd.setTextColor(0xFF141414);
        btnAdd.setTypeface(null, android.graphics.Typeface.BOLD);
        btnAdd.setOnClickListener(v -> showAddHelperDialog());
        row.addView(btnAdd);
        section.addView(row);

        List<TrustedHelper> helpers = AppState.get().getStorageRepository().getTrustedHelpers();
        for (TrustedHelper th : helpers) {
            section.addView(buildHelperItem(th, senior));
        }
        return section;
    }

    private View buildHelperItem(TrustedHelper th, boolean senior) {
        LinearLayout item = new LinearLayout(activity);
        item.setOrientation(LinearLayout.HORIZONTAL);
        item.setGravity(Gravity.CENTER_VERTICAL);
        item.setBackgroundResource(R.drawable.bg_card_cred);
        item.setPadding(dp(16), dp(12), dp(16), dp(12));
        LinearLayout.LayoutParams ip = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        ip.bottomMargin = dp(8);
        item.setLayoutParams(ip);

        LinearLayout col = new LinearLayout(activity);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        TextView tvName = new TextView(activity);
        tvName.setText(th.getName());
        tvName.setTextSize(senior ? 16 : 14);
        tvName.setTextColor(0xFF141414);
        tvName.setTypeface(null, android.graphics.Typeface.BOLD);
        col.addView(tvName);

        TextView tvPhone = new TextView(activity);
        tvPhone.setText(th.getPhoneNumber() + " • " + th.getRelationship());
        tvPhone.setTextSize(senior ? 13 : 11);
        tvPhone.setTextColor(0xFF666666);
        col.addView(tvPhone);
        item.addView(col);

        Button btnCall = new Button(activity);
        btnCall.setText("📞");
        btnCall.setBackgroundResource(R.drawable.bg_pill_black);
        btnCall.setTextColor(0xFFFFFFFF);
        btnCall.setTextSize(senior ? 14 : 12);
        btnCall.setLayoutParams(new LinearLayout.LayoutParams(dp(48), dp(48)));
        btnCall.setOnClickListener(v -> {
            Intent dial = new Intent(Intent.ACTION_DIAL);
            dial.setData(Uri.parse("tel:" + th.getPhoneNumber().replaceAll("[^0-9+]", "")));
            try { activity.startActivity(dial); } catch (Exception ignored) {}
        });
        item.addView(btnCall);

        View spacer = new View(activity);
        spacer.setLayoutParams(new LinearLayout.LayoutParams(dp(6), 1));
        item.addView(spacer);

        Button btnRemove = new Button(activity);
        btnRemove.setText("🗑");
        btnRemove.setBackgroundResource(R.drawable.bg_pill_crimson);
        btnRemove.setTextColor(0xFFA63232);
        btnRemove.setTextSize(12);
        btnRemove.setLayoutParams(new LinearLayout.LayoutParams(dp(48), dp(48)));
        btnRemove.setOnClickListener(v ->
            new AlertDialog.Builder(activity)
                .setTitle("Remove Trusted Helper")
                .setMessage("Remove " + th.getName() + " from your trusted helpers? They will no longer receive SOS alerts.")
                .setPositiveButton("Remove", (d, w) -> {
                    AppState.get().getStorageRepository().removeTrustedHelper(th.getHelperId());
                    render();
                })
                .setNegativeButton("Keep", null)
                .show()
        );
        item.addView(btnRemove);
        return item;
    }

    private void showAddHelperDialog() {
        LinearLayout form = new LinearLayout(activity);
        form.setOrientation(LinearLayout.VERTICAL);
        form.setPadding(dp(20), dp(10), dp(20), dp(10));

        EditText etName = new EditText(activity);
        etName.setHint("Helper Name (e.g., Uncle Suresh)");
        form.addView(etName);

        EditText etPhone = new EditText(activity);
        etPhone.setHint("Phone Number (+91 …)");
        etPhone.setInputType(android.text.InputType.TYPE_CLASS_PHONE);
        form.addView(etPhone);

        EditText etRelation = new EditText(activity);
        etRelation.setHint("Relationship (e.g., Uncle, Neighbour)");
        form.addView(etRelation);

        new AlertDialog.Builder(activity)
                .setTitle("Add Trusted Helper")
                .setView(form)
                .setPositiveButton("Save", (d, w) -> {
                    String name  = etName.getText().toString().trim();
                    String phone = etPhone.getText().toString().trim();
                    String rel   = etRelation.getText().toString().trim();
                    if (name.isEmpty() || phone.isEmpty()) {
                        Toast.makeText(activity, "Name and phone number are required.", Toast.LENGTH_SHORT).show();
                        return;
                    }
                    TrustedHelper helper = new TrustedHelper(
                            "th-" + System.currentTimeMillis(), name,
                            rel.isEmpty() ? "TRUSTED_FAMILY" : rel,
                            phone, true);
                    AppState.get().getStorageRepository().addTrustedHelper(helper);
                    render();
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    // ──────────────────────────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────────────────────────

    private LinearLayout buildCard(int bottomMargin) {
        LinearLayout card = new LinearLayout(activity);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundResource(R.drawable.bg_card_cred);
        card.setPadding(dp(18), dp(16), dp(18), dp(16));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        params.bottomMargin = bottomMargin;
        card.setLayoutParams(params);
        return card;
    }

    private View flexSpacer() {
        View sp = new View(activity);
        sp.setLayoutParams(new LinearLayout.LayoutParams(0, 1, 1f));
        return sp;
    }

    private int dp(int val) { return (int) (val * density); }
}
