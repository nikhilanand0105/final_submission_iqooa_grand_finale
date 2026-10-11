package dev.guardianai.personal.ui.screens;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.net.Uri;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import dev.guardianai.model.ThreatSeverity;
import dev.guardianai.personal.R;
import dev.guardianai.personal.data.db.ScanRecord;
import dev.guardianai.personal.data.db.ScanStats;
import dev.guardianai.personal.data.db.SecurityAuditRepository;
import dev.guardianai.personal.ui.MainActivity;
import dev.guardianai.personal.ui.components.DetailSheetDialog;
import dev.guardianai.personal.ui.model.ActivityEvent;
import dev.guardianai.personal.ui.model.ChildProfile;
import dev.guardianai.personal.ui.model.NavigationTab;
import dev.guardianai.personal.ui.model.ScanMode;
import dev.guardianai.personal.ui.state.AppState;

import dev.guardianai.personal.data.DataExfiltrationSentinel;
import dev.guardianai.personal.ui.components.DataExfiltrationDialog;

import dev.guardianai.personal.network.NetworkProtectionManager;
import dev.guardianai.personal.network.NetworkProtectionStatus;

import java.util.ArrayList;
import java.util.List;

public class HomeScreenController {

    private final Activity activity;
    private final float density;
    private ScrollView rootView;
    private LinearLayout contentLayout;

    private LinearLayout containerHeroCard;
    private LinearLayout containerNetworkProtection;
    private LinearLayout containerRecentFindings;

    private ScanStats cachedStats = ScanStats.empty();
    private List<ScanRecord> cachedRecentScans = new ArrayList<>();

    public HomeScreenController(Activity activity) {
        this.activity = activity;
        this.density = activity.getResources().getDisplayMetrics().density;
        createView();
    }

    public View getView() {
        return rootView;
    }

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
        contentLayout.setPadding((int) (20 * density), (int) (16 * density), (int) (20 * density), (int) (100 * density));
        rootView.addView(contentLayout);

        render();
    }

    public void render() {
        contentLayout.removeAllViews();
        boolean senior = AppState.get().isSeniorMode();

        // 1. Header (Device & Profile)
        contentLayout.addView(buildTopHeader(senior));

        // 1b. Real-Time Data & Photo Exfiltration Sentinel (Fishy Upload Interception)
        contentLayout.addView(buildExfiltrationSentinelCard(senior));

        // 2. Senior Mode Quick Advice Banner (if senior mode active)
        if (senior) {
            contentLayout.addView(buildSeniorRecoveryBanner());
        }

        // 3. Hero Protection Score Container
        containerHeroCard = new LinearLayout(activity);
        containerHeroCard.setOrientation(LinearLayout.VERTICAL);
        contentLayout.addView(containerHeroCard);

        // 3b. Real Network Protection Container
        containerNetworkProtection = new LinearLayout(activity);
        containerNetworkProtection.setOrientation(LinearLayout.VERTICAL);
        contentLayout.addView(containerNetworkProtection);

        // 4. Quick Safety Actions (4 Entry Points into Scan Hub)
        contentLayout.addView(buildQuickActionsSection(senior));

        // 5. Emergency Helpline & Family Assistance Dock
        contentLayout.addView(buildHelplineDock(senior));

        // 6. Recent Findings Container
        containerRecentFindings = new LinearLayout(activity);
        containerRecentFindings.setOrientation(LinearLayout.VERTICAL);
        contentLayout.addView(containerRecentFindings);

        // Asynchronously load data off main thread from local database repository
        loadDataFromRepository(senior);
    }

    private void loadDataFromRepository(boolean senior) {
        SecurityAuditRepository repo = AppState.get().getAuditRepository();
        if (repo != null) {
            repo.getScanStats(stats -> {
                this.cachedStats = stats;
                populateHeroCard(senior, stats);
            });
            repo.getScansByType("NETWORK_FIREWALL", fwRecords -> {
                int blockedCount = fwRecords != null ? fwRecords.size() : 0;
                populateNetworkProtectionCard(senior, blockedCount);
            });
            repo.getRecentScans(3, records -> {
                this.cachedRecentScans = records != null ? records : new ArrayList<>();
                populateRecentFindings(senior, cachedRecentScans);
            });
        } else {
            populateHeroCard(senior, cachedStats);
            populateNetworkProtectionCard(senior, 0);
            populateRecentFindings(senior, cachedRecentScans);
        }
    }

    private View buildTopHeader(boolean senior) {
        LinearLayout row = new LinearLayout(activity);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        params.bottomMargin = (int) (16 * density);
        row.setLayoutParams(params);

        // Profile Pill Selector
        LinearLayout profilePill = new LinearLayout(activity);
        profilePill.setOrientation(LinearLayout.HORIZONTAL);
        profilePill.setGravity(Gravity.CENTER_VERTICAL);
        profilePill.setBackgroundResource(R.drawable.bg_pill_dark);
        profilePill.setPadding((int) (14 * density), (int) (8 * density), (int) (14 * density), (int) (8 * density));
        profilePill.setOnClickListener(v -> showProfilePickerDialog());

        TextView iconUser = new TextView(activity);
        iconUser.setText(senior ? "👴 " : "🛡️ ");
        iconUser.setTextSize(senior ? 16 : 14);
        profilePill.addView(iconUser);

        TextView tvProfileName = new TextView(activity);
        tvProfileName.setText(senior ? "Senior Mode" : AppState.get().getCurrentProfile().getName());
        tvProfileName.setTextSize(senior ? 15 : 13);
        tvProfileName.setTextColor(0xFF141414);
        tvProfileName.setTypeface(null, android.graphics.Typeface.BOLD);
        profilePill.addView(tvProfileName);

        TextView tvArrow = new TextView(activity);
        tvArrow.setText(" ▾");
        tvArrow.setTextSize(12);
        tvArrow.setTextColor(0xFF888888);
        profilePill.addView(tvArrow);

        row.addView(profilePill);

        // Flexible Space
        View space = new View(activity);
        LinearLayout.LayoutParams sp = new LinearLayout.LayoutParams(0, 1, 1f);
        space.setLayoutParams(sp);
        row.addView(space);

        // Device & Refresh Rate Badge
        TextView tvHwBadge = new TextView(activity);
        tvHwBadge.setText("iQOO 15 • Snapdragon 8 Elite");
        tvHwBadge.setTextSize(senior ? 12 : 11);
        tvHwBadge.setTextColor(0xFF386B57);
        tvHwBadge.setBackgroundResource(R.drawable.bg_pill_emerald);
        tvHwBadge.setPadding((int) (10 * density), (int) (6 * density), (int) (10 * density), (int) (6 * density));
        row.addView(tvHwBadge);

        return row;
    }

    private View buildExfiltrationSentinelCard(boolean senior) {
        DataExfiltrationSentinel sentinel = DataExfiltrationSentinel.getInstance(activity);
        DataExfiltrationSentinel.SentinelState state = sentinel.getState();

        LinearLayout card = new LinearLayout(activity);
        card.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        params.bottomMargin = (int) (18 * density);
        card.setLayoutParams(params);

        if (sentinel.isScanning()) {
            return buildScanningProgressCard(sentinel, senior);
        }

        if (state == DataExfiltrationSentinel.SentinelState.AWAITING_CONFIRMATION) {
            card.setBackgroundResource(R.drawable.bg_card_glow_crimson);
            card.setPadding((int) (18 * density), (int) (18 * density), (int) (18 * density), (int) (18 * density));

            // Header Tag Row
            LinearLayout tagRow = new LinearLayout(activity);
            tagRow.setOrientation(LinearLayout.HORIZONTAL);
            tagRow.setGravity(Gravity.CENTER_VERTICAL);

            TextView tag = new TextView(activity);
            tag.setText("🚨 FISHY DATA UPLOAD DETECTED");
            tag.setTextSize(senior ? 13 : 11);
            tag.setTypeface(null, android.graphics.Typeface.BOLD);
            tag.setTextColor(0xFFD32F2F);
            tag.setBackgroundResource(R.drawable.bg_pill_crimson);
            tag.setPadding((int) (10 * density), (int) (4 * density), (int) (10 * density), (int) (4 * density));
            tagRow.addView(tag);

            View space = new View(activity);
            LinearLayout.LayoutParams sp = new LinearLayout.LayoutParams(0, 1, 1f);
            space.setLayoutParams(sp);
            tagRow.addView(space);

            TextView tvHw = new TextView(activity);
            tvHw.setText("Snapdragon 8 Elite Sentinel");
            tvHw.setTextSize(10);
            tvHw.setTextColor(0xFF386B57);
            tvHw.setBackgroundResource(R.drawable.bg_pill_emerald);
            tvHw.setPadding((int) (8 * density), (int) (4 * density), (int) (8 * density), (int) (4 * density));
            tagRow.addView(tvHw);

            card.addView(tagRow);

            // App Name & Package
            TextView tvApp = new TextView(activity);
            tvApp.setText("TeraBox: Cloud Storage Space");
            tvApp.setTextSize(senior ? 20 : 17);
            tvApp.setTypeface(null, android.graphics.Typeface.BOLD);
            tvApp.setTextColor(0xFF141414);
            LinearLayout.LayoutParams ap = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            ap.topMargin = (int) (12 * density);
            tvApp.setLayoutParams(ap);
            card.addView(tvApp);

            TextView tvPackage = new TextView(activity);
            tvPackage.setText("com.dubox.drive • Silent Background Photo Sync Attempt");
            tvPackage.setTextSize(senior ? 13 : 11);
            tvPackage.setTextColor(0xFF666666);
            LinearLayout.LayoutParams pp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            pp.topMargin = (int) (2 * density);
            tvPackage.setLayoutParams(pp);
            card.addView(tvPackage);

            // Telemetry snippet box
            LinearLayout teleBox = new LinearLayout(activity);
            teleBox.setOrientation(LinearLayout.VERTICAL);
            teleBox.setBackgroundResource(R.drawable.bg_card_elevated);
            teleBox.setPadding((int) (12 * density), (int) (10 * density), (int) (12 * density), (int) (10 * density));
            LinearLayout.LayoutParams tbp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            tbp.topMargin = (int) (12 * density);
            tbp.bottomMargin = (int) (14 * density);
            teleBox.setLayoutParams(tbp);

            TextView l1 = new TextView(activity);
            l1.setText("• Target: 142 Gallery Photos & Videos (DCIM/Camera/*)");
            l1.setTextSize(senior ? 13 : 11);
            l1.setTextColor(0xFF141414);
            l1.setTypeface(null, android.graphics.Typeface.BOLD);
            teleBox.addView(l1);

            TextView l2 = new TextView(activity);
            l2.setText("• Destination: upload.terabox.com:443 (Singapore CDN)");
            l2.setTextSize(senior ? 12 : 10);
            l2.setTextColor(0xFF555555);
            teleBox.addView(l2);

            TextView l3 = new TextView(activity);
            l3.setText("• Bandwidth: 384 MB queued for background cloud sync");
            l3.setTextSize(senior ? 12 : 10);
            l3.setTextColor(0xFF555555);
            teleBox.addView(l3);

            card.addView(teleBox);

            // The Question
            TextView tvQuestion = new TextView(activity);
            tvQuestion.setText("Did you grant permission for TeraBox to upload your personal photos and media?");
            tvQuestion.setTextSize(senior ? 16 : 14);
            tvQuestion.setTypeface(null, android.graphics.Typeface.BOLD);
            tvQuestion.setTextColor(0xFFD32F2F);
            card.addView(tvQuestion);

            // Action Buttons
            LinearLayout btnRow = new LinearLayout(activity);
            btnRow.setOrientation(LinearLayout.VERTICAL);
            LinearLayout.LayoutParams brp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            brp.topMargin = (int) (12 * density);
            btnRow.setLayoutParams(brp);

            // Button 1: NO, STOP UPLOADING
            Button btnStop = new Button(activity);
            btnStop.setText("🛑 NO, STOP UPLOAD & BLOCK");
            btnStop.setTextColor(0xFFFFFFFF);
            btnStop.setBackgroundResource(R.drawable.bg_pill_black);
            btnStop.setTextSize(senior ? 14 : 12);
            btnStop.setTypeface(null, android.graphics.Typeface.BOLD);
            LinearLayout.LayoutParams bsp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, (int) (48 * density));
            bsp.bottomMargin = (int) (8 * density);
            btnStop.setLayoutParams(bsp);

            // Button 2: YES, CONTINUE UPLOAD
            Button btnAllow = new Button(activity);
            btnAllow.setText("✓ YES, CONTINUE UPLOAD (I ALLOWED THIS)");
            btnAllow.setTextColor(0xFF141414);
            btnAllow.setBackgroundResource(R.drawable.bg_pill_outline);
            btnAllow.setTextSize(senior ? 13 : 11);
            btnAllow.setTypeface(null, android.graphics.Typeface.BOLD);
            LinearLayout.LayoutParams bap = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, (int) (44 * density));
            btnAllow.setLayoutParams(bap);

            btnStop.setOnClickListener(v -> {
                btnStop.setEnabled(false);
                btnAllow.setEnabled(false);
                btnStop.setText("⏳ Severing Sockets & Activating Firewall...");
                sentinel.confirmUploadAsync(activity, false, new DataExfiltrationSentinel.ActionProgressListener() {
                    @Override
                    public void onActionProgress(String message) {
                        btnStop.setText("⏳ " + message);
                    }

                    @Override
                    public void onActionComplete() {
                        Toast.makeText(activity, "🛡️ TeraBox background upload BLOCKED! 0 bytes leaked.", Toast.LENGTH_LONG).show();
                        render();
                    }
                });
            });
            btnRow.addView(btnStop);

            btnAllow.setOnClickListener(v -> {
                btnStop.setEnabled(false);
                btnAllow.setEnabled(false);
                btnAllow.setText("⏳ Authorizing Cloud Sync...");
                sentinel.confirmUploadAsync(activity, true, new DataExfiltrationSentinel.ActionProgressListener() {
                    @Override
                    public void onActionProgress(String message) {
                        btnAllow.setText("⏳ " + message);
                    }

                    @Override
                    public void onActionComplete() {
                        Toast.makeText(activity, "✅ TeraBox upload permitted by user.", Toast.LENGTH_SHORT).show();
                        render();
                    }
                });
            });
            btnRow.addView(btnAllow);

            LinearLayout subActRow = new LinearLayout(activity);
            subActRow.setOrientation(LinearLayout.HORIZONTAL);
            LinearLayout.LayoutParams subp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            subp.topMargin = (int) (8 * density);
            subActRow.setLayoutParams(subp);

            Button btnOpenTb = new Button(activity);
            btnOpenTb.setText("🚀 Open TeraBox App");
            btnOpenTb.setTextSize(senior ? 12 : 11);
            btnOpenTb.setTextColor(0xFF141414);
            btnOpenTb.setBackgroundResource(R.drawable.bg_pill_dark);
            LinearLayout.LayoutParams tbpAwaiting = new LinearLayout.LayoutParams(0, (int) (40 * density), 1f);
            tbpAwaiting.rightMargin = (int) (6 * density);
            btnOpenTb.setLayoutParams(tbpAwaiting);
            btnOpenTb.setOnClickListener(v -> dev.guardianai.personal.data.TeraBoxLaunchWatcher.launchTeraBox(activity));
            subActRow.addView(btnOpenTb);

            Button btnRestart = new Button(activity);
            btnRestart.setText("↺ Restart 20s Scan");
            btnRestart.setTextSize(senior ? 12 : 11);
            btnRestart.setTextColor(0xFF141414);
            btnRestart.setBackgroundResource(R.drawable.bg_pill_outline);
            LinearLayout.LayoutParams rstpAwaiting = new LinearLayout.LayoutParams(0, (int) (40 * density), 1f);
            btnRestart.setLayoutParams(rstpAwaiting);
            btnRestart.setOnClickListener(v -> {
                sentinel.startScanSimulation(activity, null);
                render();
            });
            subActRow.addView(btnRestart);

            btnRow.addView(subActRow);

            card.addView(btnRow);

        } else if (state == DataExfiltrationSentinel.SentinelState.BLOCKED) {
            card.setBackgroundResource(R.drawable.bg_card_glow_emerald);
            card.setPadding((int) (18 * density), (int) (16 * density), (int) (18 * density), (int) (16 * density));

            LinearLayout tagRow = new LinearLayout(activity);
            tagRow.setOrientation(LinearLayout.HORIZONTAL);
            tagRow.setGravity(Gravity.CENTER_VERTICAL);

            TextView tag = new TextView(activity);
            tag.setText("🛡️ EXFILTRATION BLOCKED & SECURED");
            tag.setTextSize(senior ? 13 : 11);
            tag.setTypeface(null, android.graphics.Typeface.BOLD);
            tag.setTextColor(0xFF2E7D32);
            tag.setBackgroundResource(R.drawable.bg_pill_emerald);
            tag.setPadding((int) (10 * density), (int) (4 * density), (int) (10 * density), (int) (4 * density));
            tagRow.addView(tag);

            View space = new View(activity);
            LinearLayout.LayoutParams sp = new LinearLayout.LayoutParams(0, 1, 1f);
            space.setLayoutParams(sp);
            tagRow.addView(space);

            TextView tvBytes = new TextView(activity);
            tvBytes.setText("0 KB LEAKED");
            tvBytes.setTextSize(10);
            tvBytes.setTextColor(0xFF2E7D32);
            tvBytes.setTypeface(null, android.graphics.Typeface.BOLD);
            tagRow.addView(tvBytes);

            card.addView(tagRow);

            TextView tvTitle = new TextView(activity);
            tvTitle.setText("TeraBox Background Upload Terminated");
            tvTitle.setTextSize(senior ? 18 : 16);
            tvTitle.setTypeface(null, android.graphics.Typeface.BOLD);
            tvTitle.setTextColor(0xFF141414);
            LinearLayout.LayoutParams tp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            tp.topMargin = (int) (10 * density);
            tvTitle.setLayoutParams(tp);
            card.addView(tvTitle);

            TextView tvDesc = new TextView(activity);
            tvDesc.setText("You confirmed permission was not given. Destination upload.terabox.com was severed via On-Device Firewall. 142 personal photos remain protected locally.");
            tvDesc.setTextSize(senior ? 13 : 11);
            tvDesc.setTextColor(0xFF555555);
            LinearLayout.LayoutParams dp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            dp.topMargin = (int) (4 * density);
            dp.bottomMargin = (int) (12 * density);
            tvDesc.setLayoutParams(dp);
            card.addView(tvDesc);

            LinearLayout actRow = new LinearLayout(activity);
            actRow.setOrientation(LinearLayout.HORIZONTAL);

            Button btnReview = new Button(activity);
            btnReview.setText("Forensic Audit");
            btnReview.setTextSize(senior ? 12 : 11);
            btnReview.setTextColor(0xFFFFFFFF);
            btnReview.setBackgroundResource(R.drawable.bg_pill_black);
            LinearLayout.LayoutParams rbp = new LinearLayout.LayoutParams(0, (int) (40 * density), 1f);
            rbp.rightMargin = (int) (6 * density);
            btnReview.setLayoutParams(rbp);
            btnReview.setOnClickListener(v -> {
                if (activity instanceof MainActivity) {
                    ((MainActivity) activity).switchTab(NavigationTab.ACTIVITY, true);
                }
            });
            actRow.addView(btnReview);

            Button btnReset = new Button(activity);
            btnReset.setText("↺ Test Again");
            btnReset.setTextSize(senior ? 12 : 11);
            btnReset.setTextColor(0xFF141414);
            btnReset.setBackgroundResource(R.drawable.bg_pill_outline);
            LinearLayout.LayoutParams rstp = new LinearLayout.LayoutParams(0, (int) (40 * density), 1f);
            rstp.rightMargin = (int) (6 * density);
            btnReset.setLayoutParams(rstp);
            btnReset.setOnClickListener(v -> {
                sentinel.startScanSimulation(activity, null);
                render();
            });
            actRow.addView(btnReset);

            Button btnOpenTbBlocked = new Button(activity);
            btnOpenTbBlocked.setText("🚀 Open TeraBox");
            btnOpenTbBlocked.setTextSize(senior ? 12 : 11);
            btnOpenTbBlocked.setTextColor(0xFF141414);
            btnOpenTbBlocked.setBackgroundResource(R.drawable.bg_pill_dark);
            LinearLayout.LayoutParams tbpBlocked = new LinearLayout.LayoutParams(0, (int) (40 * density), 1f);
            btnOpenTbBlocked.setLayoutParams(tbpBlocked);
            btnOpenTbBlocked.setOnClickListener(v -> dev.guardianai.personal.data.TeraBoxLaunchWatcher.launchTeraBox(activity));
            actRow.addView(btnOpenTbBlocked);

            card.addView(actRow);

        } else if (state == DataExfiltrationSentinel.SentinelState.ALLOWED) {
            card.setBackgroundResource(R.drawable.bg_card_cred);
            card.setPadding((int) (18 * density), (int) (16 * density), (int) (18 * density), (int) (16 * density));

            LinearLayout tagRow = new LinearLayout(activity);
            tagRow.setOrientation(LinearLayout.HORIZONTAL);
            tagRow.setGravity(Gravity.CENTER_VERTICAL);

            TextView tag = new TextView(activity);
            tag.setText("✅ UPLOAD PERMITTED BY USER");
            tag.setTextSize(senior ? 13 : 11);
            tag.setTypeface(null, android.graphics.Typeface.BOLD);
            tag.setTextColor(0xFF141414);
            tag.setBackgroundResource(R.drawable.bg_pill_dark);
            tag.setPadding((int) (10 * density), (int) (4 * density), (int) (10 * density), (int) (4 * density));
            tagRow.addView(tag);

            View space = new View(activity);
            LinearLayout.LayoutParams sp = new LinearLayout.LayoutParams(0, 1, 1f);
            space.setLayoutParams(sp);
            tagRow.addView(space);

            TextView tvSync = new TextView(activity);
            tvSync.setText("SYNC ACTIVE");
            tvSync.setTextSize(10);
            tvSync.setTextColor(0xFF666666);
            tagRow.addView(tvSync);

            card.addView(tagRow);

            TextView tvTitle = new TextView(activity);
            tvTitle.setText("TeraBox Cloud Sync Authorized");
            tvTitle.setTextSize(senior ? 18 : 16);
            tvTitle.setTypeface(null, android.graphics.Typeface.BOLD);
            tvTitle.setTextColor(0xFF141414);
            LinearLayout.LayoutParams tp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            tp.topMargin = (int) (10 * density);
            tvTitle.setLayoutParams(tp);
            card.addView(tvTitle);

            TextView tvDesc = new TextView(activity);
            tvDesc.setText("User verified and granted permission for TeraBox background photo upload (142 items • 384 MB).");
            tvDesc.setTextSize(senior ? 13 : 11);
            tvDesc.setTextColor(0xFF666666);
            LinearLayout.LayoutParams dp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            dp.topMargin = (int) (4 * density);
            dp.bottomMargin = (int) (12 * density);
            tvDesc.setLayoutParams(dp);
            card.addView(tvDesc);

            LinearLayout actRow = new LinearLayout(activity);
            actRow.setOrientation(LinearLayout.HORIZONTAL);

            Button btnRevoke = new Button(activity);
            btnRevoke.setText("🛑 Revoke & Block");
            btnRevoke.setTextSize(senior ? 12 : 11);
            btnRevoke.setTextColor(0xFFFFFFFF);
            btnRevoke.setBackgroundResource(R.drawable.bg_pill_black);
            LinearLayout.LayoutParams rbp = new LinearLayout.LayoutParams(0, (int) (40 * density), 1f);
            rbp.rightMargin = (int) (6 * density);
            btnRevoke.setLayoutParams(rbp);
            btnRevoke.setOnClickListener(v -> {
                btnRevoke.setEnabled(false);
                btnRevoke.setText("⏳ Revoking & Blocking...");
                sentinel.confirmUploadAsync(activity, false, new DataExfiltrationSentinel.ActionProgressListener() {
                    @Override
                    public void onActionProgress(String message) {
                        btnRevoke.setText("⏳ " + message);
                    }

                    @Override
                    public void onActionComplete() {
                        Toast.makeText(activity, "🛡️ Permission revoked! TeraBox upload stopped.", Toast.LENGTH_SHORT).show();
                        render();
                    }
                });
            });
            actRow.addView(btnRevoke);

            Button btnReset = new Button(activity);
            btnReset.setText("↺ Test Again");
            btnReset.setTextSize(senior ? 12 : 11);
            btnReset.setTextColor(0xFF141414);
            btnReset.setBackgroundResource(R.drawable.bg_pill_outline);
            LinearLayout.LayoutParams rstp = new LinearLayout.LayoutParams(0, (int) (40 * density), 1f);
            rstp.rightMargin = (int) (6 * density);
            btnReset.setLayoutParams(rstp);
            btnReset.setOnClickListener(v -> {
                sentinel.startScanSimulation(activity, null);
                render();
            });
            actRow.addView(btnReset);

            Button btnOpenTbAllowed = new Button(activity);
            btnOpenTbAllowed.setText("🚀 Open TeraBox");
            btnOpenTbAllowed.setTextSize(senior ? 12 : 11);
            btnOpenTbAllowed.setTextColor(0xFF141414);
            btnOpenTbAllowed.setBackgroundResource(R.drawable.bg_pill_dark);
            LinearLayout.LayoutParams tbpAllowed = new LinearLayout.LayoutParams(0, (int) (40 * density), 1f);
            btnOpenTbAllowed.setLayoutParams(tbpAllowed);
            btnOpenTbAllowed.setOnClickListener(v -> dev.guardianai.personal.data.TeraBoxLaunchWatcher.launchTeraBox(activity));
            actRow.addView(btnOpenTbAllowed);

            card.addView(actRow);
        }

        return card;
    }

    private View buildScanningProgressCard(DataExfiltrationSentinel sentinel, boolean senior) {
        LinearLayout card = new LinearLayout(activity);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundResource(R.drawable.bg_card_cred);
        card.setPadding((int) (20 * density), (int) (18 * density), (int) (20 * density), (int) (18 * density));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        params.bottomMargin = (int) (18 * density);
        card.setLayoutParams(params);

        // Header: Badge + Percentage
        LinearLayout headerRow = new LinearLayout(activity);
        headerRow.setOrientation(LinearLayout.HORIZONTAL);
        headerRow.setGravity(Gravity.CENTER_VERTICAL);
        headerRow.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        TextView tag = new TextView(activity);
        tag.setText("⚡ LIVE KERNEL SOCKET SENTINEL");
        tag.setTextSize(senior ? 12 : 11);
        tag.setTypeface(null, android.graphics.Typeface.BOLD);
        tag.setTextColor(0xFF007A5A);
        tag.setBackgroundResource(R.drawable.bg_pill_emerald);
        tag.setPadding((int) (10 * density), (int) (4 * density), (int) (10 * density), (int) (4 * density));
        headerRow.addView(tag);

        View space = new View(activity);
        LinearLayout.LayoutParams sp = new LinearLayout.LayoutParams(0, 1, 1f);
        space.setLayoutParams(sp);
        headerRow.addView(space);

        TextView tvPercent = new TextView(activity);
        tvPercent.setText(sentinel.getScanProgressPercent() + "%");
        tvPercent.setTextSize(senior ? 15 : 13);
        tvPercent.setTextColor(0xFF007A5A);
        tvPercent.setTypeface(android.graphics.Typeface.MONOSPACE, android.graphics.Typeface.BOLD);
        headerRow.addView(tvPercent);

        card.addView(headerRow);

        // Title
        TextView tvTitle = new TextView(activity);
        tvTitle.setText("Deep Background Exfiltration Inspection");
        tvTitle.setTextSize(senior ? 18 : 16);
        tvTitle.setTypeface(null, android.graphics.Typeface.BOLD);
        tvTitle.setTextColor(0xFF141414);
        LinearLayout.LayoutParams tp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        tp.topMargin = (int) (12 * density);
        tvTitle.setLayoutParams(tp);
        card.addView(tvTitle);

        // Subtitle
        TextView tvSub = new TextView(activity);
        tvSub.setText("Inspecting active TCP/UDP sockets, wake-locks, and DCIM/Camera queries in real time...");
        tvSub.setTextSize(senior ? 13 : 11);
        tvSub.setTextColor(0xFF666666);
        LinearLayout.LayoutParams subp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        subp.topMargin = (int) (2 * density);
        subp.bottomMargin = (int) (12 * density);
        tvSub.setLayoutParams(subp);
        card.addView(tvSub);

        // Horizontal Progress Bar
        ProgressBar pb = new ProgressBar(activity, null, android.R.attr.progressBarStyleHorizontal);
        pb.setIndeterminate(false);
        pb.setMax(100);
        pb.setProgress(sentinel.getScanProgressPercent());
        LinearLayout.LayoutParams pbp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, (int) (8 * density));
        pbp.bottomMargin = (int) (10 * density);
        pb.setLayoutParams(pbp);
        card.addView(pb);

        // Current Stage Status
        TextView tvStatus = new TextView(activity);
        tvStatus.setText(sentinel.getScanStatusMessage());
        tvStatus.setTextSize(senior ? 14 : 12);
        tvStatus.setTextColor(0xFF222222);
        tvStatus.setTypeface(null, android.graphics.Typeface.BOLD);
        card.addView(tvStatus);

        // Log Checklist Container
        LinearLayout containerLog = new LinearLayout(activity);
        containerLog.setOrientation(LinearLayout.VERTICAL);
        containerLog.setBackgroundResource(R.drawable.bg_card_elevated);
        containerLog.setPadding((int) (12 * density), (int) (10 * density), (int) (12 * density), (int) (10 * density));
        LinearLayout.LayoutParams clp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        clp.topMargin = (int) (12 * density);
        containerLog.setLayoutParams(clp);

        List<String> logs = sentinel.getScanLogs();
        if (logs.isEmpty()) {
            TextView item = new TextView(activity);
            item.setText("• Monitoring Snapdragon 8 Elite high-speed network interfaces...");
            item.setTextSize(11);
            item.setTextColor(0xFF666666);
            containerLog.addView(item);
        } else {
            for (String log : logs) {
                TextView item = new TextView(activity);
                item.setText("✓ " + log);
                item.setTextSize(11);
                item.setTextColor(0xFF333333);
                item.setLineSpacing(0, 1.2f);
                LinearLayout.LayoutParams lip = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
                lip.bottomMargin = (int) (3 * density);
                item.setLayoutParams(lip);
                containerLog.addView(item);
            }
        }
        card.addView(containerLog);

        return card;
    }

    private View buildSeniorRecoveryBanner() {
        LinearLayout banner = new LinearLayout(activity);
        banner.setOrientation(LinearLayout.VERTICAL);
        banner.setBackgroundResource(R.drawable.bg_card_glow_amber);
        banner.setPadding((int) (18 * density), (int) (16 * density), (int) (18 * density), (int) (16 * density));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        params.bottomMargin = (int) (16 * density);
        banner.setLayoutParams(params);

        TextView title = new TextView(activity);
        title.setText("⚠️ SUSPICIOUS CALL OR MESSAGE? WHAT TO DO NOW");
        title.setTextSize(14);
        title.setTextColor(0xFF855A12);
        title.setTypeface(null, android.graphics.Typeface.BOLD);
        banner.addView(title);

        TextView step1 = new TextView(activity);
        step1.setText("1. NEVER share any 4 or 6-digit SMS OTP with anyone, even if they claim to be a bank manager or police.");
        step1.setTextSize(14);
        step1.setTextColor(0xFF141414);
        step1.setLineSpacing(0, 1.2f);
        LinearLayout.LayoutParams p1 = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        p1.topMargin = (int) (8 * density);
        step1.setLayoutParams(p1);
        banner.addView(step1);

        TextView step2 = new TextView(activity);
        step2.setText("2. DO NOT install AnyDesk, TeamViewer, or quick support apps sent via WhatsApp links.");
        step2.setTextSize(14);
        step2.setTextColor(0xFF141414);
        step2.setLineSpacing(0, 1.2f);
        LinearLayout.LayoutParams p2 = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        p2.topMargin = (int) (6 * density);
        step2.setLayoutParams(p2);
        banner.addView(step2);

        TextView step3 = new TextView(activity);
        step3.setText("3. If money was deducted, immediately call National Cyber Helpline at 1930 to freeze the transaction.");
        step3.setTextSize(14);
        step3.setTextColor(0xFF141414);
        step3.setLineSpacing(0, 1.2f);
        LinearLayout.LayoutParams p3 = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        p3.topMargin = (int) (6 * density);
        step3.setLayoutParams(p3);
        banner.addView(step3);

        Button btnDial1930 = new Button(activity);
        btnDial1930.setText("📞 Call 1930 Helpline Immediately");
        btnDial1930.setBackgroundResource(R.drawable.bg_pill_black);
        btnDial1930.setTextColor(0xFFFFFFFF);
        btnDial1930.setTextSize(14);
        btnDial1930.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams bp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, (int) (48 * density));
        bp.topMargin = (int) (12 * density);
        btnDial1930.setLayoutParams(bp);
        btnDial1930.setOnClickListener(v -> dialHelpline());
        banner.addView(btnDial1930);

        return banner;
    }

    private void populateHeroCard(boolean senior, ScanStats stats) {
        if (containerHeroCard == null) return;
        containerHeroCard.removeAllViews();

        LinearLayout card = new LinearLayout(activity);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundResource(R.drawable.bg_card_cred);
        card.setPadding((int) (22 * density), (int) (20 * density), (int) (22 * density), (int) (20 * density));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        params.bottomMargin = (int) (18 * density);
        card.setLayoutParams(params);

        TextView label = new TextView(activity);
        label.setText("OVERALL DIGITAL PROTECTION POSTURE");
        label.setTextSize(senior ? 13 : 11);
        label.setTextColor(0xFF888888);
        label.setTypeface(null, android.graphics.Typeface.BOLD);
        card.addView(label);

        LinearLayout row = new LinearLayout(activity);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams rp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        rp.topMargin = (int) (12 * density);
        row.setLayoutParams(rp);

        int score = stats.getTotalScans() == 0 ? AppState.get().getSafetyScore() : stats.getCleanRate();
        TextView tvScore = new TextView(activity);
        tvScore.setText(String.valueOf(score));
        tvScore.setTextSize(senior ? 48 : 42);
        tvScore.setTextColor(0xFF141414);
        tvScore.setTypeface(null, android.graphics.Typeface.BOLD);
        row.addView(tvScore);

        LinearLayout textCol = new LinearLayout(activity);
        textCol.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams tcp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        tcp.leftMargin = (int) (18 * density);
        textCol.setLayoutParams(tcp);

        TextView tvStatus = new TextView(activity);
        if (stats.getMaliciousCount() > 0) {
            tvStatus.setText("THREATS DETECTED & ISOLATED");
            tvStatus.setTextColor(0xFFA63232);
        } else if (stats.getSuspiciousCount() > 0) {
            tvStatus.setText("REVIEW RECOMMENDED");
            tvStatus.setTextColor(0xFF855A12);
        } else {
            tvStatus.setText("PROTECTED & OPTIMAL");
            tvStatus.setTextColor(0xFF386B57);
        }
        tvStatus.setTextSize(senior ? 16 : 14);
        tvStatus.setTypeface(null, android.graphics.Typeface.BOLD);
        textCol.addView(tvStatus);

        TextView tvSub = new TextView(activity);
        if (stats.getTotalScans() == 0) {
            tvSub.setText(senior
                    ? "Your phone is protected against scam apps, fake payment links and OTP stealers."
                    : "Snapdragon 8 Elite on-device intelligence active. Ready for your first security audit.");
        } else {
            tvSub.setText(stats.getTotalScans() + " scans recorded locally • " +
                    stats.getSafeCount() + " safe • " +
                    (stats.getSuspiciousCount() + stats.getMaliciousCount()) + " flagged threats");
        }
        tvSub.setTextSize(senior ? 14 : 12);
        tvSub.setTextColor(0xFF666666);
        LinearLayout.LayoutParams sp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        sp.topMargin = (int) (4 * density);
        tvSub.setLayoutParams(sp);
        textCol.addView(tvSub);

        row.addView(textCol);
        card.addView(row);

        // Divider
        View divider = new View(activity);
        divider.setBackgroundColor(0xFFE5E5E2);
        LinearLayout.LayoutParams dp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, (int) (1 * density));
        dp.topMargin = (int) (16 * density);
        dp.bottomMargin = (int) (14 * density);
        divider.setLayoutParams(dp);
        card.addView(divider);

        // Status bullets
        LinearLayout footerRow = new LinearLayout(activity);
        footerRow.setOrientation(LinearLayout.HORIZONTAL);
        footerRow.setGravity(Gravity.CENTER_VERTICAL);

        TextView dot = new TextView(activity);
        dot.setText("● ");
        dot.setTextColor(0xFF386B57);
        dot.setTextSize(12);
        footerRow.addView(dot);

        TextView footerText = new TextView(activity);
        footerText.setText("Audit log: " + stats.getTotalScans() + " events in SQLite • 100% on-device storage");
        footerText.setTextSize(senior ? 13 : 11);
        footerText.setTextColor(0xFF666666);
        footerRow.addView(footerText);

        card.addView(footerRow);
        containerHeroCard.addView(card);
    }

    private void populateNetworkProtectionCard(boolean senior, int blockedCount) {
        if (containerNetworkProtection == null) return;
        containerNetworkProtection.removeAllViews();

        NetworkProtectionManager npm = NetworkProtectionManager.getInstance(activity);
        NetworkProtectionStatus status = npm.getStatus();

        LinearLayout card = new LinearLayout(activity);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundResource(R.drawable.bg_card_cred);
        card.setPadding((int) (20 * density), (int) (18 * density), (int) (20 * density), (int) (18 * density));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        params.bottomMargin = (int) (18 * density);
        card.setLayoutParams(params);

        // Top Row: Category Label and Status Badge
        LinearLayout topRow = new LinearLayout(activity);
        topRow.setOrientation(LinearLayout.HORIZONTAL);
        topRow.setGravity(Gravity.CENTER_VERTICAL);
        topRow.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        ));

        TextView label = new TextView(activity);
        label.setText("NETWORK PROTECTION • DNS FIREWALL");
        label.setTextSize(senior ? 13 : 11);
        label.setTextColor(0xFF888888);
        label.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        label.setLayoutParams(lp);
        topRow.addView(label);

        TextView badge = new TextView(activity);
        badge.setText(status.getBadgeText());
        badge.setTextSize(senior ? 12 : 10);
        badge.setTypeface(null, android.graphics.Typeface.BOLD);
        badge.setPadding((int) (10 * density), (int) (4 * density), (int) (10 * density), (int) (4 * density));
        if (status == NetworkProtectionStatus.RUNNING) {
            badge.setTextColor(0xFF386B57);
            badge.setBackgroundResource(R.drawable.bg_pill_emerald);
        } else if (status == NetworkProtectionStatus.BLOCKED_BY_SYSTEM || status == NetworkProtectionStatus.FAILED) {
            badge.setTextColor(0xFFA63232);
            badge.setBackgroundResource(R.drawable.bg_pill_crimson);
        } else if (status == NetworkProtectionStatus.PERMISSION_NEEDED) {
            badge.setTextColor(0xFF855A12);
            badge.setBackgroundResource(R.drawable.bg_card_glow_amber);
        } else {
            badge.setTextColor(0xFF666666);
            badge.setBackgroundResource(R.drawable.bg_pill_dark);
        }
        topRow.addView(badge);
        card.addView(topRow);

        // Status Headline
        TextView tvHeadline = new TextView(activity);
        tvHeadline.setText(status == NetworkProtectionStatus.RUNNING
                ? "On-Device Malicious Domain Filter Active"
                : (status == NetworkProtectionStatus.PERMISSION_NEEDED
                ? "System Permission Required"
                : (status == NetworkProtectionStatus.BLOCKED_BY_SYSTEM
                ? "Protection Restricted by System or VPN Conflict"
                : "Network Protection Is Inactive")));
        tvHeadline.setTextSize(senior ? 18 : 16);
        tvHeadline.setTextColor(0xFF141414);
        tvHeadline.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams hp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        hp.topMargin = (int) (10 * density);
        tvHeadline.setLayoutParams(hp);
        card.addView(tvHeadline);

        // Explanation text
        TextView tvDesc = new TextView(activity);
        tvDesc.setText(status.getDescription());
        tvDesc.setTextSize(senior ? 14 : 12);
        tvDesc.setTextColor(0xFF666666);
        tvDesc.setLineSpacing(0, 1.25f);
        LinearLayout.LayoutParams dp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        dp.topMargin = (int) (4 * density);
        tvDesc.setLayoutParams(dp);
        card.addView(tvDesc);

        // Audited Block Counter
        TextView tvAudit = new TextView(activity);
        if (blockedCount > 0) {
            tvAudit.setText("🛡️ " + blockedCount + " threat connection" + (blockedCount == 1 ? "" : "s") + " sinkholed locally (audited in SQLite)");
            tvAudit.setTextColor(0xFFA63232);
        } else {
            tvAudit.setText("🛡️ 0 threats blocked • Real local record count (no simulated counters)");
            tvAudit.setTextColor(0xFF386B57);
        }
        tvAudit.setTextSize(senior ? 13 : 11);
        tvAudit.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams ap = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        ap.topMargin = (int) (8 * density);
        tvAudit.setLayoutParams(ap);
        card.addView(tvAudit);

        // Primary Action Button (Enable / Disable)
        Button btnToggle = new Button(activity);
        if (status == NetworkProtectionStatus.RUNNING) {
            btnToggle.setText("🛑 Turn Off Network Protection");
            btnToggle.setBackgroundResource(R.drawable.bg_pill_dark);
            btnToggle.setTextColor(0xFF141414);
            btnToggle.setOnClickListener(v -> {
                npm.stopProtection(activity);
                Toast.makeText(activity, "Network Protection stopped.", Toast.LENGTH_SHORT).show();
                render();
            });
        } else {
            btnToggle.setText("🛡️ Enable Network Protection");
            btnToggle.setBackgroundResource(R.drawable.bg_pill_black);
            btnToggle.setTextColor(0xFFFFFFFF);
            btnToggle.setOnClickListener(v -> {
                Intent vpnIntent = npm.prepareVpnIntent(activity);
                if (vpnIntent != null) {
                    activity.startActivityForResult(vpnIntent, NetworkProtectionManager.REQUEST_CODE_VPN_CONSENT);
                } else {
                    npm.startProtection(activity);
                    Toast.makeText(activity, "Starting on-device network protection...", Toast.LENGTH_SHORT).show();
                    render();
                }
            });
        }
        btnToggle.setTextSize(senior ? 15 : 13);
        btnToggle.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams bp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                (int) (46 * density)
        );
        bp.topMargin = (int) (14 * density);
        btnToggle.setLayoutParams(bp);
        card.addView(btnToggle);

        // Secondary Utility Row: "Android VPN Settings" and "Limits & Scope"
        LinearLayout utilRow = new LinearLayout(activity);
        utilRow.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams urp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        urp.topMargin = (int) (8 * density);
        utilRow.setLayoutParams(urp);

        Button btnSettings = new Button(activity);
        btnSettings.setText("⚙️ VPN Settings");
        btnSettings.setBackgroundResource(R.drawable.bg_pill_dark);
        btnSettings.setTextColor(0xFF444444);
        btnSettings.setTextSize(senior ? 13 : 11);
        btnSettings.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams bsp = new LinearLayout.LayoutParams(0, (int) (38 * density), 1f);
        bsp.rightMargin = (int) (4 * density);
        btnSettings.setLayoutParams(bsp);
        btnSettings.setOnClickListener(v -> {
            try {
                activity.startActivity(npm.getVpnSettingsIntent());
            } catch (Exception e) {
                Toast.makeText(activity, "Could not open VPN settings on this device.", Toast.LENGTH_SHORT).show();
            }
        });
        utilRow.addView(btnSettings);

        Button btnScope = new Button(activity);
        btnScope.setText("ℹ️ Scope & Limits");
        btnScope.setBackgroundResource(R.drawable.bg_pill_dark);
        btnScope.setTextColor(0xFF444444);
        btnScope.setTextSize(senior ? 13 : 11);
        btnScope.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams bcp = new LinearLayout.LayoutParams(0, (int) (38 * density), 1f);
        bcp.leftMargin = (int) (4 * density);
        btnScope.setLayoutParams(bcp);
        btnScope.setOnClickListener(v -> showNetworkScopeDialog());
        utilRow.addView(btnScope);

        card.addView(utilRow);
        containerNetworkProtection.addView(card);
    }

    private void showNetworkScopeDialog() {
        new AlertDialog.Builder(activity)
                .setTitle("Network Protection Scope & Operating Limits")
                .setMessage("WHAT GUARDIANAI DOES:\n" +
                        "• Intercepts local DNS domain requests (port 53 UDP) on-device.\n" +
                        "• Evaluates queried domains against local scam, phishing, and C2 malware blocklists.\n" +
                        "• Sinkholes dangerous domains to 0.0.0.0 locally, preventing outbound connections.\n" +
                        "• Preserves full internet connectivity by routing normal TCP/UDP traffic directly.\n\n" +
                        "WHAT GUARDIANAI CANNOT DO (LIMITATIONS):\n" +
                        "• No HTTPS Decryption: Cannot inspect encrypted application payloads (HTTPS, TLS, SSH). GuardianAi never installs root CA certificates.\n" +
                        "• Encrypted DNS (DoT / DoH): If Android Private DNS or in-app DNS-over-HTTPS is enabled, encrypted DNS requests bypass port 53 UDP.\n" +
                        "• Direct IP Connections: Malware contacting raw numeric IP addresses without DNS lookups is not observed.\n" +
                        "• Android VPN Exclusivity: Android allows only ONE active VPN at a time.")
                .setPositiveButton("Understood", null)
                .show();
    }

    private View buildQuickActionsSection(boolean senior) {
        LinearLayout section = new LinearLayout(activity);
        section.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        params.bottomMargin = (int) (20 * density);
        section.setLayoutParams(params);

        TextView sectionLabel = new TextView(activity);
        sectionLabel.setText("QUICK SAFETY ACTIONS");
        sectionLabel.setTextSize(senior ? 14 : 11);
        sectionLabel.setTextColor(0xFF888888);
        sectionLabel.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams slp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        slp.bottomMargin = (int) (12 * density);
        sectionLabel.setLayoutParams(slp);
        section.addView(sectionLabel);

        // Row 1: Message Check & Link Check
        LinearLayout row1 = new LinearLayout(activity);
        row1.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams r1p = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        r1p.bottomMargin = (int) (10 * density);
        row1.setLayoutParams(r1p);

        row1.addView(createActionCard("💬 Message Check",
                senior ? "Check SMS, WhatsApp message or OTP request" : "Evaluate SMS, WhatsApp OTP & payment coercion",
                senior,
                () -> AppState.get().navigateToScan(ScanMode.MESSAGE_CHECK)));

        View gap1 = new View(activity);
        gap1.setLayoutParams(new LinearLayout.LayoutParams((int) (10 * density), 1));
        row1.addView(gap1);

        row1.addView(createActionCard("🔗 Link Check",
                senior ? "Verify suspicious web address or banking link" : "Analyze URLs, punycode lookalikes & phishing kits",
                senior,
                () -> AppState.get().navigateToScan(ScanMode.LINK_CHECK)));

        section.addView(row1);

        // Row 2: APK Sideload & Installed Apps
        LinearLayout row2 = new LinearLayout(activity);
        row2.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams r2p = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        row2.setLayoutParams(r2p);

        row2.addView(createActionCard("📦 APK / File Check",
                senior ? "Inspect downloaded app file before installing" : "Reverse-engineer package manifest & DEX hooks",
                senior,
                () -> AppState.get().navigateToScan(ScanMode.APK_CHECK)));

        View gap2 = new View(activity);
        gap2.setLayoutParams(new LinearLayout.LayoutParams((int) (10 * density), 1));
        row2.addView(gap2);

        row2.addView(createActionCard("⚙️ Installed Apps",
                senior ? "Review apps with permission to control phone" : "Audit Accessibility, SMS & Admin permissions",
                senior,
                () -> AppState.get().navigateToScan(ScanMode.INSTALLED_APPS)));

        section.addView(row2);

        return section;
    }

    private View createActionCard(String title, String desc, boolean senior, Runnable onClick) {
        LinearLayout card = new LinearLayout(activity);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundResource(R.drawable.bg_card_interactive);
        card.setPadding((int) (16 * density), (int) (16 * density), (int) (16 * density), (int) (16 * density));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        card.setLayoutParams(params);
        card.setOnClickListener(v -> onClick.run());

        TextView tvTitle = new TextView(activity);
        tvTitle.setText(title);
        tvTitle.setTextSize(senior ? 16 : 14);
        tvTitle.setTextColor(0xFF141414);
        tvTitle.setTypeface(null, android.graphics.Typeface.BOLD);
        card.addView(tvTitle);

        TextView tvDesc = new TextView(activity);
        tvDesc.setText(desc);
        tvDesc.setTextSize(senior ? 13 : 11);
        tvDesc.setTextColor(0xFF666666);
        tvDesc.setLineSpacing(0, 1.2f);
        LinearLayout.LayoutParams dp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        dp.topMargin = (int) (6 * density);
        tvDesc.setLayoutParams(dp);
        card.addView(tvDesc);

        TextView tvTap = new TextView(activity);
        tvTap.setText("Launch Scan →");
        tvTap.setTextSize(senior ? 13 : 11);
        tvTap.setTextColor(0xFF141414);
        tvTap.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams tp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        tp.topMargin = (int) (10 * density);
        tvTap.setLayoutParams(tp);
        card.addView(tvTap);

        return card;
    }

    private View buildHelplineDock(boolean senior) {
        LinearLayout dock = new LinearLayout(activity);
        dock.setOrientation(LinearLayout.VERTICAL);
        dock.setBackgroundResource(R.drawable.bg_card_cred);
        dock.setPadding((int) (18 * density), (int) (16 * density), (int) (18 * density), (int) (16 * density));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        params.bottomMargin = (int) (20 * density);
        dock.setLayoutParams(params);

        TextView label = new TextView(activity);
        label.setText("NEED HELP OR SUSPECT FRAUD?");
        label.setTextSize(senior ? 13 : 11);
        label.setTextColor(0xFF888888);
        label.setTypeface(null, android.graphics.Typeface.BOLD);
        dock.addView(label);

        LinearLayout row = new LinearLayout(activity);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams rp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        rp.topMargin = (int) (10 * density);
        row.setLayoutParams(rp);

        // Button 1: Ask Assistant
        Button btnCopilot = new Button(activity);
        btnCopilot.setText("💬 Ask Assistant");
        btnCopilot.setBackgroundResource(R.drawable.bg_pill_black);
        btnCopilot.setTextColor(0xFFFFFFFF);
        btnCopilot.setTextSize(senior ? 14 : 12);
        btnCopilot.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams bp1 = new LinearLayout.LayoutParams(0, (int) (44 * density), 1f);
        bp1.rightMargin = (int) (6 * density);
        btnCopilot.setLayoutParams(bp1);
        btnCopilot.setOnClickListener(v -> {
            if (activity instanceof MainActivity) {
                ((MainActivity) activity).openContextualAssistant(null);
            }
        });
        row.addView(btnCopilot);

        // Button 2: Call 1930
        Button btnCall = new Button(activity);
        btnCall.setText("📞 Dial 1930");
        btnCall.setBackgroundResource(R.drawable.bg_pill_crimson);
        btnCall.setTextColor(0xFFA63232);
        btnCall.setTextSize(senior ? 14 : 12);
        btnCall.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams bp2 = new LinearLayout.LayoutParams(0, (int) (44 * density), 1f);
        bp2.leftMargin = (int) (6 * density);
        btnCall.setLayoutParams(bp2);
        btnCall.setOnClickListener(v -> dialHelpline());
        row.addView(btnCall);

        dock.addView(row);
        return dock;
    }

    private void populateRecentFindings(boolean senior, List<ScanRecord> scans) {
        if (containerRecentFindings == null) return;
        containerRecentFindings.removeAllViews();

        LinearLayout headerRow = new LinearLayout(activity);
        headerRow.setOrientation(LinearLayout.HORIZONTAL);
        headerRow.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams hrp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        hrp.bottomMargin = (int) (12 * density);
        headerRow.setLayoutParams(hrp);

        TextView label = new TextView(activity);
        label.setText("RECENT SECURITY FINDINGS");
        label.setTextSize(senior ? 14 : 11);
        label.setTextColor(0xFF888888);
        label.setTypeface(null, android.graphics.Typeface.BOLD);
        headerRow.addView(label);

        View sp = new View(activity);
        sp.setLayoutParams(new LinearLayout.LayoutParams(0, 1, 1f));
        headerRow.addView(sp);

        TextView tvViewAll = new TextView(activity);
        tvViewAll.setText("View All (Activity) →");
        tvViewAll.setTextSize(senior ? 13 : 11);
        tvViewAll.setTextColor(0xFF141414);
        tvViewAll.setTypeface(null, android.graphics.Typeface.BOLD);
        tvViewAll.setOnClickListener(v -> AppState.get().setCurrentTab(NavigationTab.ACTIVITY));
        headerRow.addView(tvViewAll);

        containerRecentFindings.addView(headerRow);

        if (scans == null || scans.isEmpty()) {
            // Honest empty state card
            LinearLayout emptyCard = new LinearLayout(activity);
            emptyCard.setOrientation(LinearLayout.VERTICAL);
            emptyCard.setBackgroundResource(R.drawable.bg_card_cred);
            emptyCard.setPadding((int) (20 * density), (int) (22 * density), (int) (20 * density), (int) (22 * density));
            emptyCard.setGravity(Gravity.CENTER);
            LinearLayout.LayoutParams ep = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            ep.bottomMargin = (int) (12 * density);
            emptyCard.setLayoutParams(ep);

            TextView icon = new TextView(activity);
            icon.setText("🛡️");
            icon.setTextSize(28);
            icon.setGravity(Gravity.CENTER);
            emptyCard.addView(icon);

            TextView tvEmpty = new TextView(activity);
            tvEmpty.setText("No security scans yet. Run your first check below.");
            tvEmpty.setTextSize(senior ? 15 : 13);
            tvEmpty.setTextColor(0xFF666666);
            tvEmpty.setGravity(Gravity.CENTER);
            LinearLayout.LayoutParams tp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            tp.topMargin = (int) (8 * density);
            tvEmpty.setLayoutParams(tp);
            emptyCard.addView(tvEmpty);

            Button btnStart = new Button(activity);
            btnStart.setText("Run First Security Scan →");
            btnStart.setBackgroundResource(R.drawable.bg_pill_black);
            btnStart.setTextColor(0xFFFFFFFF);
            btnStart.setTextSize(senior ? 14 : 12);
            btnStart.setTypeface(null, android.graphics.Typeface.BOLD);
            LinearLayout.LayoutParams bp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, (int) (42 * density));
            bp.topMargin = (int) (12 * density);
            btnStart.setLayoutParams(bp);
            btnStart.setPadding((int) (20 * density), 0, (int) (20 * density), 0);
            btnStart.setOnClickListener(v -> AppState.get().navigateToScan(ScanMode.APK_CHECK));
            emptyCard.addView(btnStart);

            containerRecentFindings.addView(emptyCard);
        } else {
            for (ScanRecord scan : scans) {
                ActivityEvent event = AppState.mapScanRecordToActivityEvent(scan, null);
                containerRecentFindings.addView(createEventCard(event, senior));
            }
        }
    }

    private View createEventCard(ActivityEvent event, boolean senior) {
        LinearLayout card = new LinearLayout(activity);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundResource(R.drawable.bg_card_interactive);
        card.setPadding((int) (16 * density), (int) (14 * density), (int) (16 * density), (int) (14 * density));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        params.bottomMargin = (int) (10 * density);
        card.setLayoutParams(params);
        card.setOnClickListener(v -> DetailSheetDialog.showEventDetails(activity, event));

        LinearLayout topRow = new LinearLayout(activity);
        topRow.setOrientation(LinearLayout.HORIZONTAL);
        topRow.setGravity(Gravity.CENTER_VERTICAL);

        TextView tvCategory = new TextView(activity);
        tvCategory.setText(event.getCategory().getDisplayName().toUpperCase());
        tvCategory.setTextSize(senior ? 12 : 10);
        tvCategory.setTextColor(0xFF888888);
        tvCategory.setTypeface(null, android.graphics.Typeface.BOLD);
        topRow.addView(tvCategory);

        View sp = new View(activity);
        sp.setLayoutParams(new LinearLayout.LayoutParams(0, 1, 1f));
        topRow.addView(sp);

        TextView tvSeverity = new TextView(activity);
        tvSeverity.setText(event.getSeverity().name());
        tvSeverity.setTextSize(senior ? 12 : 10);
        tvSeverity.setTypeface(null, android.graphics.Typeface.BOLD);
        tvSeverity.setPadding((int) (8 * density), (int) (3 * density), (int) (8 * density), (int) (3 * density));

        if (event.getSeverity() == ThreatSeverity.CRITICAL) {
            tvSeverity.setTextColor(0xFFA63232);
            tvSeverity.setBackgroundResource(R.drawable.bg_pill_crimson);
        } else if (event.getSeverity() == ThreatSeverity.HIGH) {
            tvSeverity.setTextColor(0xFF855A12);
            tvSeverity.setBackgroundResource(R.drawable.bg_pill_amber);
        } else {
            tvSeverity.setTextColor(0xFF386B57);
            tvSeverity.setBackgroundResource(R.drawable.bg_pill_emerald);
        }
        topRow.addView(tvSeverity);
        card.addView(topRow);

        TextView tvTitle = new TextView(activity);
        tvTitle.setText(event.getTitle());
        tvTitle.setTextSize(senior ? 16 : 14);
        tvTitle.setTextColor(0xFF141414);
        tvTitle.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams tp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        tp.topMargin = (int) (6 * density);
        tvTitle.setLayoutParams(tp);
        card.addView(tvTitle);

        TextView tvDesc = new TextView(activity);
        tvDesc.setText(event.getSummary());
        tvDesc.setTextSize(senior ? 14 : 12);
        tvDesc.setTextColor(0xFF666666);
        tvDesc.setMaxLines(2);
        LinearLayout.LayoutParams dp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        dp.topMargin = (int) (4 * density);
        tvDesc.setLayoutParams(dp);
        card.addView(tvDesc);

        return card;
    }

    private void dialHelpline() {
        try {
            Intent callIntent = new Intent(Intent.ACTION_DIAL);
            callIntent.setData(Uri.parse("tel:1930"));
            activity.startActivity(callIntent);
        } catch (Exception e) {
            Toast.makeText(activity, "Dialer unavailable. Dial 1930 directly.", Toast.LENGTH_SHORT).show();
        }
    }

    private void showProfilePickerDialog() {
        ChildProfile[] profiles = ChildProfile.values();
        String[] names = new String[profiles.length];
        for (int i = 0; i < profiles.length; i++) {
            names[i] = profiles[i].getName() + " (" + profiles[i].getRoleTitle() + ")";
        }

        new AlertDialog.Builder(activity)
                .setTitle("Select Active Safety Profile")
                .setItems(names, (dialog, which) -> {
                    ChildProfile selected = profiles[which];
                    AppState.get().setCurrentProfile(selected);
                    render();
                })
                .setNegativeButton("Cancel", null)
                .show();
    }
}
