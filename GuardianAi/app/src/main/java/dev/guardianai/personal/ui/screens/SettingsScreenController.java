package dev.guardianai.personal.ui.screens;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.net.Uri;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CompoundButton;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import dev.guardianai.personal.R;
import dev.guardianai.personal.network.NetworkProtectionManager;
import dev.guardianai.personal.network.NetworkProtectionStatus;
import dev.guardianai.personal.ui.model.NavigationTab;
import dev.guardianai.personal.ui.state.AppState;

public class SettingsScreenController {

    private final Activity activity;
    private final float density;
    private ScrollView rootView;
    private LinearLayout contentLayout;

    public SettingsScreenController(Activity activity) {
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

        // 1. Header
        contentLayout.addView(buildHeader(senior));

        // 2. Appearance & Accessibility (Senior Mode, Large Text, Contrast)
        contentLayout.addView(buildAccessibilitySection(senior));

        // 2b. Real Network Protection & Local Firewall
        contentLayout.addView(buildNetworkProtectionSection(senior));

        // 3. Privacy & On-Device Storage
        contentLayout.addView(buildPrivacySection(senior));

        // 4. Family Circle Shortcut
        contentLayout.addView(buildFamilyShortcutCard(senior));

        // 5. National Cybercrime & Help Resources
        contentLayout.addView(buildHelpSection(senior));

        // 6. Device & Application Metadata
        contentLayout.addView(buildMetadataSection(senior));
    }

    private View buildHeader(boolean senior) {
        LinearLayout header = new LinearLayout(activity);
        header.setOrientation(LinearLayout.VERTICAL);
        header.setPadding(0, 0, 0, (int) (16 * density));

        TextView tvTitle = new TextView(activity);
        tvTitle.setText(senior ? "PREFERENCES & ACCESSIBILITY" : "SETTINGS & SYSTEM ARCHITECTURE");
        tvTitle.setTextSize(senior ? 24 : 22);
        tvTitle.setTextColor(0xFF141414);
        tvTitle.setTypeface(null, android.graphics.Typeface.BOLD);
        header.addView(tvTitle);

        TextView tvSub = new TextView(activity);
        tvSub.setText(senior
                ? "Customise readability, privacy preferences, and elder protection assistance."
                : "Accessibility scaling, Senior Mode, local storage hygiene & hardware diagnostics");
        tvSub.setTextSize(senior ? 15 : 13);
        tvSub.setTextColor(0xFF666666);
        LinearLayout.LayoutParams sp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        sp.topMargin = (int) (4 * density);
        tvSub.setLayoutParams(sp);
        header.addView(tvSub);

        return header;
    }

    private View buildAccessibilitySection(boolean senior) {
        LinearLayout card = new LinearLayout(activity);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundResource(R.drawable.bg_card_cred);
        card.setPadding((int) (18 * density), (int) (16 * density), (int) (18 * density), (int) (16 * density));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        params.bottomMargin = (int) (16 * density);
        card.setLayoutParams(params);

        TextView label = new TextView(activity);
        label.setText("APPEARANCE & ACCESSIBILITY");
        label.setTextSize(senior ? 14 : 11);
        label.setTextColor(0xFF888888);
        label.setTypeface(null, android.graphics.Typeface.BOLD);
        card.addView(label);

        // Senior Mode Switch Row
        card.addView(createToggleRow(
                "👴 Senior Protection Mode",
                "Larger text, high-contrast buttons, simplified terms & scam recovery guide",
                AppState.get().isSeniorMode(),
                (v, isChecked) -> {
                    AppState.get().setSeniorMode(isChecked);
                    render();
                },
                senior
        ));

        // Large Text Switch Row
        card.addView(createToggleRow(
                "🔤 Large Typography Scale",
                "Scales headings and body text for easier reading across all screens",
                AppState.get().isLargeText(),
                (v, isChecked) -> {
                    AppState.get().setLargeText(isChecked);
                    render();
                },
                senior
        ));

        // High Contrast Switch Row
        card.addView(createToggleRow(
                "👁️ High Contrast Mode",
                "Deep monochrome black borders and enhanced button definition",
                AppState.get().isHighContrast(),
                (v, isChecked) -> {
                    AppState.get().setHighContrast(isChecked);
                    render();
                },
                senior
        ));

        // Hindi Vernacular Switch Row
        card.addView(createToggleRow(
                "🇮🇳 Hindi Vernacular Explanations",
                "Provide Hindi voice and plain-language summaries for threats",
                AppState.get().isHindi(),
                (v, isChecked) -> {
                    AppState.get().setHindi(isChecked);
                    render();
                },
                senior
        ));

        return card;
    }

    private View createToggleRow(String title, String subtitle, boolean isChecked, CompoundButton.OnCheckedChangeListener listener, boolean senior) {
        LinearLayout row = new LinearLayout(activity);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams rp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        rp.topMargin = (int) (14 * density);
        row.setLayoutParams(rp);

        LinearLayout textCol = new LinearLayout(activity);
        textCol.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams tcp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        textCol.setLayoutParams(tcp);

        TextView tvTitle = new TextView(activity);
        tvTitle.setText(title);
        tvTitle.setTextSize(senior ? 16 : 14);
        tvTitle.setTextColor(0xFF141414);
        tvTitle.setTypeface(null, android.graphics.Typeface.BOLD);
        textCol.addView(tvTitle);

        TextView tvSub = new TextView(activity);
        tvSub.setText(subtitle);
        tvSub.setTextSize(senior ? 13 : 11);
        tvSub.setTextColor(0xFF666666);
        tvSub.setLineSpacing(0, 1.2f);
        LinearLayout.LayoutParams sp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        sp.topMargin = (int) (2 * density);
        tvSub.setLayoutParams(sp);
        textCol.addView(tvSub);

        row.addView(textCol);

        Switch sw = new Switch(activity);
        sw.setChecked(isChecked);
        sw.setOnCheckedChangeListener(listener);
        row.addView(sw);

        return row;
    }

    private View buildNetworkProtectionSection(boolean senior) {
        NetworkProtectionManager npm = NetworkProtectionManager.getInstance(activity);
        NetworkProtectionStatus status = npm.getStatus();

        LinearLayout card = new LinearLayout(activity);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundResource(R.drawable.bg_card_cred);
        card.setPadding((int) (18 * density), (int) (16 * density), (int) (18 * density), (int) (16 * density));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        params.bottomMargin = (int) (16 * density);
        card.setLayoutParams(params);

        // Header Row: Category and Badge
        LinearLayout rowHeader = new LinearLayout(activity);
        rowHeader.setOrientation(LinearLayout.HORIZONTAL);
        rowHeader.setGravity(Gravity.CENTER_VERTICAL);
        rowHeader.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        ));

        TextView label = new TextView(activity);
        label.setText("NETWORK PROTECTION & DNS FIREWALL");
        label.setTextSize(senior ? 14 : 11);
        label.setTextColor(0xFF888888);
        label.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        label.setLayoutParams(lp);
        rowHeader.addView(label);

        TextView badge = new TextView(activity);
        badge.setText(status.getBadgeText());
        badge.setTextSize(senior ? 12 : 10);
        badge.setTypeface(null, android.graphics.Typeface.BOLD);
        badge.setPadding((int) (8 * density), (int) (3 * density), (int) (8 * density), (int) (3 * density));
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
        rowHeader.addView(badge);
        card.addView(rowHeader);

        // Subtitle / Status description
        TextView tvDesc = new TextView(activity);
        tvDesc.setText(status.getDescription());
        tvDesc.setTextSize(senior ? 14 : 12);
        tvDesc.setTextColor(0xFF444444);
        tvDesc.setLineSpacing(0, 1.25f);
        LinearLayout.LayoutParams dp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        dp.topMargin = (int) (8 * density);
        tvDesc.setLayoutParams(dp);
        card.addView(tvDesc);

        // Action Buttons Row: Enable/Disable and System Settings
        LinearLayout btnRow = new LinearLayout(activity);
        btnRow.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams brp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        brp.topMargin = (int) (12 * density);
        btnRow.setLayoutParams(brp);

        Button btnToggle = new Button(activity);
        if (status == NetworkProtectionStatus.RUNNING) {
            btnToggle.setText("🛑 Stop Protection");
            btnToggle.setBackgroundResource(R.drawable.bg_pill_dark);
            btnToggle.setTextColor(0xFF141414);
            btnToggle.setOnClickListener(v -> {
                npm.stopProtection(activity);
                Toast.makeText(activity, "Network protection disabled.", Toast.LENGTH_SHORT).show();
                render();
            });
        } else {
            btnToggle.setText("🛡️ Enable Protection");
            btnToggle.setBackgroundResource(R.drawable.bg_pill_black);
            btnToggle.setTextColor(0xFFFFFFFF);
            btnToggle.setOnClickListener(v -> {
                Intent vpnIntent = npm.prepareVpnIntent(activity);
                if (vpnIntent != null) {
                    activity.startActivityForResult(vpnIntent, NetworkProtectionManager.REQUEST_CODE_VPN_CONSENT);
                } else {
                    npm.startProtection(activity);
                    Toast.makeText(activity, "Network protection started.", Toast.LENGTH_SHORT).show();
                    render();
                }
            });
        }
        btnToggle.setTextSize(senior ? 13 : 11);
        btnToggle.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams btp = new LinearLayout.LayoutParams(0, (int) (42 * density), 1.2f);
        btp.rightMargin = (int) (6 * density);
        btnToggle.setLayoutParams(btp);
        btnRow.addView(btnToggle);

        Button btnVpnSettings = new Button(activity);
        btnVpnSettings.setText("⚙️ Android VPN");
        btnVpnSettings.setBackgroundResource(R.drawable.bg_pill_dark);
        btnVpnSettings.setTextColor(0xFF333333);
        btnVpnSettings.setTextSize(senior ? 13 : 11);
        btnVpnSettings.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams bvp = new LinearLayout.LayoutParams(0, (int) (42 * density), 1f);
        btnVpnSettings.setLayoutParams(bvp);
        btnVpnSettings.setOnClickListener(v -> {
            try {
                activity.startActivity(npm.getVpnSettingsIntent());
            } catch (Exception e) {
                Toast.makeText(activity, "Cannot open VPN settings on this device.", Toast.LENGTH_SHORT).show();
            }
        });
        btnRow.addView(btnVpnSettings);

        card.addView(btnRow);
        return card;
    }

    private View buildPrivacySection(boolean senior) {
        LinearLayout card = new LinearLayout(activity);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundResource(R.drawable.bg_card_cred);
        card.setPadding((int) (18 * density), (int) (16 * density), (int) (18 * density), (int) (16 * density));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        params.bottomMargin = (int) (16 * density);
        card.setLayoutParams(params);

        TextView label = new TextView(activity);
        label.setText("PRIVACY & DATA RESIDENCY");
        label.setTextSize(senior ? 14 : 11);
        label.setTextColor(0xFF888888);
        label.setTypeface(null, android.graphics.Typeface.BOLD);
        card.addView(label);

        TextView desc = new TextView(activity);
        desc.setText("• 100% On-Device Processing: APK DEX reverse-engineering and message analysis run entirely inside this phone's memory. No data is sent to external servers.\n" +
                "• Zero Tracking: No analytics beacons, no advertising IDs, no personal contact exfiltration.\n" +
                "• Encrypted Storage: All audit logs are encrypted locally with Android Keystore AES-256.");
        desc.setTextSize(senior ? 14 : 12);
        desc.setTextColor(0xFF444444);
        desc.setLineSpacing(0, 1.25f);
        LinearLayout.LayoutParams dp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        dp.topMargin = (int) (8 * density);
        desc.setLayoutParams(dp);
        card.addView(desc);

        Button btnClear = new Button(activity);
        btnClear.setText("🧹 Prune & Clear Local Audit Cache");
        btnClear.setBackgroundResource(R.drawable.bg_pill_dark);
        btnClear.setTextColor(0xFF141414);
        btnClear.setTextSize(senior ? 14 : 12);
        btnClear.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams bp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, (int) (44 * density));
        bp.topMargin = (int) (12 * density);
        btnClear.setLayoutParams(bp);
        btnClear.setOnClickListener(v -> {
            new AlertDialog.Builder(activity)
                    .setTitle("Prune & Clear Local Audit Cache")
                    .setMessage("This will permanently remove all security scan records from the local SQLite database. Proceed?")
                    .setPositiveButton("Prune & Clear", (dialog, which) -> {
                        AppState.get().clearLocalAuditCache(() -> {
                            Toast.makeText(activity, "Local audit database cleared. 0 records retained.", Toast.LENGTH_SHORT).show();
                            render();
                        });
                    })
                    .setNegativeButton("Cancel", null)
                    .show();
        });
        card.addView(btnClear);

        return card;
    }

    private View buildFamilyShortcutCard(boolean senior) {
        LinearLayout card = new LinearLayout(activity);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundResource(R.drawable.bg_card_interactive);
        card.setPadding((int) (18 * density), (int) (16 * density), (int) (18 * density), (int) (16 * density));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        params.bottomMargin = (int) (16 * density);
        card.setLayoutParams(params);
        card.setOnClickListener(v -> AppState.get().setCurrentTab(NavigationTab.FAMILY));

        TextView label = new TextView(activity);
        label.setText("FAMILY CIRCLE & CONSENT");
        label.setTextSize(senior ? 14 : 11);
        label.setTextColor(0xFF888888);
        label.setTypeface(null, android.graphics.Typeface.BOLD);
        card.addView(label);

        TextView title = new TextView(activity);
        title.setText("Manage Paired Devices & Safety Agreement →");
        title.setTextSize(senior ? 16 : 14);
        title.setTextColor(0xFF141414);
        title.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams tp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        tp.topMargin = (int) (4 * density);
        title.setLayoutParams(tp);
        card.addView(title);

        TextView desc = new TextView(activity);
        desc.setText("Pair child devices, manage trusted emergency contacts, and review volunteer safety reports.");
        desc.setTextSize(senior ? 13 : 11);
        desc.setTextColor(0xFF666666);
        LinearLayout.LayoutParams dp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        dp.topMargin = (int) (2 * density);
        desc.setLayoutParams(dp);
        card.addView(desc);

        return card;
    }

    private View buildHelpSection(boolean senior) {
        LinearLayout card = new LinearLayout(activity);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundResource(R.drawable.bg_card_cred);
        card.setPadding((int) (18 * density), (int) (16 * density), (int) (18 * density), (int) (16 * density));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        params.bottomMargin = (int) (16 * density);
        card.setLayoutParams(params);

        TextView label = new TextView(activity);
        label.setText("OFFICIAL CYBER FRAUD ASSISTANCE (INDIA)");
        label.setTextSize(senior ? 14 : 11);
        label.setTextColor(0xFF888888);
        label.setTypeface(null, android.graphics.Typeface.BOLD);
        card.addView(label);

        TextView info = new TextView(activity);
        info.setText("National Cyber Crime Reporting Portal:\n" +
                "• Helpline Number: 1930 (Immediate Financial Fraud Freeze)\n" +
                "• Official Portal: cybercrime.gov.in (Ministry of Home Affairs)\n" +
                "• Always report fraud within the 'Golden Hour' (first 2 hours) to maximize stolen funds recovery.");
        info.setTextSize(senior ? 14 : 12);
        info.setTextColor(0xFF333333);
        info.setLineSpacing(0, 1.25f);
        LinearLayout.LayoutParams ip = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        ip.topMargin = (int) (8 * density);
        info.setLayoutParams(ip);
        card.addView(info);

        LinearLayout row = new LinearLayout(activity);
        row.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams rp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        rp.topMargin = (int) (12 * density);
        row.setLayoutParams(rp);

        Button btnCall = new Button(activity);
        btnCall.setText("📞 Call 1930");
        btnCall.setBackgroundResource(R.drawable.bg_pill_crimson);
        btnCall.setTextColor(0xFFA63232);
        btnCall.setTextSize(senior ? 14 : 12);
        btnCall.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams b1p = new LinearLayout.LayoutParams(0, (int) (44 * density), 1f);
        b1p.rightMargin = (int) (6 * density);
        btnCall.setLayoutParams(b1p);
        btnCall.setOnClickListener(v -> {
            try {
                Intent call = new Intent(Intent.ACTION_DIAL, Uri.parse("tel:1930"));
                activity.startActivity(call);
            } catch (Exception ignored) {}
        });
        row.addView(btnCall);

        Button btnWeb = new Button(activity);
        btnWeb.setText("🌐 cybercrime.gov.in");
        btnWeb.setBackgroundResource(R.drawable.bg_pill_black);
        btnWeb.setTextColor(0xFFFFFFFF);
        btnWeb.setTextSize(senior ? 14 : 12);
        btnWeb.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams b2p = new LinearLayout.LayoutParams(0, (int) (44 * density), 1f);
        b2p.leftMargin = (int) (6 * density);
        btnWeb.setLayoutParams(b2p);
        btnWeb.setOnClickListener(v -> {
            try {
                Intent browser = new Intent(Intent.ACTION_VIEW, Uri.parse("https://cybercrime.gov.in"));
                activity.startActivity(browser);
            } catch (Exception ignored) {}
        });
        row.addView(btnWeb);

        card.addView(row);
        return card;
    }

    private View buildMetadataSection(boolean senior) {
        LinearLayout card = new LinearLayout(activity);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundResource(R.drawable.bg_pill_dark);
        card.setPadding((int) (18 * density), (int) (16 * density), (int) (18 * density), (int) (16 * density));
        card.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        ));

        TextView appTitle = new TextView(activity);
        appTitle.setText("GUARDIANAI PERSONAL • DIGITAL SAFETY COMPANION");
        appTitle.setTextSize(13);
        appTitle.setTextColor(0xFF141414);
        appTitle.setTypeface(null, android.graphics.Typeface.BOLD);
        card.addView(appTitle);

        TextView meta = new TextView(activity);
        meta.setText("Version: 1.0.0-personal (Build 2026.10)\n" +
                "Hardware: iQOO 15 (I2501i)\n" +
                "SoC: Qualcomm Snapdragon 8 Elite (SM8750)\n" +
                "Display: 144Hz LTPO AMOLED • 1440 × 3168\n" +
                "OS: Android 16 (API 36 • Baklava)\n" +
                "Architecture: Native Java/XML • Local Static Engine");
        meta.setTextSize(11);
        meta.setTextColor(0xFF666666);
        meta.setLineSpacing(0, 1.25f);
        LinearLayout.LayoutParams mp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        mp.topMargin = (int) (6 * density);
        Button btnDiag = new Button(activity);
        btnDiag.setText("🛠️ Open AI Diagnostics (LiteRT-LM Gemma)");
        btnDiag.setBackgroundResource(R.drawable.bg_pill_black);
        btnDiag.setTextColor(0xFFFFFFFF);
        btnDiag.setTextSize(12);
        btnDiag.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams dp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, (int) (40 * density));
        dp.topMargin = (int) (12 * density);
        btnDiag.setLayoutParams(dp);
        btnDiag.setOnClickListener(v -> dev.guardianai.personal.ui.components.AiDiagnosticsDialog.show(activity));
        card.addView(btnDiag);

        return card;
    }
}
