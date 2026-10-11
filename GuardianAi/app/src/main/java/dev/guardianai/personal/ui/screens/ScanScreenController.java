package dev.guardianai.personal.ui.screens;

import android.app.Activity;
import android.app.Dialog;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.net.Uri;
import android.provider.Settings;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.HorizontalScrollView;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import dev.guardianai.ai.HindiExplanationSynthesizer;
import dev.guardianai.ai.SecurityFindingContext;
import java.io.File;
import dev.guardianai.engine.ApkInstallHandoffHelper;
import dev.guardianai.model.ApkAnalysisReport;
import dev.guardianai.model.ScanVerdict;
import dev.guardianai.model.ThreatIndicator;
import dev.guardianai.model.ThreatSeverity;
import dev.guardianai.personal.R;
import dev.guardianai.personal.data.apk.ApkStaticAnalyzer;
import dev.guardianai.personal.data.apps.InstalledAppInfo;
import dev.guardianai.personal.data.apps.InstalledAppsRepository;
import dev.guardianai.personal.data.db.FindingRecord;
import dev.guardianai.personal.data.db.ScanRecord;
import dev.guardianai.personal.ui.MainActivity;
import dev.guardianai.personal.ui.components.DetailSheetDialog;
import dev.guardianai.personal.ui.model.ActivityEvent;
import dev.guardianai.personal.ui.model.ScanMode;
import dev.guardianai.personal.ui.state.AppState;
import dev.guardianai.sense.ConversationRiskReport;
import dev.guardianai.sense.SafetyCategory;
import dev.guardianai.shield.network.PhishingUrlScanner;
import dev.guardianai.shield.network.hash.HashReputationResult;
import dev.guardianai.shield.network.url.ParsedUrl;
import dev.guardianai.shield.network.url.ReputationResult;
import dev.guardianai.shield.network.url.ReputationState;
import dev.guardianai.shield.network.url.UrlAnalysisResult;
import dev.guardianai.shield.network.url.UrlIndicator;
import dev.guardianai.shield.network.url.UrlParseException;
import dev.guardianai.shield.message.MessageIndicator;
import dev.guardianai.shield.message.MessageIndicatorType;
import dev.guardianai.shield.message.MessageRiskAssessment;
import dev.guardianai.shield.message.MessageRiskCategory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class ScanScreenController {

    private final Activity activity;
    private final float density;
    private ScrollView rootView;
    private LinearLayout contentLayout;
    private LinearLayout containerFlow;

    // Controllers state
    private ScanMode activeMode = ScanMode.APK_CHECK;

    // APK sub-flow views & last result state
    private LinearLayout containerApkResult;
    private ApkAnalysisReport lastApkReport = null;
    private ActivityEvent lastApkEvent = null;

    // Link sub-flow views
    private EditText etLinkInput;
    private LinearLayout containerLinkResult;

    // Message sub-flow views
    private EditText etMessageInput;
    private LinearLayout containerMessageResult;

    // Installed apps sub-flow views & state
    private LinearLayout containerAppsList;
    private TextView tvAppsStats;
    private LinearLayout filterChipsRow;
    private List<InstalledAppInfo> cachedInstalledApps = null;
    private boolean isLoadingInstalledApps = false;
    private String appSearchQuery = "";
    private enum AppFilter { ALL, HIGH_PRIVILEGE, USER_ONLY }
    private AppFilter currentAppFilter = AppFilter.ALL;

    public ScanScreenController(Activity activity) {
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
        this.activeMode = AppState.get().getCurrentScanMode();
        boolean senior = AppState.get().isSeniorMode();

        // 1. Header
        contentLayout.addView(buildHeader(senior));

        // 2. Segmented Mode Switcher (4 entry points)
        contentLayout.addView(buildModeSwitcher(senior));

        // 3. Dynamic Sub-flow container
        containerFlow = new LinearLayout(activity);
        containerFlow.setOrientation(LinearLayout.VERTICAL);
        containerFlow.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        ));
        contentLayout.addView(containerFlow);

        // Render selected sub-flow
        renderSubFlow(activeMode, senior);
    }

    private View buildHeader(boolean senior) {
        LinearLayout header = new LinearLayout(activity);
        header.setOrientation(LinearLayout.VERTICAL);
        header.setPadding(0, 0, 0, (int) (16 * density));

        TextView tvTitle = new TextView(activity);
        tvTitle.setText(senior ? "SAFETY SCAN HUB" : "GUARDIANAI SHIELD • SCAN HUB");
        tvTitle.setTextSize(senior ? 24 : 22);
        tvTitle.setTextColor(0xFF141414);
        tvTitle.setTypeface(null, android.graphics.Typeface.BOLD);
        header.addView(tvTitle);

        TextView tvSub = new TextView(activity);
        tvSub.setText(senior
                ? "Check suspicious apps, website links, or messages before opening them."
                : "Deterministic on-device static analysis, DEX reverse-engineering & scam heuristics");
        tvSub.setTextSize(senior ? 15 : 13);
        tvSub.setTextColor(0xFF666666);
        LinearLayout.LayoutParams sp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        sp.topMargin = (int) (4 * density);
        tvSub.setLayoutParams(sp);
        header.addView(tvSub);

        // Hardware NPU badge
        TextView tvEngineBadge = new TextView(activity);
        tvEngineBadge.setText("⚡ Snapdragon 8 Elite • Private On-Device Static Inference");
        tvEngineBadge.setTextSize(senior ? 12 : 11);
        tvEngineBadge.setTextColor(0xFF141414);
        tvEngineBadge.setBackgroundResource(R.drawable.bg_pill_dark);
        tvEngineBadge.setPadding((int) (12 * density), (int) (6 * density), (int) (12 * density), (int) (6 * density));
        LinearLayout.LayoutParams bp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        bp.topMargin = (int) (10 * density);
        tvEngineBadge.setLayoutParams(bp);
        header.addView(tvEngineBadge);

        return header;
    }

    private View buildModeSwitcher(boolean senior) {
        HorizontalScrollView hsv = new HorizontalScrollView(activity);
        hsv.setHorizontalScrollBarEnabled(false);
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        params.bottomMargin = (int) (18 * density);
        hsv.setLayoutParams(params);

        LinearLayout row = new LinearLayout(activity);
        row.setOrientation(LinearLayout.HORIZONTAL);
        hsv.addView(row);

        for (ScanMode mode : ScanMode.values()) {
            boolean isSelected = (mode == activeMode);
            Button btn = new Button(activity);
            btn.setText(mode.getTitle());
            btn.setTextSize(senior ? 14 : 12);
            btn.setTypeface(null, isSelected ? android.graphics.Typeface.BOLD : android.graphics.Typeface.NORMAL);
            btn.setBackgroundResource(isSelected ? R.drawable.bg_pill_black : R.drawable.bg_pill_dark);
            btn.setTextColor(isSelected ? 0xFFFFFFFF : 0xFF666666);
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    (int) (42 * density)
            );
            lp.rightMargin = (int) (8 * density);
            btn.setLayoutParams(lp);
            btn.setPadding((int) (16 * density), 0, (int) (16 * density), 0);
            btn.setOnClickListener(v -> {
                activeMode = mode;
                AppState.get().setCurrentScanMode(mode);
                render();
            });
            row.addView(btn);
        }

        return hsv;
    }

    private void renderSubFlow(ScanMode mode, boolean senior) {
        containerFlow.removeAllViews();
        switch (mode) {
            case APK_CHECK:
                renderApkSubFlow(senior);
                break;
            case LINK_CHECK:
                renderLinkSubFlow(senior);
                break;
            case MESSAGE_CHECK:
                renderMessageSubFlow(senior);
                break;
            case INSTALLED_APPS:
                renderInstalledAppsSubFlow(senior);
                break;
        }
    }

    // ==========================================
    // 1. APK / FILE CHECK SUB-FLOW
    // ==========================================
    private void renderApkSubFlow(boolean senior) {
        LinearLayout card = new LinearLayout(activity);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundResource(R.drawable.bg_card_cred);
        card.setPadding((int) (20 * density), (int) (18 * density), (int) (20 * density), (int) (18 * density));
        card.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        ));

        TextView title = new TextView(activity);
        title.setText("APK & SIDELOAD SAFETY INSPECTOR");
        title.setTextSize(senior ? 16 : 14);
        title.setTextColor(0xFF141414);
        title.setTypeface(null, android.graphics.Typeface.BOLD);
        card.addView(title);

        TextView desc = new TextView(activity);
        desc.setText(senior
                ? "Before installing an application downloaded from Chrome, WhatsApp, or Telegram, inspect its digital signature and screen permissions."
                : "Static reverse-engineering extracts AndroidManifest.xml, parses DEX bytecode for trojan hooks, and verifies X.509 signature certificates.");
        desc.setTextSize(senior ? 14 : 12);
        desc.setTextColor(0xFF666666);
        desc.setLineSpacing(0, 1.2f);
        LinearLayout.LayoutParams dp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        dp.topMargin = (int) (6 * density);
        dp.bottomMargin = (int) (14 * density);
        desc.setLayoutParams(dp);
        card.addView(desc);

        // Action 1: File Picker (SAF)
        Button btnPickFile = new Button(activity);
        btnPickFile.setText("📂 Select APK from Downloads");
        btnPickFile.setBackgroundResource(R.drawable.bg_pill_black);
        btnPickFile.setTextColor(0xFFFFFFFF);
        btnPickFile.setTextSize(senior ? 15 : 13);
        btnPickFile.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams bpp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, (int) (48 * density));
        btnPickFile.setLayoutParams(bpp);
        btnPickFile.setOnClickListener(v -> triggerSafPicker());
        card.addView(btnPickFile);

        // Result Container
        containerApkResult = new LinearLayout(activity);
        containerApkResult.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams rp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        rp.topMargin = (int) (16 * density);
        containerApkResult.setLayoutParams(rp);
        card.addView(containerApkResult);

        if (lastApkReport != null && lastApkEvent != null) {
            displayApkVerdictCard(lastApkReport, lastApkEvent, senior);
        }

        containerFlow.addView(card);
    }

    private void triggerSafPicker() {
        try {
            Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
            intent.setType("*/*");
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            String[] extraMimeTypes = {"application/vnd.android.package-archive", "application/zip", "application/octet-stream", "*/*"};
            intent.putExtra(Intent.EXTRA_MIME_TYPES, extraMimeTypes);
            activity.startActivityForResult(Intent.createChooser(intent, "Select APK to Inspect"), 2001);
        } catch (Exception e) {
            try {
                Intent fallback = new Intent(Intent.ACTION_OPEN_DOCUMENT);
                fallback.addCategory(Intent.CATEGORY_OPENABLE);
                fallback.setType("*/*");
                activity.startActivityForResult(fallback, 2001);
            } catch (Exception ex) {
                Toast.makeText(activity, "File picker could not be opened: " + ex.getMessage(), Toast.LENGTH_SHORT).show();
            }
        }
    }

    public void analyzeSelectedApkUri(Uri uri) {
        if (uri == null) return;
        AppState.get().setCurrentScanMode(ScanMode.APK_CHECK);
        if (containerApkResult == null) {
            render();
        }
        if (containerApkResult == null) return;
        boolean senior = AppState.get().isSeniorMode();

        containerApkResult.removeAllViews();

        LinearLayout progressCard = new LinearLayout(activity);
        progressCard.setOrientation(LinearLayout.VERTICAL);
        progressCard.setBackgroundResource(R.drawable.bg_card_cred);
        progressCard.setPadding((int) (20 * density), (int) (18 * density), (int) (20 * density), (int) (18 * density));
        progressCard.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        // Header row: Title + Percentage
        LinearLayout headerRow = new LinearLayout(activity);
        headerRow.setOrientation(LinearLayout.HORIZONTAL);
        headerRow.setGravity(Gravity.CENTER_VERTICAL);
        headerRow.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        TextView tvScanningTitle = new TextView(activity);
        tvScanningTitle.setText("DEEP STATIC APK INSPECTION");
        tvScanningTitle.setTextSize(senior ? 15 : 13);
        tvScanningTitle.setTextColor(0xFF141414);
        tvScanningTitle.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams tlp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.0f);
        tvScanningTitle.setLayoutParams(tlp);
        headerRow.addView(tvScanningTitle);

        TextView tvPercent = new TextView(activity);
        tvPercent.setText("0%");
        tvPercent.setTextSize(senior ? 15 : 13);
        tvPercent.setTextColor(0xFF007A5A);
        tvPercent.setTypeface(android.graphics.Typeface.MONOSPACE, android.graphics.Typeface.BOLD);
        headerRow.addView(tvPercent);

        progressCard.addView(headerRow);

        TextView tvSubTitle = new TextView(activity);
        tvSubTitle.setText("Snapdragon 8 Elite • Sandboxed Static Reverse-Engineering");
        tvSubTitle.setTextSize(senior ? 13 : 11);
        tvSubTitle.setTextColor(0xFF888888);
        LinearLayout.LayoutParams stlp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        stlp.topMargin = (int) (2 * density);
        stlp.bottomMargin = (int) (12 * density);
        tvSubTitle.setLayoutParams(stlp);
        progressCard.addView(tvSubTitle);

        ProgressBar pb = new ProgressBar(activity, null, android.R.attr.progressBarStyleHorizontal);
        pb.setIndeterminate(false);
        pb.setMax(100);
        pb.setProgress(5);
        LinearLayout.LayoutParams pbp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, (int) (10 * density));
        pbp.bottomMargin = (int) (12 * density);
        pb.setLayoutParams(pbp);
        progressCard.addView(pb);

        TextView tvStatus = new TextView(activity);
        tvStatus.setText("Initializing static analysis pipeline...");
        tvStatus.setTextSize(senior ? 14 : 12);
        tvStatus.setTextColor(0xFF222222);
        tvStatus.setTypeface(null, android.graphics.Typeface.BOLD);
        progressCard.addView(tvStatus);

        // Steps checklist log container
        LinearLayout containerLog = new LinearLayout(activity);
        containerLog.setOrientation(LinearLayout.VERTICAL);
        containerLog.setBackgroundColor(0xFFF3F3F1);
        containerLog.setPadding((int) (14 * density), (int) (12 * density), (int) (14 * density), (int) (12 * density));
        LinearLayout.LayoutParams clp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        clp.topMargin = (int) (12 * density);
        containerLog.setLayoutParams(clp);
        progressCard.addView(containerLog);

        containerApkResult.addView(progressCard);

        ApkStaticAnalyzer.analyzeUri(activity, uri, new ApkStaticAnalyzer.AnalysisCallback() {
            @Override
            public void onProgress(int currentStep, int totalSteps, String message) {
                int percent = Math.min(100, (int) (currentStep * 100.0 / totalSteps));
                pb.setProgress(percent);
                tvPercent.setText(percent + "%");
                tvStatus.setText("Stage " + currentStep + "/" + totalSteps + ": " + message);

                TextView logItem = new TextView(activity);
                logItem.setText("✓ " + message);
                logItem.setTextSize(11);
                logItem.setTextColor(0xFF333333);
                logItem.setLineSpacing(0, 1.2f);
                LinearLayout.LayoutParams lip = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
                lip.bottomMargin = (int) (4 * density);
                logItem.setLayoutParams(lip);
                containerLog.addView(logItem);
            }

            @Override
            public void onSuccess(ApkAnalysisReport report, ScanRecord scanRecord, List<FindingRecord> findings) {
                ActivityEvent event = AppState.mapScanRecordToActivityEvent(scanRecord, findings);
                lastApkReport = report;
                lastApkEvent = event;
                displayApkVerdictCard(report, event, senior);
                DetailSheetDialog.showEventDetails(activity, event);
            }

            @Override
            public void onError(String errorMessage) {
                containerApkResult.removeAllViews();
                LinearLayout errorCard = new LinearLayout(activity);
                errorCard.setOrientation(LinearLayout.VERTICAL);
                errorCard.setBackgroundResource(R.drawable.bg_card_cred);
                errorCard.setPadding((int) (20 * density), (int) (18 * density), (int) (20 * density), (int) (18 * density));

                TextView tvErrTitle = new TextView(activity);
                tvErrTitle.setText("⚠️ APK Analysis Could Not Complete");
                tvErrTitle.setTextSize(senior ? 16 : 14);
                tvErrTitle.setTextColor(0xFFA63232);
                tvErrTitle.setTypeface(null, android.graphics.Typeface.BOLD);
                errorCard.addView(tvErrTitle);

                TextView tvErrMsg = new TextView(activity);
                tvErrMsg.setText(errorMessage);
                tvErrMsg.setTextSize(senior ? 14 : 12);
                tvErrMsg.setTextColor(0xFF444444);
                LinearLayout.LayoutParams emp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
                emp.topMargin = (int) (8 * density);
                tvErrMsg.setLayoutParams(emp);
                errorCard.addView(tvErrMsg);

                containerApkResult.addView(errorCard);
                Toast.makeText(activity, errorMessage, Toast.LENGTH_LONG).show();
            }
        });
    }

    private void displayApkVerdictCard(ApkAnalysisReport report, ActivityEvent event, boolean senior) {
        containerApkResult.removeAllViews();

        LinearLayout resCard = new LinearLayout(activity);
        resCard.setOrientation(LinearLayout.VERTICAL);
        resCard.setBackgroundResource(R.drawable.bg_card_cred);
        resCard.setPadding((int) (18 * density), (int) (16 * density), (int) (18 * density), (int) (16 * density));
        resCard.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        // 1. Shared Verdict Badge
        resCard.addView(buildSharedVerdictBadge(report.getVerdict(), senior));

        // 2. Package & File Identity Header
        TextView tvFile = new TextView(activity);
        long sizeKb = report.getFileSizeBytes() > 0 ? (report.getFileSizeBytes() / 1024) : 0;
        String sizeStr = sizeKb > 1024 ? String.format(Locale.ROOT, "%.1f MB", sizeKb / 1024.0) : (sizeKb + " KB");
        tvFile.setText(report.getFileName() + " (" + sizeStr + ")");
        tvFile.setTextSize(senior ? 17 : 15);
        tvFile.setTextColor(0xFF141414);
        tvFile.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams fp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        fp.topMargin = (int) (10 * density);
        tvFile.setLayoutParams(fp);
        resCard.addView(tvFile);

        // SHA-256 Hash pill
        TextView tvHash = new TextView(activity);
        String hash = report.getSha256Checksum() != null ? report.getSha256Checksum() : "N/A";
        String displayHash = hash.length() > 24 ? (hash.substring(0, 12) + "..." + hash.substring(hash.length() - 10)) : hash;
        tvHash.setText("SHA-256: " + displayHash);
        tvHash.setTextSize(senior ? 12 : 11);
        tvHash.setTextColor(0xFF888888);
        tvHash.setTypeface(android.graphics.Typeface.MONOSPACE);
        LinearLayout.LayoutParams hp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        hp.topMargin = (int) (3 * density);
        tvHash.setLayoutParams(hp);
        resCard.addView(tvHash);

        // 3. Plain Language Assessment
        TextView tvPlain = new TextView(activity);
        tvPlain.setText(report.getPlainLanguageExplanation());
        tvPlain.setTextSize(senior ? 15 : 13);
        tvPlain.setTextColor(0xFF333333);
        tvPlain.setLineSpacing(0, 1.25f);
        LinearLayout.LayoutParams pp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        pp.topMargin = (int) (10 * density);
        tvPlain.setLayoutParams(pp);
        resCard.addView(tvPlain);

        // 4. Metadata Quick Summary Table (Package, Signature, Archive)
        LinearLayout metaGrid = new LinearLayout(activity);
        metaGrid.setOrientation(LinearLayout.VERTICAL);
        metaGrid.setBackgroundResource(R.drawable.bg_pill_dark);
        metaGrid.setPadding((int) (14 * density), (int) (12 * density), (int) (14 * density), (int) (12 * density));
        LinearLayout.LayoutParams mgp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        mgp.topMargin = (int) (12 * density);
        metaGrid.setLayoutParams(mgp);

        TextView tvMetaTitle = new TextView(activity);
        tvMetaTitle.setText("STATIC INSPECTION METADATA");
        tvMetaTitle.setTextSize(senior ? 12 : 10);
        tvMetaTitle.setTextColor(0xFF888888);
        tvMetaTitle.setTypeface(null, android.graphics.Typeface.BOLD);
        metaGrid.addView(tvMetaTitle);

        if (report.getManifestMetadata() != null) {
            String pkg = report.getManifestMetadata().getPackageName();
            String ver = report.getManifestMetadata().getVersionName() + " (" + report.getManifestMetadata().getVersionCode() + ")";
            int perms = report.getManifestMetadata().getRequestedPermissions().size();
            metaGrid.addView(createEvidenceBullet("• Package ID: " + pkg, senior));
            metaGrid.addView(createEvidenceBullet("• Version: " + ver + " | targetSdk: " + report.getManifestMetadata().getTargetSdk(), senior));
            metaGrid.addView(createEvidenceBullet("• Permissions Declared: " + perms, senior));
        }

        if (report.getCertificateMetadata() != null) {
            String certSubject = report.getCertificateMetadata().getSubject();
            boolean isDebug = report.getCertificateMetadata().isDebugCertificate();
            String certBadge = isDebug ? " ⚠️ (Debug Certificate)" : " (Release Signed)";
            metaGrid.addView(createEvidenceBullet("• Signer: " + (certSubject.length() > 36 ? certSubject.substring(0, 34) + "..." : certSubject) + certBadge, senior));
        }

        int zipEntries = report.getTotalZipEntries();
        int dexCount = report.getDexResult() != null ? report.getDexResult().getDexFileCount() : 0;
        int nativeLibs = report.getNativeLibraries() != null ? report.getNativeLibraries().size() : 0;
        metaGrid.addView(createEvidenceBullet("• Archive Inventory: " + zipEntries + " entries, " + dexCount + " DEX files, " + nativeLibs + " native libs", senior));

        resCard.addView(metaGrid);

        // 4.5 Live Cryptographic Hash Reputation Status Card
        HashReputationResult hashRep = report.getHashReputationResult();
        if (hashRep != null) {
            LinearLayout repCard = new LinearLayout(activity);
            repCard.setOrientation(LinearLayout.VERTICAL);
            repCard.setBackgroundResource(R.drawable.bg_pill_dark);
            repCard.setPadding((int) (14 * density), (int) (10 * density), (int) (14 * density), (int) (10 * density));
            LinearLayout.LayoutParams rcp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            rcp.topMargin = (int) (10 * density);
            repCard.setLayoutParams(rcp);

            TextView tvRepHead = new TextView(activity);
            String stateTitle = hashRep.getState().getDisplayName().toUpperCase(Locale.ROOT);
            tvRepHead.setText("LIVE HASH REPUTATION: " + stateTitle);
            tvRepHead.setTextSize(senior ? 12 : 10);
            tvRepHead.setTextColor(hashRep.getState() == ReputationState.THREAT_MATCH ? 0xFFA63232 : 0xFF666666);
            tvRepHead.setTypeface(null, android.graphics.Typeface.BOLD);
            repCard.addView(tvRepHead);

            TextView tvRepDetail = new TextView(activity);
            String detailMsg = hashRep.getStatusMessage();
            if (hashRep.getState() == ReputationState.THREAT_MATCH && hashRep.getMaliciousDetections() > 0) {
                detailMsg += " (" + hashRep.getMaliciousDetections() + "/" + hashRep.getTotalEngines() + " security vendors detected)";
            }
            tvRepDetail.setText(detailMsg);
            tvRepDetail.setTextSize(senior ? 13 : 11);
            tvRepDetail.setTextColor(0xFF444444);
            LinearLayout.LayoutParams rdp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            rdp.topMargin = (int) (4 * density);
            tvRepDetail.setLayoutParams(rdp);
            repCard.addView(tvRepDetail);

            resCard.addView(repCard);
        }

        // 5. Structured Evidence List
        LinearLayout evidenceBox = new LinearLayout(activity);
        evidenceBox.setOrientation(LinearLayout.VERTICAL);
        evidenceBox.setBackgroundResource(R.drawable.bg_pill_dark);
        evidenceBox.setPadding((int) (14 * density), (int) (12 * density), (int) (14 * density), (int) (12 * density));
        LinearLayout.LayoutParams ep = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        ep.topMargin = (int) (10 * density);
        evidenceBox.setLayoutParams(ep);

        TextView evHeader = new TextView(activity);
        int indCount = report.getIndicators() != null ? report.getIndicators().size() : 0;
        evHeader.setText("STRUCTURED EVIDENCE (" + indCount + " FINDINGS)");
        evHeader.setTextSize(senior ? 12 : 10);
        evHeader.setTextColor(0xFF888888);
        evHeader.setTypeface(null, android.graphics.Typeface.BOLD);
        evidenceBox.addView(evHeader);

        if (indCount == 0) {
            evidenceBox.addView(createEvidenceBullet("• No static threat indicators or dangerous permission combos observed.", senior));
        } else {
            for (ThreatIndicator ti : report.getIndicators()) {
                LinearLayout indItem = new LinearLayout(activity);
                indItem.setOrientation(LinearLayout.VERTICAL);
                indItem.setPadding(0, (int) (6 * density), 0, (int) (6 * density));

                LinearLayout badgeLine = new LinearLayout(activity);
                badgeLine.setOrientation(LinearLayout.HORIZONTAL);
                badgeLine.setGravity(Gravity.CENTER_VERTICAL);

                // Direct Fact vs Heuristic pill
                TextView factPill = new TextView(activity);
                factPill.setText(ti.isDirectFact() ? "FACT" : "HEURISTIC");
                factPill.setTextSize(9);
                factPill.setTypeface(null, android.graphics.Typeface.BOLD);
                factPill.setTextColor(0xFFFFFFFF);
                factPill.setBackgroundResource(ti.isDirectFact() ? R.drawable.bg_pill_black : R.drawable.bg_pill_dark);
                factPill.setPadding((int) (6 * density), (int) (2 * density), (int) (6 * density), (int) (2 * density));
                badgeLine.addView(factPill);

                // Source pill
                TextView srcPill = new TextView(activity);
                srcPill.setText(" [" + ti.getEvidenceSource() + "]");
                srcPill.setTextSize(10);
                srcPill.setTextColor(0xFF777777);
                badgeLine.addView(srcPill);

                // Severity
                TextView sevPill = new TextView(activity);
                sevPill.setText(" • " + ti.getSeverity().name());
                sevPill.setTextSize(10);
                sevPill.setTypeface(null, android.graphics.Typeface.BOLD);
                sevPill.setTextColor(ti.getSeverity() == ThreatSeverity.CRITICAL ? 0xFFA63232 :
                        (ti.getSeverity() == ThreatSeverity.HIGH ? 0xFFB35900 : 0xFF555555));
                badgeLine.addView(sevPill);

                indItem.addView(badgeLine);

                // What was observed
                TextView tvObs = new TextView(activity);
                tvObs.setText(ti.getTitle() + ": " + ti.getDescription());
                tvObs.setTextSize(senior ? 13 : 11);
                tvObs.setTextColor(0xFF141414);
                LinearLayout.LayoutParams obsp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
                obsp.topMargin = (int) (3 * density);
                tvObs.setLayoutParams(obsp);
                indItem.addView(tvObs);

                // Why it matters
                if (ti.getRiskRationale() != null && !ti.getRiskRationale().isEmpty() && !ti.getRiskRationale().equals(ti.getDescription())) {
                    TextView tvWhy = new TextView(activity);
                    tvWhy.setText("Why it matters: " + ti.getRiskRationale());
                    tvWhy.setTextSize(senior ? 12 : 10);
                    tvWhy.setTextColor(0xFF666666);
                    tvWhy.setLineSpacing(0, 1.15f);
                    LinearLayout.LayoutParams whyp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
                    whyp.topMargin = (int) (2 * density);
                    tvWhy.setLayoutParams(whyp);
                    indItem.addView(tvWhy);
                }

                evidenceBox.addView(indItem);
            }
        }

        resCard.addView(evidenceBox);

        // 6. Action Buttons Row
        LinearLayout actionsRow = new LinearLayout(activity);
        actionsRow.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams arp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        arp.topMargin = (int) (14 * density);
        actionsRow.setLayoutParams(arp);

        if (report.canSafelyProceedWithInstall()) {
            Button btnInstall = new Button(activity);
            btnInstall.setText("Proceed with Android Install");
            btnInstall.setBackgroundResource(R.drawable.bg_pill_emerald);
            btnInstall.setTextColor(0xFF386B57);
            btnInstall.setTextSize(senior ? 14 : 12);
            btnInstall.setTypeface(null, android.graphics.Typeface.BOLD);
            LinearLayout.LayoutParams bip = new LinearLayout.LayoutParams(0, (int) (46 * density), 1f);
            bip.rightMargin = (int) (6 * density);
            btnInstall.setLayoutParams(bip);
            btnInstall.setOnClickListener(v -> Toast.makeText(activity, "Safe to install. Downloaded package verified against known threats.", Toast.LENGTH_SHORT).show());
            actionsRow.addView(btnInstall);
        } else {
            Button btnDelete = new Button(activity);
            btnDelete.setText("🗑️ Quarantine & Advise Deletion");
            btnDelete.setBackgroundResource(R.drawable.bg_pill_crimson);
            btnDelete.setTextColor(0xFFA63232);
            btnDelete.setTextSize(senior ? 14 : 12);
            btnDelete.setTypeface(null, android.graphics.Typeface.BOLD);
            LinearLayout.LayoutParams bdp = new LinearLayout.LayoutParams(0, (int) (46 * density), 1f);
            bdp.rightMargin = (int) (6 * density);
            btnDelete.setLayoutParams(bdp);
            btnDelete.setOnClickListener(v -> {
                Toast.makeText(activity, "Threat quarantined. Advised removing the file from device downloads.", Toast.LENGTH_LONG).show();
                containerApkResult.removeAllViews();
            });
            actionsRow.addView(btnDelete);
        }

        Button btnAskAssistant = new Button(activity);
        btnAskAssistant.setText("💬 Ask Assistant");
        btnAskAssistant.setBackgroundResource(R.drawable.bg_pill_black);
        btnAskAssistant.setTextColor(0xFFFFFFFF);
        btnAskAssistant.setTextSize(senior ? 14 : 12);
        btnAskAssistant.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams bap = new LinearLayout.LayoutParams(0, (int) (46 * density), 1f);
        bap.leftMargin = (int) (6 * density);
        btnAskAssistant.setLayoutParams(bap);
        btnAskAssistant.setOnClickListener(v -> {
            if (activity instanceof MainActivity) {
                AppState.get().setActiveFindingContext(new SecurityFindingContext(
                        SecurityFindingContext.FindingType.APK,
                        report.getFileName(),
                        report.getFileName(),
                        report.getVerdict(),
                        null,
                        null,
                        "Static APK bytecode inspection on Snapdragon 8 Elite",
                        AppState.get().isSeniorMode(),
                        AppState.get().isHindi()
                ));
                ((MainActivity) activity).openContextualAssistant("Please explain why " + report.getFileName() + " received verdict [" + report.getVerdict().getDisplayName() + "] and what safety precautions I should follow.");
            }
        });
        actionsRow.addView(btnAskAssistant);

        resCard.addView(actionsRow);
        containerApkResult.addView(resCard);
    }

    // ==========================================
    // 2. LINK CHECK SUB-FLOW
    // ==========================================
    private void renderLinkSubFlow(boolean senior) {
        LinearLayout card = new LinearLayout(activity);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundResource(R.drawable.bg_card_cred);
        card.setPadding((int) (20 * density), (int) (18 * density), (int) (20 * density), (int) (18 * density));
        card.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        ));

        TextView title = new TextView(activity);
        title.setText("PHISHING & FRAUD LINK CHECKER");
        title.setTextSize(senior ? 16 : 14);
        title.setTextColor(0xFF141414);
        title.setTypeface(null, android.graphics.Typeface.BOLD);
        card.addView(title);

        TextView desc = new TextView(activity);
        desc.setText(senior
                ? "Enter or paste any suspicious web address from SMS or WhatsApp to test if it is a fake banking page."
                : "Heuristic scanner checks Punycode homoglyphs, high-risk disposable TLDs (.top, .xyz), raw IP targets, and banking impersonations.");
        desc.setTextSize(senior ? 14 : 12);
        desc.setTextColor(0xFF666666);
        desc.setLineSpacing(0, 1.2f);
        LinearLayout.LayoutParams dp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        dp.topMargin = (int) (6 * density);
        dp.bottomMargin = (int) (14 * density);
        desc.setLayoutParams(dp);
        card.addView(desc);

        // Input Field
        etLinkInput = new EditText(activity);
        etLinkInput.setHint("https://sbi-kyc-verify.top/login");
        etLinkInput.setHintTextColor(0xFF888888);
        etLinkInput.setTextColor(0xFF141414);
        etLinkInput.setTextSize(senior ? 15 : 13);
        etLinkInput.setBackgroundResource(R.drawable.bg_input_field);
        etLinkInput.setPadding((int) (16 * density), (int) (14 * density), (int) (16 * density), (int) (14 * density));
        card.addView(etLinkInput);

        // Analyze Button
        Button btnScanLink = new Button(activity);
        btnScanLink.setText("🔍 Analyze Link Safety");
        btnScanLink.setBackgroundResource(R.drawable.bg_pill_black);
        btnScanLink.setTextColor(0xFFFFFFFF);
        btnScanLink.setTextSize(senior ? 15 : 13);
        btnScanLink.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams bp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, (int) (48 * density));
        bp.topMargin = (int) (12 * density);
        btnScanLink.setLayoutParams(bp);
        btnScanLink.setOnClickListener(v -> {
            String text = etLinkInput.getText().toString().trim();
            if (text.isEmpty()) {
                showLinkValidationError("The web address cannot be empty or blank. Please enter a valid URL.");
                return;
            }
            executeLinkAnalysis(text, senior);
        });
        card.addView(btnScanLink);

        // Quick Samples Row
        TextView sampleLabel = new TextView(activity);
        sampleLabel.setText("QUICK TEST SAMPLES");
        sampleLabel.setTextSize(senior ? 12 : 10);
        sampleLabel.setTextColor(0xFF888888);
        sampleLabel.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams slp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        slp.topMargin = (int) (14 * density);
        slp.bottomMargin = (int) (8 * density);
        sampleLabel.setLayoutParams(slp);
        card.addView(sampleLabel);

        HorizontalScrollView hsv = new HorizontalScrollView(activity);
        hsv.setHorizontalScrollBarEnabled(false);
        LinearLayout samplesRow = new LinearLayout(activity);
        samplesRow.setOrientation(LinearLayout.HORIZONTAL);
        hsv.addView(samplesRow);

        samplesRow.addView(createSampleChip("Fake SBI KYC (.top)", () -> {
            etLinkInput.setText("http://sbi-kyc-verify.top/update");
            executeLinkAnalysis("http://sbi-kyc-verify.top/update", senior);
        }));

        samplesRow.addView(createSampleChip("Gaming Scam (free-bgmi.top)", () -> {
            etLinkInput.setText("http://free-bgmi-uc-rewards.top/claim");
            executeLinkAnalysis("http://free-bgmi-uc-rewards.top/claim", senior);
        }));

        samplesRow.addView(createSampleChip("Raw IP Target (192.168.1.100)", () -> {
            etLinkInput.setText("http://192.168.1.100/bank");
            executeLinkAnalysis("http://192.168.1.100/bank", senior);
        }));

        samplesRow.addView(createSampleChip("Official SBI (onlinesbi.sbi)", () -> {
            etLinkInput.setText("https://onlinesbi.sbi");
            executeLinkAnalysis("https://onlinesbi.sbi", senior);
        }));

        card.addView(hsv);

        // Result Container
        containerLinkResult = new LinearLayout(activity);
        containerLinkResult.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams crp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        crp.topMargin = (int) (16 * density);
        containerLinkResult.setLayoutParams(crp);
        card.addView(containerLinkResult);

        containerFlow.addView(card);
    }

    private void showLinkValidationError(String message) {
        if (containerLinkResult == null) return;
        containerLinkResult.removeAllViews();

        LinearLayout errCard = new LinearLayout(activity);
        errCard.setOrientation(LinearLayout.VERTICAL);
        errCard.setBackgroundResource(R.drawable.bg_card_cred);
        errCard.setPadding((int) (18 * density), (int) (16 * density), (int) (18 * density), (int) (16 * density));

        TextView tvErrTitle = new TextView(activity);
        tvErrTitle.setText("⚠️ Invalid Web Address");
        tvErrTitle.setTextSize(15);
        tvErrTitle.setTextColor(0xFFA63232);
        tvErrTitle.setTypeface(null, android.graphics.Typeface.BOLD);
        errCard.addView(tvErrTitle);

        TextView tvErrMsg = new TextView(activity);
        tvErrMsg.setText(message);
        tvErrMsg.setTextSize(13);
        tvErrMsg.setTextColor(0xFF444444);
        tvErrMsg.setLineSpacing(0, 1.2f);
        LinearLayout.LayoutParams emp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        emp.topMargin = (int) (6 * density);
        tvErrMsg.setLayoutParams(emp);
        errCard.addView(tvErrMsg);

        TextView tvHelp = new TextView(activity);
        tvHelp.setText("Tip: Enter an address beginning with http:// or https://, or a valid domain such as onlinesbi.sbi.");
        tvHelp.setTextSize(11);
        tvHelp.setTextColor(0xFF888888);
        LinearLayout.LayoutParams hp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        hp.topMargin = (int) (8 * density);
        tvHelp.setLayoutParams(hp);
        errCard.addView(tvHelp);

        containerLinkResult.addView(errCard);
    }

    private void executeLinkAnalysis(String rawUrl, boolean senior) {
        if (containerLinkResult == null) return;
        containerLinkResult.removeAllViews();

        try {
            // Step 1 & 2 & 3: Robust parsing, local heuristics, and reputation interface
            UrlAnalysisResult analysis = AppState.get().getPhishingScanner().analyze(rawUrl);
            ParsedUrl parsed = analysis.getParsedUrl();
            ScanVerdict verdict = analysis.getCombinedVerdict();
            ThreatSeverity severity = analysis.getOverallSeverity();

            // Persist the real result to Phase 2 SecurityAuditRepository
            String scanId = "scan-link-" + System.currentTimeMillis();
            String verdictStr = (verdict == ScanVerdict.KNOWN_MALICIOUS) ? "KNOWN_MALICIOUS" :
                    (verdict == ScanVerdict.HIGH_RISK || verdict == ScanVerdict.CAUTION ? "SUSPICIOUS" : "SAFE");
            String sevStr = severity.name();

            ScanRecord scan = new ScanRecord(
                    scanId,
                    "LINK",
                    System.currentTimeMillis(),
                    "COMPLETED",
                    analysis.getPlainAdvice(),
                    parsed.getOriginalInput(), // Real URL actually evaluated!
                    "1.0.0",
                    true,
                    verdictStr,
                    sevStr,
                    verdict == ScanVerdict.KNOWN_MALICIOUS ? "Block Destination" : "Proceed with Caution"
            );

            List<FindingRecord> findings = new ArrayList<>();
            int fIdx = 1;
            if (analysis.getReputationResult() != null && analysis.getReputationResult().getState() != ReputationState.NOT_CHECKED) {
                ReputationResult rep = analysis.getReputationResult();
                findings.add(new FindingRecord(
                        scanId + "-f" + (fIdx++),
                        scanId,
                        "CLOUD_URL_INTEL",
                        rep.getState() == ReputationState.THREAT_MATCH ? "CRITICAL" : (rep.getState() == ReputationState.NO_KNOWN_THREAT_MATCH ? "INFO" : "LOW"),
                        "[Threat Intel] " + rep.getProviderName() + ": " + rep.getStatusMessage(),
                        rep.getState() == ReputationState.THREAT_MATCH ? "Matches confirmed phishing/malware threat list" : "Live reputation lookup completed"
                ));
            }
            for (UrlIndicator ind : analysis.getIndicators()) {
                findings.add(new FindingRecord(
                        scanId + "-f" + (fIdx++),
                        scanId,
                        ind.getCategory(),
                        ind.getSeverity().name(),
                        ind.getTitle() + ": " + ind.getExplanation() + " (Evidence: " + ind.getEvidence() + ")",
                        ind.getSeverity() == ThreatSeverity.CRITICAL ? "Do not submit credentials" : "Verify official domain"
                ));
            }

            AppState.get().recordScan(scan, findings);

            // Step 4: Render comprehensive result UI
            displayLinkVerdictCard(analysis, senior);

        } catch (UrlParseException e) {
            showLinkValidationError(e.getMessage());
        } catch (Exception e) {
            showLinkValidationError("Failed to complete link evaluation: " + e.getMessage());
        }
    }

    private void displayLinkVerdictCard(UrlAnalysisResult result, boolean senior) {
        containerLinkResult.removeAllViews();

        LinearLayout resCard = new LinearLayout(activity);
        resCard.setOrientation(LinearLayout.VERTICAL);
        resCard.setBackgroundResource(R.drawable.bg_card_cred);
        resCard.setPadding((int) (18 * density), (int) (16 * density), (int) (18 * density), (int) (16 * density));
        resCard.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        // 1. Shared Verdict Badge
        resCard.addView(buildSharedVerdictBadge(result.getCombinedVerdict(), senior));

        // 2. Parsed URL Anatomy Card (Hostname, Scheme, Path)
        LinearLayout urlAnatomy = new LinearLayout(activity);
        urlAnatomy.setOrientation(LinearLayout.VERTICAL);
        urlAnatomy.setBackgroundResource(R.drawable.bg_pill_dark);
        urlAnatomy.setPadding((int) (14 * density), (int) (12 * density), (int) (14 * density), (int) (12 * density));
        LinearLayout.LayoutParams uap = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        uap.topMargin = (int) (12 * density);
        urlAnatomy.setLayoutParams(uap);

        TextView tvAnatomyTitle = new TextView(activity);
        tvAnatomyTitle.setText("PARSED WEB ADDRESS ARCHITECTURE");
        tvAnatomyTitle.setTextSize(senior ? 12 : 10);
        tvAnatomyTitle.setTextColor(0xFF888888);
        tvAnatomyTitle.setTypeface(null, android.graphics.Typeface.BOLD);
        urlAnatomy.addView(tvAnatomyTitle);

        ParsedUrl parsed = result.getParsedUrl();
        String hostDisplay = parsed.getAsciiHost();
        if (parsed.isPunycode() || parsed.containsNonAscii()) {
            hostDisplay += " (Unicode: " + parsed.getUnicodeHost() + ")";
        }
        urlAnatomy.addView(createEvidenceBullet("• Server Hostname: " + hostDisplay, senior));
        urlAnatomy.addView(createEvidenceBullet("• Protocol: " + parsed.getScheme().toUpperCase(Locale.ROOT)
                + (parsed.isNonStandardPort() ? " (Custom Port " + parsed.getPort() + ")" : " (Standard Port)"), senior));
        urlAnatomy.addView(createEvidenceBullet("• Resource Path: " + parsed.getPath(), senior));
        if (parsed.hasUserInfo()) {
            urlAnatomy.addView(createEvidenceBullet("• Embedded User-Info Prefix: " + parsed.getUserInfo() + " [Deceptive]", senior));
        }

        resCard.addView(urlAnatomy);

        // 3. Plain Language Assessment
        TextView tvAdvice = new TextView(activity);
        tvAdvice.setText(result.getPlainAdvice());
        tvAdvice.setTextSize(senior ? 15 : 13);
        tvAdvice.setTextColor(0xFF333333);
        tvAdvice.setLineSpacing(0, 1.25f);
        LinearLayout.LayoutParams ap = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        ap.topMargin = (int) (10 * density);
        tvAdvice.setLayoutParams(ap);
        resCard.addView(tvAdvice);

        // 4. Live Threat Reputation Status Card
        LinearLayout repCard = new LinearLayout(activity);
        repCard.setOrientation(LinearLayout.VERTICAL);
        repCard.setBackgroundResource(R.drawable.bg_pill_dark);
        repCard.setPadding((int) (14 * density), (int) (10 * density), (int) (14 * density), (int) (10 * density));
        LinearLayout.LayoutParams rcp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        rcp.topMargin = (int) (10 * density);
        repCard.setLayoutParams(rcp);

        TextView tvRepHead = new TextView(activity);
        tvRepHead.setText("LIVE REPUTATION STATUS: " + result.getReputationResult().getState().getDisplayName().toUpperCase(Locale.ROOT));
        tvRepHead.setTextSize(senior ? 12 : 10);
        tvRepHead.setTextColor(result.getReputationResult().getState() == ReputationState.THREAT_MATCH ? 0xFFA63232 : 0xFF666666);
        tvRepHead.setTypeface(null, android.graphics.Typeface.BOLD);
        repCard.addView(tvRepHead);

        TextView tvRepDetail = new TextView(activity);
        tvRepDetail.setText(result.getReputationResult().getStatusMessage());
        tvRepDetail.setTextSize(senior ? 13 : 11);
        tvRepDetail.setTextColor(0xFF444444);
        LinearLayout.LayoutParams rdp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        rdp.topMargin = (int) (4 * density);
        tvRepDetail.setLayoutParams(rdp);
        repCard.addView(tvRepDetail);

        resCard.addView(repCard);

        // 5. Observable Forensic Signals / Warning Signs
        LinearLayout cuesBox = new LinearLayout(activity);
        cuesBox.setOrientation(LinearLayout.VERTICAL);
        cuesBox.setBackgroundResource(R.drawable.bg_pill_dark);
        cuesBox.setPadding((int) (14 * density), (int) (12 * density), (int) (14 * density), (int) (12 * density));
        LinearLayout.LayoutParams cp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        cp.topMargin = (int) (10 * density);
        cuesBox.setLayoutParams(cp);

        TextView cueHead = new TextView(activity);
        int cueCount = result.getIndicators().size();
        cueHead.setText("OBSERVABLE FORENSIC SIGNALS (" + cueCount + " DETECTED)");
        cueHead.setTextSize(senior ? 12 : 10);
        cueHead.setTextColor(0xFF888888);
        cueHead.setTypeface(null, android.graphics.Typeface.BOLD);
        cuesBox.addView(cueHead);

        if (result.getIndicators().isEmpty()) {
            cuesBox.addView(createEvidenceBullet("• No structural deception, homoglyphs, or urgency lures detected.", senior));
            cuesBox.addView(createEvidenceBullet("• Hostname syntax matches valid domain registration conventions.", senior));
        } else {
            for (UrlIndicator ind : result.getIndicators()) {
                LinearLayout indItem = new LinearLayout(activity);
                indItem.setOrientation(LinearLayout.VERTICAL);
                indItem.setPadding(0, (int) (5 * density), 0, (int) (5 * density));

                LinearLayout badgeRow = new LinearLayout(activity);
                badgeRow.setOrientation(LinearLayout.HORIZONTAL);
                badgeRow.setGravity(Gravity.CENTER_VERTICAL);

                TextView pillHeuristic = new TextView(activity);
                pillHeuristic.setText("HEURISTIC");
                pillHeuristic.setTextSize(9);
                pillHeuristic.setTypeface(null, android.graphics.Typeface.BOLD);
                pillHeuristic.setTextColor(0xFFFFFFFF);
                pillHeuristic.setBackgroundResource(R.drawable.bg_pill_black);
                pillHeuristic.setPadding((int) (6 * density), (int) (2 * density), (int) (6 * density), (int) (2 * density));
                badgeRow.addView(pillHeuristic);

                TextView pillCat = new TextView(activity);
                pillCat.setText(" [" + ind.getCategory() + "]");
                pillCat.setTextSize(10);
                pillCat.setTextColor(0xFF777777);
                badgeRow.addView(pillCat);

                TextView pillSev = new TextView(activity);
                pillSev.setText(" • " + ind.getSeverity().name());
                pillSev.setTextSize(10);
                pillSev.setTypeface(null, android.graphics.Typeface.BOLD);
                pillSev.setTextColor(ind.getSeverity() == ThreatSeverity.CRITICAL ? 0xFFA63232 :
                        (ind.getSeverity() == ThreatSeverity.HIGH ? 0xFFB35900 : 0xFF555555));
                badgeRow.addView(pillSev);

                indItem.addView(badgeRow);

                TextView tvObs = new TextView(activity);
                tvObs.setText(ind.getTitle() + ": " + ind.getExplanation());
                tvObs.setTextSize(senior ? 13 : 11);
                tvObs.setTextColor(0xFF141414);
                LinearLayout.LayoutParams obsp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
                obsp.topMargin = (int) (3 * density);
                tvObs.setLayoutParams(obsp);
                indItem.addView(tvObs);

                TextView tvEv = new TextView(activity);
                tvEv.setText("Evidence: " + ind.getEvidence());
                tvEv.setTextSize(senior ? 12 : 10);
                tvEv.setTextColor(0xFF666666);
                indItem.addView(tvEv);

                TextView tvRat = new TextView(activity);
                tvRat.setText("Why it matters: " + ind.getSeverityRationale());
                tvRat.setTextSize(senior ? 11 : 9);
                tvRat.setTextColor(0xFF888888);
                indItem.addView(tvRat);

                cuesBox.addView(indItem);
            }
        }

        resCard.addView(cuesBox);

        // 6. Practical Next Steps Card
        LinearLayout stepsBox = new LinearLayout(activity);
        stepsBox.setOrientation(LinearLayout.VERTICAL);
        stepsBox.setBackgroundResource(R.drawable.bg_pill_dark);
        stepsBox.setPadding((int) (14 * density), (int) (12 * density), (int) (14 * density), (int) (12 * density));
        LinearLayout.LayoutParams sbp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        sbp.topMargin = (int) (10 * density);
        stepsBox.setLayoutParams(sbp);

        TextView tvStepsTitle = new TextView(activity);
        tvStepsTitle.setText("PRACTICAL NEXT STEPS");
        tvStepsTitle.setTextSize(senior ? 12 : 10);
        tvStepsTitle.setTextColor(0xFF888888);
        tvStepsTitle.setTypeface(null, android.graphics.Typeface.BOLD);
        stepsBox.addView(tvStepsTitle);

        for (String step : result.getPracticalNextSteps()) {
            stepsBox.addView(createEvidenceBullet(step, senior));
        }

        resCard.addView(stepsBox);

        // 7. Uncertainty and Limitations Disclaimer
        TextView tvLimit = new TextView(activity);
        tvLimit.setText(result.getUncertaintyLimitations());
        tvLimit.setTextSize(senior ? 12 : 10);
        tvLimit.setTextColor(0xFF888888);
        tvLimit.setLineSpacing(0, 1.15f);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = (int) (10 * density);
        tvLimit.setLayoutParams(lp);
        resCard.addView(tvLimit);

        // 8. Action Buttons (Retry, Check Another, Ask Copilot)
        LinearLayout actionsRow = new LinearLayout(activity);
        actionsRow.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams arp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        arp.topMargin = (int) (14 * density);
        actionsRow.setLayoutParams(arp);

        Button btnRetry = new Button(activity);
        btnRetry.setText("🔄 Retry");
        btnRetry.setBackgroundResource(R.drawable.bg_pill_dark);
        btnRetry.setTextColor(0xFF141414);
        btnRetry.setTextSize(senior ? 13 : 11);
        btnRetry.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams brp = new LinearLayout.LayoutParams(0, (int) (44 * density), 1f);
        brp.rightMargin = (int) (4 * density);
        btnRetry.setLayoutParams(brp);
        btnRetry.setOnClickListener(v -> executeLinkAnalysis(parsed.getOriginalInput(), senior));
        actionsRow.addView(btnRetry);

        Button btnClear = new Button(activity);
        btnClear.setText("🧹 Check Another");
        btnClear.setBackgroundResource(R.drawable.bg_pill_dark);
        btnClear.setTextColor(0xFF141414);
        btnClear.setTextSize(senior ? 13 : 11);
        btnClear.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams bcp = new LinearLayout.LayoutParams(0, (int) (44 * density), 1f);
        bcp.rightMargin = (int) (4 * density);
        btnClear.setLayoutParams(bcp);
        btnClear.setOnClickListener(v -> {
            etLinkInput.setText("");
            containerLinkResult.removeAllViews();
        });
        actionsRow.addView(btnClear);

        Button btnAsk = new Button(activity);
        btnAsk.setText("💬 Ask Copilot");
        btnAsk.setBackgroundResource(R.drawable.bg_pill_black);
        btnAsk.setTextColor(0xFFFFFFFF);
        btnAsk.setTextSize(senior ? 13 : 11);
        btnAsk.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams bap = new LinearLayout.LayoutParams(0, (int) (44 * density), 1.2f);
        btnAsk.setLayoutParams(bap);
        btnAsk.setOnClickListener(v -> {
            if (activity instanceof MainActivity) {
                AppState.get().setActiveFindingContext(SecurityFindingContext.fromUrlResult(
                        result, AppState.get().isSeniorMode(), AppState.get().isHindi()
                ));
                String prompt = "Please explain the safety analysis for this web address: " + parsed.getOriginalInput()
                        + "\nHostname: " + parsed.getAsciiHost()
                        + "\nVerdict: " + result.getCombinedVerdict().getDisplayName();
                ((MainActivity) activity).openContextualAssistant(prompt);
            }
        });
        actionsRow.addView(btnAsk);

        resCard.addView(actionsRow);

        containerLinkResult.addView(resCard);
    }

    // ==========================================
    // 3. MESSAGE CHECK SUB-FLOW
    // ==========================================
    private void renderMessageSubFlow(boolean senior) {
        LinearLayout card = new LinearLayout(activity);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundResource(R.drawable.bg_card_cred);
        card.setPadding((int) (20 * density), (int) (18 * density), (int) (20 * density), (int) (18 * density));
        card.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        ));

        TextView title = new TextView(activity);
        title.setText("SMS, OTP & COERCION EVALUATOR");
        title.setTextSize(senior ? 16 : 14);
        title.setTextColor(0xFF141414);
        title.setTypeface(null, android.graphics.Typeface.BOLD);
        card.addView(title);

        TextView desc = new TextView(activity);
        desc.setText(senior
                ? "Paste any message you received demanding money, OTP, or secrecy to see if it is a scam."
                : "Hinglish & English NLP engine evaluates parcel fraud, fake bank KYC threats, accidental UPI refund traps, and grooming secrecy.");
        desc.setTextSize(senior ? 14 : 12);
        desc.setTextColor(0xFF666666);
        desc.setLineSpacing(0, 1.2f);
        LinearLayout.LayoutParams dp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        dp.topMargin = (int) (6 * density);
        dp.bottomMargin = (int) (14 * density);
        desc.setLayoutParams(dp);
        card.addView(desc);

        // Selectable Sample Cases Header
        TextView samplesLabel = new TextView(activity);
        samplesLabel.setText("SELECT COMMON SCAM TEMPLATE TO TEST:");
        samplesLabel.setTextSize(senior ? 12 : 10);
        samplesLabel.setTextColor(0xFF888888);
        samplesLabel.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams slp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        slp.bottomMargin = (int) (8 * density);
        samplesLabel.setLayoutParams(slp);
        card.addView(samplesLabel);

        // Sample Cases Chips
        card.addView(createSampleCaseButton("📦 1. Parcel Delivery Scam",
                "Your IndiaPost package #IN8492 is held at sorting depot. Pay ₹25 address confirmation fee at bit.ly/del-track or item will be discarded today.", senior));
        card.addView(createSampleCaseButton("🏦 2. Fake Bank / KYC Block Prompt",
                "Dear Customer, your SBI YONO account has been suspended due to pending KYC. Update PAN card immediately at http://sbi-kyc-verify.top to avoid card freeze.", senior));
        card.addView(createSampleCaseButton("💸 3. Urgent UPI Mistake Trap",
                "Bhai I accidentally sent ₹5,000 by mistake to your Google Pay number. Please refund ₹5,000 immediately, my mother is in hospital emergency!", senior));
        card.addView(createSampleCaseButton("🤫 4. Secrecy & Isolation Coercion",
                "Yeh baat sirf hamare beech rahegi, kisi ko mat batana. Camera on kar ke aaja call pe, parents ko pata nahi chalna chahiye.", senior));

        // Multiline Input
        TextView inputLabel = new TextView(activity);
        inputLabel.setText("OR PASTE MESSAGE TEXT:");
        inputLabel.setTextSize(senior ? 12 : 10);
        inputLabel.setTextColor(0xFF888888);
        inputLabel.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams ilp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        ilp.topMargin = (int) (14 * density);
        ilp.bottomMargin = (int) (6 * density);
        inputLabel.setLayoutParams(ilp);
        card.addView(inputLabel);

        etMessageInput = new EditText(activity);
        etMessageInput.setHint("Paste SMS or chat excerpt here...");
        etMessageInput.setHintTextColor(0xFF888888);
        etMessageInput.setTextColor(0xFF141414);
        etMessageInput.setTextSize(senior ? 15 : 13);
        etMessageInput.setBackgroundResource(R.drawable.bg_input_field);
        etMessageInput.setPadding((int) (16 * density), (int) (14 * density), (int) (16 * density), (int) (14 * density));
        etMessageInput.setMinLines(3);
        etMessageInput.setGravity(Gravity.TOP);
        card.addView(etMessageInput);

        Button btnAnalyzeMsg = new Button(activity);
        btnAnalyzeMsg.setText("🧠 Analyze Message");
        btnAnalyzeMsg.setBackgroundResource(R.drawable.bg_pill_black);
        btnAnalyzeMsg.setTextColor(0xFFFFFFFF);
        btnAnalyzeMsg.setTextSize(senior ? 15 : 13);
        btnAnalyzeMsg.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams bp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, (int) (48 * density));
        bp.topMargin = (int) (12 * density);
        btnAnalyzeMsg.setLayoutParams(bp);
        btnAnalyzeMsg.setOnClickListener(v -> {
            String text = etMessageInput != null ? etMessageInput.getText().toString().trim() : "";
            executeMessageAnalysis(text, senior);
        });
        card.addView(btnAnalyzeMsg);

        // Result Container
        containerMessageResult = new LinearLayout(activity);
        containerMessageResult.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams mrp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        mrp.topMargin = (int) (16 * density);
        containerMessageResult.setLayoutParams(mrp);
        card.addView(containerMessageResult);

        containerFlow.addView(card);
    }

    private View createSampleCaseButton(String title, String message, boolean senior) {
        LinearLayout row = new LinearLayout(activity);
        row.setOrientation(LinearLayout.VERTICAL);
        row.setBackgroundResource(R.drawable.bg_card_interactive);
        row.setPadding((int) (14 * density), (int) (10 * density), (int) (14 * density), (int) (10 * density));
        LinearLayout.LayoutParams rp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        rp.bottomMargin = (int) (8 * density);
        row.setLayoutParams(rp);
        row.setOnClickListener(v -> {
            if (etMessageInput != null) {
                etMessageInput.setText(message);
            }
            executeMessageAnalysis(message, senior);
        });

        TextView tvTitle = new TextView(activity);
        tvTitle.setText(title);
        tvTitle.setTextSize(senior ? 15 : 13);
        tvTitle.setTextColor(0xFF141414);
        tvTitle.setTypeface(null, android.graphics.Typeface.BOLD);
        row.addView(tvTitle);

        TextView tvSnippet = new TextView(activity);
        tvSnippet.setText(message);
        tvSnippet.setTextSize(senior ? 13 : 11);
        tvSnippet.setTextColor(0xFF666666);
        tvSnippet.setMaxLines(1);
        row.addView(tvSnippet);

        return row;
    }

    private void executeMessageAnalysis(String messageText, boolean senior) {
        containerMessageResult.removeAllViews();

        // 1. Genuine Insufficient-Evidence / Empty State Handling
        if (messageText == null || messageText.trim().isEmpty()) {
            LinearLayout emptyCard = new LinearLayout(activity);
            emptyCard.setOrientation(LinearLayout.VERTICAL);
            emptyCard.setBackgroundResource(R.drawable.bg_card_cred);
            emptyCard.setPadding((int) (18 * density), (int) (16 * density), (int) (18 * density), (int) (16 * density));
            emptyCard.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

            TextView tvWarnTitle = new TextView(activity);
            tvWarnTitle.setText("⚠️ Message Empty or Incomplete");
            tvWarnTitle.setTextSize(senior ? 16 : 14);
            tvWarnTitle.setTextColor(0xFFB00020);
            tvWarnTitle.setTypeface(null, android.graphics.Typeface.BOLD);
            emptyCard.addView(tvWarnTitle);

            TextView tvWarnMsg = new TextView(activity);
            tvWarnMsg.setText("The message text cannot be empty. Please enter or paste message content from SMS, WhatsApp, or email to evaluate its risk.");
            tvWarnMsg.setTextSize(senior ? 14 : 12);
            tvWarnMsg.setTextColor(0xFF444444);
            LinearLayout.LayoutParams wmp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            wmp.topMargin = (int) (8 * density);
            tvWarnMsg.setLayoutParams(wmp);
            emptyCard.addView(tvWarnMsg);

            TextView tvTip = new TextView(activity);
            tvTip.setText("Tip: You can tap one of the common scam templates above to test real-world fraud indicators.");
            tvTip.setTextSize(senior ? 12 : 11);
            tvTip.setTextColor(0xFF888888);
            LinearLayout.LayoutParams tp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            tp.topMargin = (int) (8 * density);
            tvTip.setLayoutParams(tp);
            emptyCard.addView(tvTip);

            containerMessageResult.addView(emptyCard);
            return;
        }

        // 2. Real on-device rules analysis
        MessageRiskAssessment assessment = AppState.get().getMessageRiskAnalyzer().analyze(messageText);

        // Map to shared ScanVerdict
        ScanVerdict verdict;
        if (assessment.getCategory() == MessageRiskCategory.HIGH_RISK) {
            verdict = ScanVerdict.KNOWN_MALICIOUS;
        } else if (assessment.getCategory() == MessageRiskCategory.SUSPICIOUS) {
            verdict = ScanVerdict.HIGH_RISK;
        } else if (assessment.getCategory() == MessageRiskCategory.AMBIGUOUS) {
            verdict = ScanVerdict.CAUTION;
        } else {
            verdict = ScanVerdict.NO_KNOWN_THREAT_DETECTED;
        }

        // 3. User Privacy: Persist metadata & indicators ONLY, NEVER store raw chat text in history
        String mScanId = "scan-" + System.currentTimeMillis();
        String mVerdictStr = (verdict == ScanVerdict.KNOWN_MALICIOUS) ? "KNOWN_MALICIOUS" :
                (verdict == ScanVerdict.HIGH_RISK || verdict == ScanVerdict.CAUTION ? "SUSPICIOUS" : "SAFE");
        String mSevStr = assessment.getSeverity().name();
        String privacySnippet = "[Message Analysis: " + assessment.getCategory().name() + " • " + assessment.getIndicatorCount() + " indicators matched]";

        ScanRecord mScan = new ScanRecord(
                mScanId,
                "MESSAGE",
                System.currentTimeMillis(),
                "COMPLETED",
                assessment.getOverallSummary(),
                privacySnippet,
                assessment.getRulesVersion(),
                true,
                mVerdictStr,
                mSevStr,
                assessment.getSeverity() == ThreatSeverity.CRITICAL ? "Block Sender" : "Review Advice"
        );
        List<FindingRecord> mFindings = new ArrayList<>();
        if (assessment.getIndicators() != null) {
            int mfIdx = 1;
            for (MessageIndicator ind : assessment.getIndicators()) {
                mFindings.add(new FindingRecord(
                        mScanId + "-f" + (mfIdx++),
                        mScanId,
                        ind.getType().name(),
                        ind.getSeverity().name(),
                        ind.getTitle() + " (Evidence: \"" + ind.getEvidenceText() + "\")",
                        ind.getPlainLanguageExplanation()
                ));
            }
        }
        AppState.get().recordScan(mScan, mFindings);

        // 4. Render comprehensive results card
        LinearLayout resCard = new LinearLayout(activity);
        resCard.setOrientation(LinearLayout.VERTICAL);
        resCard.setBackgroundResource(R.drawable.bg_card_cred);
        resCard.setPadding((int) (18 * density), (int) (16 * density), (int) (18 * density), (int) (16 * density));
        resCard.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        // Shared Verdict Badge
        resCard.addView(buildSharedVerdictBadge(verdict, senior));

        // Engine & Version Badge
        TextView tvEngineBadge = new TextView(activity);
        tvEngineBadge.setText("⚡ Snapdragon 8 Elite • Rules v" + assessment.getRulesVersion() + " • 100% Private On-Device");
        tvEngineBadge.setTextSize(senior ? 12 : 11);
        tvEngineBadge.setTextColor(0xFF333333);
        tvEngineBadge.setBackgroundResource(R.drawable.bg_pill_dark);
        tvEngineBadge.setPadding((int) (10 * density), (int) (4 * density), (int) (10 * density), (int) (4 * density));
        LinearLayout.LayoutParams ebp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        ebp.topMargin = (int) (8 * density);
        tvEngineBadge.setLayoutParams(ebp);
        resCard.addView(tvEngineBadge);

        // Plain-Language Summary
        TextView tvExplanation = new TextView(activity);
        tvExplanation.setText(assessment.getOverallSummary());
        tvExplanation.setTextSize(senior ? 15 : 13);
        tvExplanation.setTextColor(0xFF141414);
        tvExplanation.setLineSpacing(0, 1.25f);
        LinearLayout.LayoutParams ep = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        ep.topMargin = (int) (12 * density);
        tvExplanation.setLayoutParams(ep);
        resCard.addView(tvExplanation);

        // Observable Signals Box
        LinearLayout cuesBox = new LinearLayout(activity);
        cuesBox.setOrientation(LinearLayout.VERTICAL);
        cuesBox.setBackgroundResource(R.drawable.bg_pill_dark);
        cuesBox.setPadding((int) (14 * density), (int) (12 * density), (int) (14 * density), (int) (12 * density));
        LinearLayout.LayoutParams cp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        cp.topMargin = (int) (12 * density);
        cuesBox.setLayoutParams(cp);

        TextView cueHead = new TextView(activity);
        cueHead.setText("OBSERVABLE FORENSIC SIGNALS (" + assessment.getIndicatorCount() + " DETECTED)");
        cueHead.setTextSize(senior ? 12 : 10);
        cueHead.setTextColor(0xFF888888);
        cueHead.setTypeface(null, android.graphics.Typeface.BOLD);
        cuesBox.addView(cueHead);

        if (assessment.getIndicators().isEmpty()) {
            cuesBox.addView(createEvidenceBullet("• No structural deception, credential demands, or extortion cues detected.", senior));
            cuesBox.addView(createEvidenceBullet("• Conversational syntax conforms to standard communication conventions.", senior));
        } else {
            for (MessageIndicator ind : assessment.getIndicators()) {
                LinearLayout indItem = new LinearLayout(activity);
                indItem.setOrientation(LinearLayout.VERTICAL);
                LinearLayout.LayoutParams iip = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
                iip.topMargin = (int) (8 * density);
                indItem.setLayoutParams(iip);

                TextView tvIndTitle = new TextView(activity);
                tvIndTitle.setText("[" + ind.getType().name() + "] • " + ind.getSeverity().name() + "\n" + ind.getTitle());
                tvIndTitle.setTextSize(senior ? 13 : 11);
                tvIndTitle.setTypeface(null, android.graphics.Typeface.BOLD);
                tvIndTitle.setTextColor(ind.getSeverity() == ThreatSeverity.CRITICAL ? 0xFFB00020 :
                        (ind.getSeverity() == ThreatSeverity.HIGH ? 0xFFD84315 : 0xFF141414));
                indItem.addView(tvIndTitle);

                TextView tvIndExpl = new TextView(activity);
                tvIndExpl.setText(ind.getPlainLanguageExplanation());
                tvIndExpl.setTextSize(senior ? 12 : 10);
                tvIndExpl.setTextColor(0xFF444444);
                indItem.addView(tvIndExpl);

                if (!ind.getEvidenceText().isEmpty()) {
                    TextView tvEvidence = new TextView(activity);
                    tvEvidence.setText("Evidence: \"" + ind.getEvidenceText() + "\"");
                    tvEvidence.setTextSize(senior ? 11 : 9);
                    tvEvidence.setTextColor(0xFF666666);
                    tvEvidence.setTypeface(android.graphics.Typeface.MONOSPACE, android.graphics.Typeface.ITALIC);
                    indItem.addView(tvEvidence);
                }

                cuesBox.addView(indItem);
            }
        }
        resCard.addView(cuesBox);

        // Practical Next Steps Box
        if (!assessment.getSuggestedActions().isEmpty()) {
            LinearLayout stepsBox = new LinearLayout(activity);
            stepsBox.setOrientation(LinearLayout.VERTICAL);
            stepsBox.setBackgroundResource(R.drawable.bg_pill_dark);
            stepsBox.setPadding((int) (14 * density), (int) (12 * density), (int) (14 * density), (int) (12 * density));
            LinearLayout.LayoutParams sp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            sp.topMargin = (int) (12 * density);
            stepsBox.setLayoutParams(sp);

            TextView stepsHead = new TextView(activity);
            stepsHead.setText("PRACTICAL NEXT STEPS");
            stepsHead.setTextSize(senior ? 12 : 10);
            stepsHead.setTextColor(0xFF888888);
            stepsHead.setTypeface(null, android.graphics.Typeface.BOLD);
            stepsBox.addView(stepsHead);

            for (String action : assessment.getSuggestedActions()) {
                stepsBox.addView(createEvidenceBullet("👉 " + action, senior));
            }
            resCard.addView(stepsBox);
        }

        // Limitations & Scope Disclosure
        TextView tvLimits = new TextView(activity);
        tvLimits.setText("Analysis Scope & Limitations: " + assessment.getLimitations());
        tvLimits.setTextSize(senior ? 11 : 10);
        tvLimits.setTextColor(0xFF888888);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = (int) (12 * density);
        tvLimits.setLayoutParams(lp);
        resCard.addView(tvLimits);

        // Action Buttons Row
        LinearLayout actionsRow = new LinearLayout(activity);
        actionsRow.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams arp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        arp.topMargin = (int) (14 * density);
        actionsRow.setLayoutParams(arp);

        Button btnCheckAnother = new Button(activity);
        btnCheckAnother.setText("🧹 CHECK ANOTHER");
        btnCheckAnother.setBackgroundResource(R.drawable.bg_pill_dark);
        btnCheckAnother.setTextColor(0xFF141414);
        btnCheckAnother.setTextSize(senior ? 12 : 11);
        btnCheckAnother.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams cap = new LinearLayout.LayoutParams(0, (int) (44 * density), 1.0f);
        cap.rightMargin = (int) (6 * density);
        btnCheckAnother.setLayoutParams(cap);
        btnCheckAnother.setOnClickListener(v -> {
            if (etMessageInput != null) {
                etMessageInput.setText("");
            }
            containerMessageResult.removeAllViews();
        });
        actionsRow.addView(btnCheckAnother);

        Button btnAsk = new Button(activity);
        btnAsk.setText("💬 ASK COPILOT");
        btnAsk.setBackgroundResource(R.drawable.bg_pill_black);
        btnAsk.setTextColor(0xFFFFFFFF);
        btnAsk.setTextSize(senior ? 12 : 11);
        btnAsk.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams bkp = new LinearLayout.LayoutParams(0, (int) (44 * density), 1.0f);
        btnAsk.setLayoutParams(bkp);
        btnAsk.setOnClickListener(v -> {
            if (activity instanceof MainActivity) {
                AppState.get().setActiveFindingContext(SecurityFindingContext.fromMessageAssessment(
                        messageText, assessment, AppState.get().isSeniorMode(), AppState.get().isHindi()
                ));
                String promptText = "I received this message: '" +
                        (messageText.length() > 80 ? messageText.substring(0, 77) + "..." : messageText) +
                        "'. GuardianAi evaluated this as " + assessment.getCategory().name() + " (" + assessment.getIndicatorCount() + " indicators). What should I do?";
                ((MainActivity) activity).openContextualAssistant(promptText);
            }
        });
        actionsRow.addView(btnAsk);

        resCard.addView(actionsRow);
        containerMessageResult.addView(resCard);
    }

    // ==========================================
    // 4. INSTALLED-APP REVIEW SUB-FLOW
    // ==========================================
    private void renderInstalledAppsSubFlow(boolean senior) {
        LinearLayout card = new LinearLayout(activity);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundResource(R.drawable.bg_card_cred);
        card.setPadding((int) (20 * density), (int) (18 * density), (int) (20 * density), (int) (18 * density));
        card.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        ));

        TextView title = new TextView(activity);
        title.setText("INSTALLED APPS & PERMISSIONS AUDIT");
        title.setTextSize(senior ? 16 : 14);
        title.setTextColor(0xFF141414);
        title.setTypeface(null, android.graphics.Typeface.BOLD);
        card.addView(title);

        TextView desc = new TextView(activity);
        desc.setText(senior
                ? "Scam apps often ask for Accessibility (screen control) or SMS permission to steal your bank codes without you knowing."
                : "Audits high-privilege Android permissions that enable trojans: Accessibility Services, SMS, Device Administration, and Screen Overlays.");
        desc.setTextSize(senior ? 14 : 12);
        desc.setTextColor(0xFF666666);
        desc.setLineSpacing(0, 1.2f);
        LinearLayout.LayoutParams dp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        dp.topMargin = (int) (6 * density);
        dp.bottomMargin = (int) (14 * density);
        desc.setLayoutParams(dp);
        card.addView(desc);

        // High-Risk Permissions Explainer Card
        LinearLayout explainBox = new LinearLayout(activity);
        explainBox.setOrientation(LinearLayout.VERTICAL);
        explainBox.setBackgroundResource(R.drawable.bg_pill_dark);
        explainBox.setPadding((int) (14 * density), (int) (12 * density), (int) (14 * density), (int) (12 * density));
        LinearLayout.LayoutParams ep = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        explainBox.setLayoutParams(ep);

        TextView expHead = new TextView(activity);
        expHead.setText("WHY HIGH-PRIVILEGE PERMISSIONS NEED SCRUTINY");
        expHead.setTextSize(senior ? 12 : 10);
        expHead.setTextColor(0xFF888888);
        expHead.setTypeface(null, android.graphics.Typeface.BOLD);
        explainBox.addView(expHead);

        explainBox.addView(createEvidenceBullet("• Accessibility Service: Allows an app to read what is on your screen and tap buttons automatically.", senior));
        explainBox.addView(createEvidenceBullet("• Read / Receive SMS: Allows an app to intercept incoming 2-Factor Authentication OTPs from your bank.", senior));
        explainBox.addView(createEvidenceBullet("• Draw Over Other Apps: Allows fake login boxes to be displayed on top of real banking apps.", senior));
        explainBox.addView(createEvidenceBullet("• Device Admin: Prevents you from easily uninstalling the application.", senior));

        card.addView(explainBox);

        // Action Buttons Row
        LinearLayout actionsRow = new LinearLayout(activity);
        actionsRow.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams arp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        arp.topMargin = (int) (14 * density);
        actionsRow.setLayoutParams(arp);

        Button btnRefresh = new Button(activity);
        btnRefresh.setText("🔄 Refresh Inventory");
        btnRefresh.setBackgroundResource(R.drawable.bg_pill_black);
        btnRefresh.setTextColor(0xFFFFFFFF);
        btnRefresh.setTextSize(senior ? 14 : 12);
        btnRefresh.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams brp = new LinearLayout.LayoutParams(0, (int) (46 * density), 1f);
        brp.rightMargin = (int) (6 * density);
        btnRefresh.setLayoutParams(brp);
        btnRefresh.setOnClickListener(v -> loadAppsAsync(senior));
        actionsRow.addView(btnRefresh);

        Button btnSettings = new Button(activity);
        btnSettings.setText("⚙️ System Settings");
        btnSettings.setBackgroundResource(R.drawable.bg_pill_dark);
        btnSettings.setTextColor(0xFF141414);
        btnSettings.setTextSize(senior ? 14 : 12);
        btnSettings.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams bop = new LinearLayout.LayoutParams(0, (int) (46 * density), 1f);
        bop.leftMargin = (int) (6 * density);
        btnSettings.setLayoutParams(bop);
        btnSettings.setOnClickListener(v -> openAndroidAppSettings());
        actionsRow.addView(btnSettings);

        card.addView(actionsRow);

        // Search Bar
        EditText etSearch = new EditText(activity);
        etSearch.setHint("Search apps by name or package...");
        etSearch.setHintTextColor(0xFF888888);
        etSearch.setTextColor(0xFF141414);
        etSearch.setTextSize(senior ? 15 : 13);
        etSearch.setBackgroundResource(R.drawable.bg_input_field);
        etSearch.setPadding((int) (14 * density), (int) (12 * density), (int) (14 * density), (int) (12 * density));
        etSearch.setText(appSearchQuery);
        LinearLayout.LayoutParams sep = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        sep.topMargin = (int) (14 * density);
        etSearch.setLayoutParams(sep);
        etSearch.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                appSearchQuery = s != null ? s.toString() : "";
                renderFilteredApps(senior, etSearch);
            }

            @Override
            public void afterTextChanged(Editable s) {}
        });
        card.addView(etSearch);

        // Filter Chips Row
        card.addView(buildFilterChipsRow(senior, () -> renderFilteredApps(senior, etSearch)));

        // Stats summary label
        tvAppsStats = new TextView(activity);
        tvAppsStats.setTextSize(senior ? 13 : 11);
        tvAppsStats.setTextColor(0xFF888888);
        tvAppsStats.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams stp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        stp.topMargin = (int) (4 * density);
        stp.bottomMargin = (int) (10 * density);
        tvAppsStats.setLayoutParams(stp);
        card.addView(tvAppsStats);

        // Apps List Container
        containerAppsList = new LinearLayout(activity);
        containerAppsList.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams alp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        alp.topMargin = (int) (4 * density);
        containerAppsList.setLayoutParams(alp);
        card.addView(containerAppsList);

        containerFlow.addView(card);

        // Trigger load if not already cached
        if (cachedInstalledApps == null && !isLoadingInstalledApps) {
            loadAppsAsync(senior);
        } else {
            renderFilteredApps(senior, etSearch);
        }
    }

    private View buildFilterChipsRow(boolean senior, Runnable onFilterChanged) {
        HorizontalScrollView hsv = new HorizontalScrollView(activity);
        hsv.setHorizontalScrollBarEnabled(false);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = (int) (10 * density);
        lp.bottomMargin = (int) (4 * density);
        hsv.setLayoutParams(lp);

        filterChipsRow = new LinearLayout(activity);
        filterChipsRow.setOrientation(LinearLayout.HORIZONTAL);
        hsv.addView(filterChipsRow);

        updateFilterChipsUI(senior, onFilterChanged);
        return hsv;
    }

    private void updateFilterChipsUI(boolean senior, Runnable onFilterChanged) {
        if (filterChipsRow == null) return;
        filterChipsRow.removeAllViews();

        addFilterChip(filterChipsRow, "All Apps", AppFilter.ALL, senior, onFilterChanged);
        addFilterChip(filterChipsRow, "High Privilege Only", AppFilter.HIGH_PRIVILEGE, senior, onFilterChanged);
        addFilterChip(filterChipsRow, "User Installed Only", AppFilter.USER_ONLY, senior, onFilterChanged);
    }

    private void addFilterChip(LinearLayout parent, String title, AppFilter filter, boolean senior, Runnable onFilterChanged) {
        boolean isSelected = (currentAppFilter == filter);
        Button btn = new Button(activity);
        btn.setText(title);
        btn.setTextSize(senior ? 13 : 11);
        btn.setTypeface(null, isSelected ? android.graphics.Typeface.BOLD : android.graphics.Typeface.NORMAL);
        btn.setBackgroundResource(isSelected ? R.drawable.bg_pill_black : R.drawable.bg_pill_dark);
        btn.setTextColor(isSelected ? 0xFFFFFFFF : 0xFF666666);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, (int) (38 * density));
        lp.rightMargin = (int) (8 * density);
        btn.setLayoutParams(lp);
        btn.setPadding((int) (14 * density), 0, (int) (14 * density), 0);
        btn.setOnClickListener(v -> {
            currentAppFilter = filter;
            updateFilterChipsUI(senior, onFilterChanged);
            onFilterChanged.run();
        });
        parent.addView(btn);
    }

    private void loadAppsAsync(boolean senior) {
        isLoadingInstalledApps = true;
        if (containerAppsList != null) {
            containerAppsList.removeAllViews();

            LinearLayout loadingBox = new LinearLayout(activity);
            loadingBox.setOrientation(LinearLayout.VERTICAL);
            loadingBox.setGravity(Gravity.CENTER);
            loadingBox.setPadding((int) (20 * density), (int) (30 * density), (int) (20 * density), (int) (30 * density));

            ProgressBar pb = new ProgressBar(activity);
            LinearLayout.LayoutParams pbp = new LinearLayout.LayoutParams((int) (36 * density), (int) (36 * density));
            pbp.bottomMargin = (int) (12 * density);
            pb.setLayoutParams(pbp);
            loadingBox.addView(pb);

            TextView tvLoading = new TextView(activity);
            tvLoading.setText("Auditing installed packages and declared permissions...");
            tvLoading.setTextSize(senior ? 14 : 12);
            tvLoading.setTextColor(0xFF666666);
            tvLoading.setGravity(Gravity.CENTER);
            loadingBox.addView(tvLoading);

            containerAppsList.addView(loadingBox);
        }

        InstalledAppsRepository.getInstance().loadInstalledApps(activity, new InstalledAppsRepository.Callback<List<InstalledAppInfo>>() {
            @Override
            public void onLoaded(List<InstalledAppInfo> apps) {
                isLoadingInstalledApps = false;
                cachedInstalledApps = apps;
                renderFilteredApps(senior, null);
            }

            @Override
            public void onError(Throwable error) {
                isLoadingInstalledApps = false;
                cachedInstalledApps = new ArrayList<>();
                renderFilteredApps(senior, null);
                Toast.makeText(activity, "App audit failed: " + error.getMessage(), Toast.LENGTH_SHORT).show();
            }
        });
    }

    private void renderFilteredApps(boolean senior, EditText optionalSearchField) {
        if (containerAppsList == null) return;
        if (isLoadingInstalledApps) return;

        if (cachedInstalledApps == null) {
            loadAppsAsync(senior);
            return;
        }

        containerAppsList.removeAllViews();

        List<InstalledAppInfo> filtered = new ArrayList<>();
        int highPrivilegeCount = 0;
        String query = appSearchQuery.trim().toLowerCase(Locale.ROOT);

        for (InstalledAppInfo app : cachedInstalledApps) {
            if (app.isHighPrivilege()) {
                highPrivilegeCount++;
            }

            if (currentAppFilter == AppFilter.HIGH_PRIVILEGE && !app.isHighPrivilege()) {
                continue;
            }
            if (currentAppFilter == AppFilter.USER_ONLY && app.isSystemApp()) {
                continue;
            }

            if (!query.isEmpty()) {
                boolean matchesLabel = app.getAppLabel().toLowerCase(Locale.ROOT).contains(query);
                boolean matchesPackage = app.getPackageName().toLowerCase(Locale.ROOT).contains(query);
                if (!matchesLabel && !matchesPackage) {
                    continue;
                }
            }

            filtered.add(app);
        }

        // Update stats
        if (tvAppsStats != null) {
            tvAppsStats.setText("Showing " + filtered.size() + " of " + cachedInstalledApps.size() + " apps (" + highPrivilegeCount + " High Privilege)");
        }

        // Empty state
        if (filtered.isEmpty()) {
            LinearLayout emptyCard = new LinearLayout(activity);
            emptyCard.setOrientation(LinearLayout.VERTICAL);
            emptyCard.setGravity(Gravity.CENTER);
            emptyCard.setBackgroundResource(R.drawable.bg_card_interactive);
            emptyCard.setPadding((int) (20 * density), (int) (24 * density), (int) (20 * density), (int) (24 * density));

            TextView tvEmptyTitle = new TextView(activity);
            tvEmptyTitle.setText("🔍 No Matching Applications Found");
            tvEmptyTitle.setTextSize(senior ? 16 : 14);
            tvEmptyTitle.setTextColor(0xFF141414);
            tvEmptyTitle.setTypeface(null, android.graphics.Typeface.BOLD);
            emptyCard.addView(tvEmptyTitle);

            TextView tvEmptyDesc = new TextView(activity);
            String filterDesc = currentAppFilter == AppFilter.HIGH_PRIVILEGE ? "High Privilege Only"
                    : currentAppFilter == AppFilter.USER_ONLY ? "User Installed Only" : "All Apps";
            tvEmptyDesc.setText("No apps match query \"" + (query.isEmpty() ? filterDesc : query) + "\".");
            tvEmptyDesc.setTextSize(senior ? 14 : 12);
            tvEmptyDesc.setTextColor(0xFF666666);
            LinearLayout.LayoutParams edp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            edp.topMargin = (int) (6 * density);
            edp.bottomMargin = (int) (14 * density);
            tvEmptyDesc.setLayoutParams(edp);
            emptyCard.addView(tvEmptyDesc);

            Button btnReset = new Button(activity);
            btnReset.setText("Reset Search & Filters");
            btnReset.setTextSize(senior ? 13 : 11);
            btnReset.setTypeface(null, android.graphics.Typeface.BOLD);
            btnReset.setBackgroundResource(R.drawable.bg_pill_black);
            btnReset.setTextColor(0xFFFFFFFF);
            btnReset.setPadding((int) (16 * density), 0, (int) (16 * density), 0);
            btnReset.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, (int) (40 * density)));
            btnReset.setOnClickListener(v -> {
                appSearchQuery = "";
                currentAppFilter = AppFilter.ALL;
                if (optionalSearchField != null) {
                    optionalSearchField.setText("");
                }
                updateFilterChipsUI(senior, () -> renderFilteredApps(senior, optionalSearchField));
                renderFilteredApps(senior, optionalSearchField);
            });
            emptyCard.addView(btnReset);

            containerAppsList.addView(emptyCard);
            return;
        }

        // Render app cards
        for (InstalledAppInfo app : filtered) {
            containerAppsList.addView(createInstalledAppCard(app, senior));
        }
    }

    private View createInstalledAppCard(InstalledAppInfo app, boolean senior) {
        LinearLayout card = new LinearLayout(activity);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundResource(R.drawable.bg_card_interactive);
        card.setPadding((int) (14 * density), (int) (12 * density), (int) (14 * density), (int) (12 * density));
        LinearLayout.LayoutParams rp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        rp.bottomMargin = (int) (10 * density);
        card.setLayoutParams(rp);

        // Header Row: Icon + Label + Package
        LinearLayout headerRow = new LinearLayout(activity);
        headerRow.setOrientation(LinearLayout.HORIZONTAL);
        headerRow.setGravity(Gravity.CENTER_VERTICAL);

        ImageView ivIcon = new ImageView(activity);
        if (app.getIcon() != null) {
            ivIcon.setImageDrawable(app.getIcon());
        }
        LinearLayout.LayoutParams icp = new LinearLayout.LayoutParams((int) (44 * density), (int) (44 * density));
        icp.rightMargin = (int) (12 * density);
        ivIcon.setLayoutParams(icp);
        headerRow.addView(ivIcon);

        LinearLayout textCol = new LinearLayout(activity);
        textCol.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams tcp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        textCol.setLayoutParams(tcp);

        TextView tvName = new TextView(activity);
        tvName.setText(app.getAppLabel());
        tvName.setTextSize(senior ? 16 : 14);
        tvName.setTextColor(0xFF141414);
        tvName.setTypeface(null, android.graphics.Typeface.BOLD);
        textCol.addView(tvName);

        TextView tvPkg = new TextView(activity);
        tvPkg.setText(app.getPackageName() + " • v" + (app.getVersionName().isEmpty() ? "1.0" : app.getVersionName()));
        tvPkg.setTextSize(senior ? 13 : 11);
        tvPkg.setTextColor(0xFF666666);
        textCol.addView(tvPkg);

        headerRow.addView(textCol);
        card.addView(headerRow);

        // Badges Row
        LinearLayout badgesRow = new LinearLayout(activity);
        badgesRow.setOrientation(LinearLayout.HORIZONTAL);
        badgesRow.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams brp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        brp.topMargin = (int) (8 * density);
        badgesRow.setLayoutParams(brp);

        if (app.hasAccessibilityService()) {
            badgesRow.addView(createBadge("Accessibility", R.drawable.bg_pill_crimson, 0xFFA63232, senior));
        }
        if (app.hasSmsPermissions()) {
            badgesRow.addView(createBadge("SMS", R.drawable.bg_pill_amber, 0xFF855A12, senior));
        }
        if (app.hasOverlayPermission()) {
            badgesRow.addView(createBadge("Overlay", R.drawable.bg_pill_amber, 0xFF855A12, senior));
        }
        if (app.isSystemApp()) {
            badgesRow.addView(createBadge("System App", R.drawable.bg_pill_dark, 0xFF666666, senior));
        } else if (!app.isHighPrivilege()) {
            badgesRow.addView(createBadge("Standard", R.drawable.bg_pill_emerald, 0xFF386B57, senior));
        }

        boolean isTeraBox = "com.dubox.drive".equals(app.getPackageName());
        if (isTeraBox) {
            dev.guardianai.personal.data.DataExfiltrationSentinel.SentinelState sState =
                    dev.guardianai.personal.data.DataExfiltrationSentinel.getInstance(activity).getState();
            if (sState == dev.guardianai.personal.data.DataExfiltrationSentinel.SentinelState.AWAITING_CONFIRMATION) {
                card.setBackgroundResource(R.drawable.bg_card_glow_crimson);
                badgesRow.addView(createBadge("🚨 Silent Photo Upload Active", R.drawable.bg_pill_crimson, 0xFFA63232, senior));
            } else if (sState == dev.guardianai.personal.data.DataExfiltrationSentinel.SentinelState.BLOCKED) {
                card.setBackgroundResource(R.drawable.bg_card_glow_emerald);
                badgesRow.addView(createBadge("🛡️ Upload Blocked & Firewalled", R.drawable.bg_pill_emerald, 0xFF2E7D32, senior));
            } else {
                badgesRow.addView(createBadge("✅ User Permitted Sync", R.drawable.bg_pill_dark, 0xFF666666, senior));
            }
        }

        card.addView(badgesRow);

        // Buttons Row: Details & Permissions + Android Settings
        LinearLayout btnRow = new LinearLayout(activity);
        btnRow.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams bp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        bp.topMargin = (int) (10 * density);
        btnRow.setLayoutParams(bp);

        Button btnDetails = new Button(activity);
        btnDetails.setText(isTeraBox ? "⚠️ Verify Permission" : "📋 Details & Permissions");
        btnDetails.setTextSize(senior ? 13 : 11);
        btnDetails.setTypeface(null, android.graphics.Typeface.BOLD);
        btnDetails.setBackgroundResource(isTeraBox ? R.drawable.bg_pill_crimson : R.drawable.bg_pill_black);
        btnDetails.setTextColor(isTeraBox ? 0xFFD32F2F : 0xFFFFFFFF);
        LinearLayout.LayoutParams dp1 = new LinearLayout.LayoutParams(0, (int) (40 * density), 1f);
        dp1.rightMargin = (int) (4 * density);
        btnDetails.setLayoutParams(dp1);
        btnDetails.setOnClickListener(v -> {
            if (isTeraBox) {
                dev.guardianai.personal.ui.components.DataExfiltrationDialog.show(activity, () -> renderFilteredApps(senior, null));
            } else {
                showAppDetailModal(app, senior);
            }
        });
        btnRow.addView(btnDetails);

        Button btnSettings = new Button(activity);
        btnSettings.setText("⚙️ App Settings");
        btnSettings.setTextSize(senior ? 13 : 11);
        btnSettings.setTypeface(null, android.graphics.Typeface.BOLD);
        btnSettings.setBackgroundResource(R.drawable.bg_pill_dark);
        btnSettings.setTextColor(0xFF141414);
        LinearLayout.LayoutParams dp2 = new LinearLayout.LayoutParams(0, (int) (40 * density), 1f);
        dp2.leftMargin = (int) (4 * density);
        btnSettings.setLayoutParams(dp2);
        btnSettings.setOnClickListener(v -> openPackageSettings(app.getPackageName()));
        btnRow.addView(btnSettings);

        if (isTeraBox) {
            Button btnLaunchTb = new Button(activity);
            btnLaunchTb.setText("🚀 Launch");
            btnLaunchTb.setTextSize(senior ? 13 : 11);
            btnLaunchTb.setTypeface(null, android.graphics.Typeface.BOLD);
            btnLaunchTb.setBackgroundResource(R.drawable.bg_pill_dark);
            btnLaunchTb.setTextColor(0xFF141414);
            LinearLayout.LayoutParams dp3 = new LinearLayout.LayoutParams(0, (int) (40 * density), 0.8f);
            dp3.leftMargin = (int) (4 * density);
            btnLaunchTb.setLayoutParams(dp3);
            btnLaunchTb.setOnClickListener(v -> dev.guardianai.personal.data.TeraBoxLaunchWatcher.launchTeraBox(activity));
            btnRow.addView(btnLaunchTb);
        }

        card.addView(btnRow);

        // Tap entire card to open details / sentinel dialog
        card.setOnClickListener(v -> {
            if (isTeraBox) {
                dev.guardianai.personal.ui.components.DataExfiltrationDialog.show(activity, () -> renderFilteredApps(senior, null));
            } else {
                showAppDetailModal(app, senior);
            }
        });

        return card;
    }

    private TextView createBadge(String text, int bgRes, int textColor, boolean senior) {
        TextView tv = new TextView(activity);
        tv.setText(text);
        tv.setTextSize(senior ? 11 : 10);
        tv.setTextColor(textColor);
        tv.setBackgroundResource(bgRes);
        tv.setPadding((int) (8 * density), (int) (3 * density), (int) (8 * density), (int) (3 * density));
        tv.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.rightMargin = (int) (6 * density);
        tv.setLayoutParams(lp);
        return tv;
    }

    private void showAppDetailModal(InstalledAppInfo app, boolean senior) {
        Dialog dialog = new Dialog(activity);
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);

        ScrollView scrollView = new ScrollView(activity);
        scrollView.setLayoutParams(new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        ));
        scrollView.setBackgroundResource(R.drawable.bg_bottom_sheet);

        LinearLayout layout = new LinearLayout(activity);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding((int) (24 * density), (int) (20 * density), (int) (24 * density), (int) (32 * density));

        // Drag pill bar
        TextView dragPill = new TextView(activity);
        LinearLayout.LayoutParams pillParams = new LinearLayout.LayoutParams((int) (48 * density), (int) (4 * density));
        pillParams.gravity = Gravity.CENTER_HORIZONTAL;
        pillParams.bottomMargin = (int) (16 * density);
        dragPill.setLayoutParams(pillParams);
        dragPill.setBackgroundColor(0xFFE5E5E2);
        layout.addView(dragPill);

        // Header: App icon + Label + Package
        LinearLayout appHeader = new LinearLayout(activity);
        appHeader.setOrientation(LinearLayout.HORIZONTAL);
        appHeader.setGravity(Gravity.CENTER_VERTICAL);

        ImageView iv = new ImageView(activity);
        if (app.getIcon() != null) {
            iv.setImageDrawable(app.getIcon());
        }
        LinearLayout.LayoutParams ivp = new LinearLayout.LayoutParams((int) (52 * density), (int) (52 * density));
        ivp.rightMargin = (int) (14 * density);
        iv.setLayoutParams(ivp);
        appHeader.addView(iv);

        LinearLayout col = new LinearLayout(activity);
        col.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams clp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        col.setLayoutParams(clp);

        TextView tvTitle = new TextView(activity);
        tvTitle.setText(app.getAppLabel());
        tvTitle.setTextSize(senior ? 20 : 18);
        tvTitle.setTextColor(0xFF141414);
        tvTitle.setTypeface(null, android.graphics.Typeface.BOLD);
        col.addView(tvTitle);

        TextView tvPackage = new TextView(activity);
        tvPackage.setText(app.getPackageName());
        tvPackage.setTextSize(senior ? 13 : 12);
        tvPackage.setTextColor(0xFF666666);
        col.addView(tvPackage);

        TextView tvMeta = new TextView(activity);
        tvMeta.setText("Version: " + (app.getVersionName().isEmpty() ? "1.0" : app.getVersionName()) +
                " • Target SDK: " + app.getTargetSdk() +
                (app.isSystemApp() ? " • System App" : " • User Installed"));
        tvMeta.setTextSize(senior ? 12 : 11);
        tvMeta.setTextColor(0xFF888888);
        col.addView(tvMeta);

        appHeader.addView(col);
        layout.addView(appHeader);

        // Metrics Summary Row
        LinearLayout metricsRow = new LinearLayout(activity);
        metricsRow.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams mrp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        mrp.topMargin = (int) (16 * density);
        metricsRow.setLayoutParams(mrp);

        metricsRow.addView(createMetricBox("TOTAL PERMISSIONS", String.valueOf(app.getRequestedPermissions().size()), 0xFF141414, senior));
        metricsRow.addView(createMetricBox("GRANTED", String.valueOf(app.getGrantedPermissions().size()), 0xFF386B57, senior));
        metricsRow.addView(createMetricBox("HIGH PRIVILEGE", String.valueOf(app.getSensitivePermissions().size()),
                app.getSensitivePermissions().isEmpty() ? 0xFF386B57 : 0xFFA63232, senior));

        layout.addView(metricsRow);

        // Sensitive Permissions Section
        TextView spHead = new TextView(activity);
        spHead.setText("HIGH-PRIVILEGE & SENSITIVE PERMISSIONS");
        spHead.setTextSize(senior ? 13 : 11);
        spHead.setTextColor(0xFF141414);
        spHead.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams sphp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        sphp.topMargin = (int) (20 * density);
        sphp.bottomMargin = (int) (8 * density);
        spHead.setLayoutParams(sphp);
        layout.addView(spHead);

        List<InstalledAppInfo.PermissionDetail> sensitiveDetails = app.getSensitivePermissionDetails();
        if (sensitiveDetails.isEmpty()) {
            TextView cleanCard = new TextView(activity);
            cleanCard.setText("✅ This application requests no known high-privilege accessibility, SMS, or screen overlay permissions.");
            cleanCard.setTextSize(senior ? 14 : 12);
            cleanCard.setTextColor(0xFF386B57);
            cleanCard.setBackgroundResource(R.drawable.bg_pill_emerald);
            cleanCard.setPadding((int) (14 * density), (int) (10 * density), (int) (14 * density), (int) (10 * density));
            layout.addView(cleanCard);
        } else {
            for (InstalledAppInfo.PermissionDetail detail : sensitiveDetails) {
                layout.addView(createPermissionDetailCard(detail, senior));
            }
        }

        // All Declared Permissions Section
        List<InstalledAppInfo.PermissionDetail> allDetails = app.getAllPermissionDetails();
        List<InstalledAppInfo.PermissionDetail> otherDetails = new ArrayList<>();
        for (InstalledAppInfo.PermissionDetail d : allDetails) {
            if (!d.isSensitive()) {
                otherDetails.add(d);
            }
        }

        if (!otherDetails.isEmpty()) {
            TextView otherHead = new TextView(activity);
            otherHead.setText("OTHER DECLARED PERMISSIONS (" + otherDetails.size() + ")");
            otherHead.setTextSize(senior ? 13 : 11);
            otherHead.setTextColor(0xFF888888);
            otherHead.setTypeface(null, android.graphics.Typeface.BOLD);
            LinearLayout.LayoutParams ohp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            ohp.topMargin = (int) (18 * density);
            ohp.bottomMargin = (int) (6 * density);
            otherHead.setLayoutParams(ohp);
            layout.addView(otherHead);

            LinearLayout otherBox = new LinearLayout(activity);
            otherBox.setOrientation(LinearLayout.VERTICAL);
            otherBox.setBackgroundResource(R.drawable.bg_pill_dark);
            otherBox.setPadding((int) (14 * density), (int) (10 * density), (int) (14 * density), (int) (10 * density));

            for (InstalledAppInfo.PermissionDetail od : otherDetails) {
                LinearLayout row = new LinearLayout(activity);
                row.setOrientation(LinearLayout.HORIZONTAL);
                row.setGravity(Gravity.CENTER_VERTICAL);
                LinearLayout.LayoutParams orp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
                orp.bottomMargin = (int) (4 * density);
                row.setLayoutParams(orp);

                TextView tvPName = new TextView(activity);
                tvPName.setText("• " + od.getLabel());
                tvPName.setTextSize(senior ? 13 : 11);
                tvPName.setTextColor(0xFF333333);
                LinearLayout.LayoutParams pnp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
                tvPName.setLayoutParams(pnp);
                row.addView(tvPName);

                TextView tvPStatus = new TextView(activity);
                tvPStatus.setText(od.isGranted() ? "Granted" : "Not Granted");
                tvPStatus.setTextSize(senior ? 11 : 10);
                tvPStatus.setTextColor(od.isGranted() ? 0xFF386B57 : 0xFF888888);
                row.addView(tvPStatus);

                otherBox.addView(row);
            }
            layout.addView(otherBox);
        }

        // Action Buttons Row
        LinearLayout actionsCol = new LinearLayout(activity);
        actionsCol.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams ap = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        ap.topMargin = (int) (22 * density);
        actionsCol.setLayoutParams(ap);

        Button btnOpenSettings = new Button(activity);
        btnOpenSettings.setText("⚙️ Open App Settings in Android");
        btnOpenSettings.setTextSize(senior ? 15 : 13);
        btnOpenSettings.setTextColor(0xFFFFFFFF);
        btnOpenSettings.setBackgroundResource(R.drawable.bg_pill_black);
        btnOpenSettings.setTypeface(null, android.graphics.Typeface.BOLD);
        btnOpenSettings.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, (int) (48 * density)));
        btnOpenSettings.setOnClickListener(v -> {
            openPackageSettings(app.getPackageName());
            dialog.dismiss();
        });
        actionsCol.addView(btnOpenSettings);

        if (activity instanceof MainActivity) {
            Button btnAsk = new Button(activity);
            btnAsk.setText("💬 Ask Copilot About " + app.getAppLabel());
            btnAsk.setTextSize(senior ? 14 : 12);
            btnAsk.setTextColor(0xFF141414);
            btnAsk.setBackgroundResource(R.drawable.bg_pill_dark);
            btnAsk.setTypeface(null, android.graphics.Typeface.BOLD);
            LinearLayout.LayoutParams abp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, (int) (44 * density));
            abp.topMargin = (int) (8 * density);
            btnAsk.setLayoutParams(abp);
            btnAsk.setOnClickListener(v -> {
                dialog.dismiss();
                ((MainActivity) activity).openContextualAssistant("Please explain the permissions and risk profile of " + app.getAppLabel() + " (" + app.getPackageName() + ").");
            });
            actionsCol.addView(btnAsk);
        }

        Button btnClose = new Button(activity);
        btnClose.setText("Close");
        btnClose.setTextSize(senior ? 14 : 12);
        btnClose.setTextColor(0xFF666666);
        btnClose.setBackgroundColor(Color.TRANSPARENT);
        LinearLayout.LayoutParams cbParams = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, (int) (42 * density));
        cbParams.topMargin = (int) (6 * density);
        btnClose.setLayoutParams(cbParams);
        btnClose.setOnClickListener(v -> dialog.dismiss());
        actionsCol.addView(btnClose);

        layout.addView(actionsCol);

        scrollView.addView(layout);
        dialog.setContentView(scrollView);

        Window window = dialog.getWindow();
        if (window != null) {
            window.setLayout(WindowManager.LayoutParams.MATCH_PARENT, WindowManager.LayoutParams.WRAP_CONTENT);
            window.setGravity(Gravity.BOTTOM);
            window.setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
        }

        dialog.show();
    }

    private View createMetricBox(String label, String value, int valueColor, boolean senior) {
        LinearLayout box = new LinearLayout(activity);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER);
        box.setBackgroundResource(R.drawable.bg_pill_dark);
        box.setPadding((int) (10 * density), (int) (10 * density), (int) (10 * density), (int) (10 * density));
        LinearLayout.LayoutParams bp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        bp.rightMargin = (int) (6 * density);
        box.setLayoutParams(bp);

        TextView tvVal = new TextView(activity);
        tvVal.setText(value);
        tvVal.setTextSize(senior ? 18 : 16);
        tvVal.setTextColor(valueColor);
        tvVal.setTypeface(null, android.graphics.Typeface.BOLD);
        box.addView(tvVal);

        TextView tvLbl = new TextView(activity);
        tvLbl.setText(label);
        tvLbl.setTextSize(senior ? 10 : 9);
        tvLbl.setTextColor(0xFF888888);
        box.addView(tvLbl);

        return box;
    }

    private View createPermissionDetailCard(InstalledAppInfo.PermissionDetail detail, boolean senior) {
        LinearLayout card = new LinearLayout(activity);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundResource(R.drawable.bg_card_interactive);
        card.setPadding((int) (14 * density), (int) (10 * density), (int) (14 * density), (int) (10 * density));
        LinearLayout.LayoutParams cp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        cp.bottomMargin = (int) (8 * density);
        card.setLayoutParams(cp);

        // Header Row: Label + Granted Badge
        LinearLayout hr = new LinearLayout(activity);
        hr.setOrientation(LinearLayout.HORIZONTAL);
        hr.setGravity(Gravity.CENTER_VERTICAL);

        TextView tvLabel = new TextView(activity);
        tvLabel.setText(detail.getLabel());
        tvLabel.setTextSize(senior ? 14 : 12);
        tvLabel.setTextColor(0xFF141414);
        tvLabel.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        tvLabel.setLayoutParams(lp);
        hr.addView(tvLabel);

        TextView tvBadge = new TextView(activity);
        tvBadge.setText(detail.isGranted() ? "GRANTED" : "NOT GRANTED");
        tvBadge.setTextSize(senior ? 11 : 9);
        tvBadge.setTypeface(null, android.graphics.Typeface.BOLD);
        tvBadge.setPadding((int) (8 * density), (int) (3 * density), (int) (8 * density), (int) (3 * density));
        tvBadge.setBackgroundResource(detail.isGranted() ? R.drawable.bg_pill_amber : R.drawable.bg_pill_dark);
        tvBadge.setTextColor(detail.isGranted() ? 0xFF855A12 : 0xFF666666);
        hr.addView(tvBadge);

        card.addView(hr);

        // Monospace Permission Name
        TextView tvPerm = new TextView(activity);
        tvPerm.setText(detail.getPermission());
        tvPerm.setTextSize(senior ? 11 : 10);
        tvPerm.setTextColor(0xFF888888);
        LinearLayout.LayoutParams pp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        pp.topMargin = (int) (2 * density);
        tvPerm.setLayoutParams(pp);
        card.addView(tvPerm);

        // Factual Explanation
        TextView tvExp = new TextView(activity);
        tvExp.setText(detail.getExplanation());
        tvExp.setTextSize(senior ? 13 : 11);
        tvExp.setTextColor(0xFF444444);
        tvExp.setLineSpacing(0, 1.2f);
        LinearLayout.LayoutParams ep = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        ep.topMargin = (int) (6 * density);
        tvExp.setLayoutParams(ep);
        card.addView(tvExp);

        return card;
    }

    private void openPackageSettings(String packageName) {
        try {
            Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
            intent.setData(Uri.parse("package:" + packageName));
            activity.startActivity(intent);
        } catch (Exception e) {
            Toast.makeText(activity, "Could not open settings: " + e.getMessage(), Toast.LENGTH_SHORT).show();
        }
    }

    private void openAndroidAppSettings() {
        try {
            Intent intent = new Intent(Settings.ACTION_APPLICATION_SETTINGS);
            activity.startActivity(intent);
        } catch (Exception e) {
            try {
                Intent intent = new Intent(Settings.ACTION_SETTINGS);
                activity.startActivity(intent);
            } catch (Exception ignored) {}
        }
    }

    // ==========================================
    // SHARED VERDICT HELPER
    // ==========================================
    private View buildSharedVerdictBadge(ScanVerdict verdict, boolean senior) {
        LinearLayout badgeRow = new LinearLayout(activity);
        badgeRow.setOrientation(LinearLayout.HORIZONTAL);
        badgeRow.setGravity(Gravity.CENTER_VERTICAL);

        TextView tvBadge = new TextView(activity);
        tvBadge.setTextSize(senior ? 14 : 12);
        tvBadge.setTypeface(null, android.graphics.Typeface.BOLD);
        tvBadge.setPadding((int) (12 * density), (int) (6 * density), (int) (12 * density), (int) (6 * density));

        switch (verdict) {
            case KNOWN_MALICIOUS:
                tvBadge.setText("🚨 KNOWN MALICIOUS");
                tvBadge.setTextColor(0xFFA63232);
                tvBadge.setBackgroundResource(R.drawable.bg_pill_crimson);
                break;
            case HIGH_RISK:
                tvBadge.setText("⚠️ HIGH RISK SIGNS FOUND");
                tvBadge.setTextColor(0xFF855A12);
                tvBadge.setBackgroundResource(R.drawable.bg_pill_amber);
                break;
            case CAUTION:
                tvBadge.setText("🔍 USE CAUTION");
                tvBadge.setTextColor(0xFF855A12);
                tvBadge.setBackgroundResource(R.drawable.bg_pill_amber);
                break;
            case NO_KNOWN_THREAT_DETECTED:
                tvBadge.setText("✅ NO KNOWN THREAT DETECTED");
                tvBadge.setTextColor(0xFF386B57);
                tvBadge.setBackgroundResource(R.drawable.bg_pill_emerald);
                break;
            case INCONCLUSIVE:
                tvBadge.setText("⚠️ INCONCLUSIVE SCAN");
                tvBadge.setTextColor(0xFF855A12);
                tvBadge.setBackgroundResource(R.drawable.bg_pill_amber);
                break;
            case UNABLE_TO_DETERMINE:
            default:
                tvBadge.setText("❓ PARSE FAILED / UNABLE TO SCAN");
                tvBadge.setTextColor(0xFF666666);
                tvBadge.setBackgroundResource(R.drawable.bg_pill_dark);
                break;
        }

        badgeRow.addView(tvBadge);

        View sp = new View(activity);
        sp.setLayoutParams(new LinearLayout.LayoutParams(0, 1, 1f));
        badgeRow.addView(sp);

        TextView tvStatic = new TextView(activity);
        tvStatic.setText("Snapdragon 8 Elite Static Proof");
        tvStatic.setTextSize(10);
        tvStatic.setTextColor(0xFF888888);
        badgeRow.addView(tvStatic);

        return badgeRow;
    }

    private TextView createEvidenceBullet(String text, boolean senior) {
        TextView tv = new TextView(activity);
        tv.setText(text);
        tv.setTextSize(senior ? 13 : 11);
        tv.setTextColor(0xFF333333);
        tv.setLineSpacing(0, 1.2f);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = (int) (4 * density);
        tv.setLayoutParams(lp);
        return tv;
    }

    private View createSampleChip(String text, Runnable onClick) {
        TextView tv = new TextView(activity);
        tv.setText(text);
        tv.setTextSize(11);
        tv.setTextColor(0xFF141414);
        tv.setBackgroundResource(R.drawable.bg_pill_dark);
        tv.setPadding((int) (12 * density), (int) (6 * density), (int) (12 * density), (int) (6 * density));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.rightMargin = (int) (8 * density);
        tv.setLayoutParams(lp);
        tv.setOnClickListener(v -> onClick.run());
        return tv;
    }
}
