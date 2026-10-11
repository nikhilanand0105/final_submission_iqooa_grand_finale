package dev.guardianai.personal.ui;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.provider.OpenableColumns;
import android.view.Display;
import android.view.View;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import dev.guardianai.model.ApkAnalysisReport;
import dev.guardianai.model.ScanVerdict;
import dev.guardianai.model.ThreatIndicator;
import dev.guardianai.personal.R;
import dev.guardianai.personal.data.DataExfiltrationSentinel;
import dev.guardianai.personal.data.db.FindingRecord;
import dev.guardianai.personal.data.db.ScanRecord;
import dev.guardianai.personal.data.prefs.PreferencesManager;
import dev.guardianai.personal.ui.components.DataExfiltrationDialog;
import dev.guardianai.personal.ui.components.DetailSheetDialog;
import dev.guardianai.personal.ui.components.OnboardingOverlay;
import dev.guardianai.personal.ui.model.ActivityEvent;
import dev.guardianai.personal.ui.model.NavigationTab;
import dev.guardianai.personal.ui.screens.ActivityScreenController;
import dev.guardianai.personal.ui.screens.AssistantScreenController;
import dev.guardianai.personal.ui.screens.FamilyScreenController;
import dev.guardianai.personal.ui.screens.HomeScreenController;
import dev.guardianai.personal.ui.screens.ScanScreenController;
import dev.guardianai.personal.ui.screens.SettingsScreenController;
import dev.guardianai.personal.ui.state.AppState;

import java.io.InputStream;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

public class MainActivity extends Activity {

    private FrameLayout screenContainer;
    private FrameLayout modalContainer;
    private FrameLayout onboardingContainer;

    private LinearLayout navItemHome;
    private LinearLayout navItemScan;
    private LinearLayout navItemActivity;
    private LinearLayout navItemFamily;
    private LinearLayout navItemSettings;

    private ImageView ivNavHome;
    private ImageView ivNavScan;
    private ImageView ivNavActivity;
    private ImageView ivNavFamily;
    private ImageView ivNavSettings;

    private TextView tvNavHome;
    private TextView tvNavScan;
    private TextView tvNavActivity;
    private TextView tvNavFamily;
    private TextView tvNavSettings;

    private HomeScreenController homeController;
    private ScanScreenController scanController;
    private ActivityScreenController activityController;
    private FamilyScreenController familyController;
    private SettingsScreenController settingsController;
    private AssistantScreenController assistantController;

    private final Deque<NavigationTab> navigationBackStack = new ArrayDeque<>();
    private Vibrator vibrator;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Hardware Optimization: 144Hz LTPO AMOLED sync for iQOO 15 (Snapdragon 8 Elite)
        optimizeDisplayForIqoo15();

        // Enforce Light Status Bar and Light Navigation Bar (Dark Icons)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            View decor = getWindow().getDecorView();
            int flags = decor.getSystemUiVisibility();
            flags |= View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                flags |= View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR;
            }
            decor.setSystemUiVisibility(flags);
            getWindow().setStatusBarColor(0xFFF7F7F5);
            getWindow().setNavigationBarColor(0xFFFFFFFF);
        }

        setContentView(R.layout.activity_main);

        vibrator = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);

        // Initialize persistent preferences and repository in AppState
        AppState.get().initContext(this);

        initViews();
        setupScreenControllers();
        setupNavigation();

        // Check if onboarding needs to be displayed
        checkOnboarding();

        // Listen for centralized state changes
        AppState.get().addListener(this::onAppStateChanged);
        dev.guardianai.personal.network.NetworkProtectionManager.getInstance(this)
                .addListener(this::onNetworkProtectionStatusChanged);

        // Data Exfiltration Sentinel & TeraBox Foreground Watcher
        DataExfiltrationSentinel sentinel = DataExfiltrationSentinel.getInstance(this);
        if (sentinel.getState() == DataExfiltrationSentinel.SentinelState.AWAITING_CONFIRMATION) {
            sentinel.postSystemNotification(this);
        }
        sentinel.addListener(state -> runOnUiThread(() -> {
            if (homeController != null) {
                homeController.render();
            }
        }));
        dev.guardianai.personal.data.TeraBoxLaunchWatcher.getInstance(this).startMonitoring();

        // Initial tab
        switchTab(NavigationTab.HOME, false);

        // Check incoming intent (APK shared from Chrome, WhatsApp, Files, or Sentinel notification)
        handleIncomingIntent(getIntent());
    }

    @Override
    protected void onResume() {
        super.onResume();
        dev.guardianai.personal.data.TeraBoxLaunchWatcher.getInstance(this).startMonitoring();
        if (homeController != null) {
            homeController.render();
        }
    }

    private void checkOnboarding() {
        PreferencesManager prefs = AppState.get().getPreferencesManager();
        if (prefs != null && !prefs.isOnboardingCompleted()) {
            onboardingContainer.removeAllViews();
            OnboardingOverlay overlay = new OnboardingOverlay(this, () -> {
                prefs.setOnboardingCompleted(true);
                onboardingContainer.setVisibility(View.GONE);
                onboardingContainer.removeAllViews();
            });
            onboardingContainer.addView(overlay.getView());
            onboardingContainer.setVisibility(View.VISIBLE);
        } else {
            onboardingContainer.setVisibility(View.GONE);
        }
    }

    private void optimizeDisplayForIqoo15() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            try {
                WindowManager.LayoutParams params = getWindow().getAttributes();
                Display display = getDisplay();
                if (display != null) {
                    Display.Mode[] modes = display.getSupportedModes();
                    for (Display.Mode mode : modes) {
                        if (Math.round(mode.getRefreshRate()) == 144) {
                            params.preferredDisplayModeId = mode.getModeId();
                            break;
                        }
                    }
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    params.layoutInDisplayCutoutMode = WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_SHORT_EDGES;
                }
                getWindow().setAttributes(params);
            } catch (Exception ignored) {}
        }
    }

    private void initViews() {
        screenContainer = findViewById(R.id.screen_container);
        modalContainer = findViewById(R.id.modal_container);
        onboardingContainer = findViewById(R.id.onboarding_container);

        navItemHome = findViewById(R.id.nav_item_home);
        navItemScan = findViewById(R.id.nav_item_scan);
        navItemActivity = findViewById(R.id.nav_item_activity);
        navItemFamily = findViewById(R.id.nav_item_family);
        navItemSettings = findViewById(R.id.nav_item_settings);

        ivNavHome = findViewById(R.id.iv_nav_home);
        ivNavScan = findViewById(R.id.iv_nav_scan);
        ivNavActivity = findViewById(R.id.iv_nav_activity);
        ivNavFamily = findViewById(R.id.iv_nav_family);
        ivNavSettings = findViewById(R.id.iv_nav_settings);

        tvNavHome = findViewById(R.id.tv_nav_home);
        tvNavScan = findViewById(R.id.tv_nav_scan);
        tvNavActivity = findViewById(R.id.tv_nav_activity);
        tvNavFamily = findViewById(R.id.tv_nav_family);
        tvNavSettings = findViewById(R.id.tv_nav_settings);
    }

    private void setupScreenControllers() {
        homeController = new HomeScreenController(this);
        scanController = new ScanScreenController(this);
        activityController = new ActivityScreenController(this);
        familyController = new FamilyScreenController(this);
        settingsController = new SettingsScreenController(this);
        assistantController = new AssistantScreenController(this);

        // Add 5 main screens to screenContainer
        screenContainer.addView(homeController.getView());
        screenContainer.addView(scanController.getView());
        screenContainer.addView(activityController.getView());
        screenContainer.addView(familyController.getView());
        screenContainer.addView(settingsController.getView());

        // Contextual assistant container setup
        assistantController.setCloseCallback(() -> {
            if (modalContainer != null) {
                modalContainer.setVisibility(View.GONE);
                modalContainer.removeAllViews();
            }
        });
    }

    private void setupNavigation() {
        navItemHome.setOnClickListener(v -> switchTab(NavigationTab.HOME, true));
        navItemScan.setOnClickListener(v -> switchTab(NavigationTab.SCAN, true));
        navItemActivity.setOnClickListener(v -> switchTab(NavigationTab.ACTIVITY, true));
        navItemFamily.setOnClickListener(v -> switchTab(NavigationTab.FAMILY, true));
        navItemSettings.setOnClickListener(v -> switchTab(NavigationTab.SETTINGS, true));
    }

    public void switchTab(NavigationTab targetTab, boolean addToStack) {
        // Dismiss modal if open
        if (modalContainer != null && modalContainer.getVisibility() == View.VISIBLE) {
            modalContainer.setVisibility(View.GONE);
            modalContainer.removeAllViews();
        }

        NavigationTab currentTab = AppState.get().getCurrentTab();
        if (addToStack && currentTab != targetTab) {
            navigationBackStack.push(currentTab);
        }

        AppState.get().setCurrentTab(targetTab);
        performHaptic();

        // Update Visibility of Screens
        homeController.getView().setVisibility(targetTab == NavigationTab.HOME ? View.VISIBLE : View.GONE);
        scanController.getView().setVisibility(targetTab == NavigationTab.SCAN ? View.VISIBLE : View.GONE);
        activityController.getView().setVisibility(targetTab == NavigationTab.ACTIVITY ? View.VISIBLE : View.GONE);
        familyController.getView().setVisibility(targetTab == NavigationTab.FAMILY ? View.VISIBLE : View.GONE);
        settingsController.getView().setVisibility(targetTab == NavigationTab.SETTINGS ? View.VISIBLE : View.GONE);

        // Refresh views
        if (targetTab == NavigationTab.HOME) homeController.render();
        else if (targetTab == NavigationTab.SCAN) scanController.render();
        else if (targetTab == NavigationTab.ACTIVITY) activityController.render();
        else if (targetTab == NavigationTab.FAMILY) familyController.render();
        else if (targetTab == NavigationTab.SETTINGS) settingsController.render();

        updateNavHighlight(targetTab);
    }

    public void openContextualAssistant(String prompt) {
        if (modalContainer != null) {
            modalContainer.removeAllViews();
            modalContainer.addView(assistantController.getView());
            modalContainer.setVisibility(View.VISIBLE);
            assistantController.render();
            if (prompt != null && !prompt.isBlank()) {
                assistantController.promptAssistant(prompt);
            }
        }
    }

    private void updateNavHighlight(NavigationTab tab) {
        int activeColor = 0xFF141414; // Solid Monochrome Black
        int inactiveColor = 0xFF888888; // Muted Neutral Grey

        ivNavHome.setColorFilter(tab == NavigationTab.HOME ? activeColor : inactiveColor);
        tvNavHome.setTextColor(tab == NavigationTab.HOME ? activeColor : inactiveColor);
        tvNavHome.setTypeface(null, tab == NavigationTab.HOME ? android.graphics.Typeface.BOLD : android.graphics.Typeface.NORMAL);

        ivNavScan.setColorFilter(tab == NavigationTab.SCAN ? activeColor : inactiveColor);
        tvNavScan.setTextColor(tab == NavigationTab.SCAN ? activeColor : inactiveColor);
        tvNavScan.setTypeface(null, tab == NavigationTab.SCAN ? android.graphics.Typeface.BOLD : android.graphics.Typeface.NORMAL);

        ivNavActivity.setColorFilter(tab == NavigationTab.ACTIVITY ? activeColor : inactiveColor);
        tvNavActivity.setTextColor(tab == NavigationTab.ACTIVITY ? activeColor : inactiveColor);
        tvNavActivity.setTypeface(null, tab == NavigationTab.ACTIVITY ? android.graphics.Typeface.BOLD : android.graphics.Typeface.NORMAL);

        ivNavFamily.setColorFilter(tab == NavigationTab.FAMILY ? activeColor : inactiveColor);
        tvNavFamily.setTextColor(tab == NavigationTab.FAMILY ? activeColor : inactiveColor);
        tvNavFamily.setTypeface(null, tab == NavigationTab.FAMILY ? android.graphics.Typeface.BOLD : android.graphics.Typeface.NORMAL);

        ivNavSettings.setColorFilter(tab == NavigationTab.SETTINGS ? activeColor : inactiveColor);
        tvNavSettings.setTextColor(tab == NavigationTab.SETTINGS ? activeColor : inactiveColor);
        tvNavSettings.setTypeface(null, tab == NavigationTab.SETTINGS ? android.graphics.Typeface.BOLD : android.graphics.Typeface.NORMAL);
    }

    private void performHaptic() {
        try {
            if (vibrator != null && vibrator.hasVibrator()) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    vibrator.vibrate(VibrationEffect.createOneShot(12, VibrationEffect.DEFAULT_AMPLITUDE));
                } else {
                    vibrator.vibrate(12);
                }
            }
        } catch (Exception ignored) {}
    }

    private void onAppStateChanged() {
        NavigationTab tab = AppState.get().getCurrentTab();
        if (screenContainer != null) {
            homeController.getView().setVisibility(tab == NavigationTab.HOME ? View.VISIBLE : View.GONE);
            scanController.getView().setVisibility(tab == NavigationTab.SCAN ? View.VISIBLE : View.GONE);
            activityController.getView().setVisibility(tab == NavigationTab.ACTIVITY ? View.VISIBLE : View.GONE);
            familyController.getView().setVisibility(tab == NavigationTab.FAMILY ? View.VISIBLE : View.GONE);
            settingsController.getView().setVisibility(tab == NavigationTab.SETTINGS ? View.VISIBLE : View.GONE);
            updateNavHighlight(tab);
        }
    }

    @Override
    public void onBackPressed() {
        if (modalContainer != null && modalContainer.getVisibility() == View.VISIBLE) {
            modalContainer.setVisibility(View.GONE);
            modalContainer.removeAllViews();
            return;
        }

        if (!navigationBackStack.isEmpty()) {
            NavigationTab previous = navigationBackStack.pop();
            switchTab(previous, false);
        } else {
            super.onBackPressed();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == 2001 && resultCode == RESULT_OK && data != null) {
            Uri uri = data.getData();
            if (uri != null) {
                processSelectedApkUri(uri);
            }
        } else if (requestCode == dev.guardianai.personal.network.NetworkProtectionManager.REQUEST_CODE_VPN_CONSENT) {
            dev.guardianai.personal.network.NetworkProtectionManager npm =
                    dev.guardianai.personal.network.NetworkProtectionManager.getInstance(this);
            if (resultCode == RESULT_OK) {
                npm.startProtection(this);
                Toast.makeText(this, "Network Protection enabled. On-device DNS firewall active.", Toast.LENGTH_SHORT).show();
            } else {
                npm.onPermissionDenied();
                Toast.makeText(this, "VPN permission denied. Protection cannot start without system consent.", Toast.LENGTH_LONG).show();
            }
            if (homeController != null) {
                homeController.render();
            }
            if (settingsController != null) {
                settingsController.render();
            }
        }
    }

    private void processSelectedApkUri(Uri uri) {
        if (uri == null) return;
        switchTab(NavigationTab.SCAN, true);
        if (scanController != null) {
            scanController.analyzeSelectedApkUri(uri);
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleIncomingIntent(intent);
    }

    private void handleIncomingIntent(Intent intent) {
        if (intent == null) return;
        String action = intent.getAction();
        Uri data = intent.getData();

        if (DataExfiltrationSentinel.ACTION_SENTINEL_BLOCK.equals(action)) {
            DataExfiltrationSentinel.getInstance(this).confirmUpload(this, false);
            Toast.makeText(this, "🛡️ TeraBox background upload BLOCKED! 0 bytes leaked.", Toast.LENGTH_LONG).show();
            switchTab(NavigationTab.HOME, false);
            return;
        } else if (DataExfiltrationSentinel.ACTION_SENTINEL_ALLOW.equals(action)) {
            DataExfiltrationSentinel.getInstance(this).confirmUpload(this, true);
            Toast.makeText(this, "✅ TeraBox upload permitted by user.", Toast.LENGTH_SHORT).show();
            switchTab(NavigationTab.HOME, false);
            return;
        } else if (DataExfiltrationSentinel.ACTION_SENTINEL_PROMPT.equals(action)) {
            switchTab(NavigationTab.HOME, false);
            DataExfiltrationDialog.show(this, () -> {
                if (homeController != null) homeController.render();
            });
            return;
        } else if ("dev.guardianai.personal.ACTION_TEST_TERABOX".equals(action)) {
            switchTab(NavigationTab.HOME, false);
            dev.guardianai.personal.data.TeraBoxLaunchWatcher.getInstance(this).triggerSentinelScan();
            return;
        } else if ("dev.guardianai.personal.ACTION_LAUNCH_TERABOX".equals(action)) {
            dev.guardianai.personal.data.TeraBoxLaunchWatcher.launchTeraBox(this);
            return;
        }

        if (Intent.ACTION_VIEW.equals(action) && data != null) {
            processSelectedApkUri(data);
        } else if (Intent.ACTION_SEND.equals(action)) {
            Uri streamUri = intent.getParcelableExtra(Intent.EXTRA_STREAM);
            if (streamUri != null) {
                processSelectedApkUri(streamUri);
            }
        }
    }

    private void recordAndDisplayApkReport(ApkAnalysisReport report) {
        String scanId = "scan-" + System.currentTimeMillis();
        String verdict = report.getVerdict() == ScanVerdict.KNOWN_MALICIOUS ? "KNOWN_MALICIOUS" :
                (report.getVerdict() == ScanVerdict.HIGH_RISK || report.getVerdict() == ScanVerdict.CAUTION ? "SUSPICIOUS" : "SAFE");
        String severity = report.getVerdict() == ScanVerdict.KNOWN_MALICIOUS ? "CRITICAL" :
                (report.getVerdict() == ScanVerdict.HIGH_RISK ? "HIGH" :
                (report.getVerdict() == ScanVerdict.CAUTION ? "MEDIUM" : "INFO"));

        ScanRecord scan = new ScanRecord(
                scanId,
                "APK",
                System.currentTimeMillis(),
                "COMPLETED",
                report.getPlainLanguageExplanation(),
                report.getFileName(),
                "1.0.0",
                true,
                verdict,
                severity,
                report.canSafelyProceedWithInstall() ? "Proceed with Install" : "Quarantine & Delete"
        );

        List<FindingRecord> findings = new ArrayList<>();
        if (report.getIndicators() != null) {
            int fIdx = 1;
            String recAction = (report.getRecommendedActions() != null && !report.getRecommendedActions().isEmpty())
                    ? report.getRecommendedActions().get(0)
                    : (report.canSafelyProceedWithInstall() ? "Safe to proceed" : "Quarantine application");
            for (ThreatIndicator ti : report.getIndicators()) {
                findings.add(new FindingRecord(
                        scanId + "-f" + (fIdx++),
                        scanId,
                        ti.getCategory() != null ? ti.getCategory() : ti.getTitle(),
                        ti.getSeverity().name(),
                        ti.getTitle() + ": " + ti.getDescription(),
                        recAction
                ));
            }
        }

        AppState.get().recordScan(scan, findings);
        ActivityEvent event = AppState.mapScanRecordToActivityEvent(scan, findings);
        DetailSheetDialog.showEventDetails(this, event);
    }

    private void onNetworkProtectionStatusChanged(dev.guardianai.personal.network.NetworkProtectionStatus status) {
        runOnUiThread(() -> {
            if (homeController != null) {
                homeController.render();
            }
            if (settingsController != null) {
                settingsController.render();
            }
        });
    }

    @Override
    protected void onDestroy() {
        dev.guardianai.personal.network.NetworkProtectionManager.getInstance(this)
                .removeListener(this::onNetworkProtectionStatusChanged);
        super.onDestroy();
    }
}
