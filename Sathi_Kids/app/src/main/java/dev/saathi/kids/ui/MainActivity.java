package dev.saathi.kids.ui;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.view.Display;
import android.view.View;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import dev.saathi.kids.KidsServices;
import dev.saathi.kids.R;
import dev.saathi.kids.ui.components.KidsOnboardingOverlay;
import dev.saathi.kids.safety.AlertDispatcher;
import dev.saathi.kids.safety.SafeBrowserActivity;
import dev.saathi.kids.ui.components.LessonDetailOverlay;
import dev.saathi.kids.ui.components.SafetyEventsOverlay;
import dev.saathi.safety.FlagEngine;
import dev.saathi.safety.SafetyEvent;
import dev.saathi.kids.ui.components.SosFlowOverlay;
import dev.saathi.kids.ui.model.NavigationTab;
import dev.saathi.kids.ui.screens.CheckScreenController;
import dev.saathi.kids.ui.screens.HomeScreenController;
import dev.saathi.kids.ui.screens.LearnScreenController;
import dev.saathi.kids.ui.screens.SettingsScreenController;

import java.util.ArrayDeque;
import java.util.Deque;

/** Hosts the four tabs (Home, Check, Learn, Settings) and the full-screen overlays (onboarding, help, lesson). */
public class MainActivity extends Activity implements
        HomeScreenController.HomeNavigationHost,
        CheckScreenController.CheckNavigationHost,
        LearnScreenController.LearnNavigationHost,
        SettingsScreenController.Host,
        SosFlowOverlay.Host,
        SafetyEventsOverlay.Host,
        AlertDispatcher.InAppPresenter {

    public static final String EXTRA_OPEN_HELP = "saathi_open_help";
    private static final int REQ_POST_NOTIFICATIONS = 1003;

    private static final int REQ_PICK_FILE = 1001;
    private static final int REQ_LOCATION = 1002;
    private static final String STATE_TAB = "tab";

    private FrameLayout screenContainer, overlayContainer;
    private LinearLayout navHome, navCheck, navLearn, navSettings;
    private ImageView ivHome, ivCheck, ivLearn, ivSettings;
    private TextView tvHome, tvCheck, tvLearn, tvSettings;

    private HomeScreenController home;
    private CheckScreenController check;
    private LearnScreenController learn;
    private SettingsScreenController settings;
    private SosFlowOverlay sos;
    private SafetyEventsOverlay safety;

    private NavigationTab currentTab = NavigationTab.HOME;
    private final Deque<NavigationTab> backStack = new ArrayDeque<>();
    private Vibrator vibrator;
    private Runnable pendingLocationGranted, pendingLocationDenied;

    /** Applies the persisted "Larger text" preference to every screen by scaling the font configuration. */
    @Override
    protected void attachBaseContext(Context base) {
        boolean large = KidsServices.get(base).repo.isLargeText();
        if (large) {
            Configuration c = new Configuration(base.getResources().getConfiguration());
            c.fontScale = c.fontScale * 1.2f;
            super.attachBaseContext(base.createConfigurationContext(c));
        } else {
            super.attachBaseContext(base);
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        preferHighRefreshRate();
        View decor = getWindow().getDecorView();
        int flags = decor.getSystemUiVisibility() | View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) flags |= View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR;
        decor.setSystemUiVisibility(flags);

        setContentView(R.layout.activity_main);
        vibrator = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
        bindViews();

        home = new HomeScreenController(this, this);
        check = new CheckScreenController(this, this);
        learn = new LearnScreenController(this, this);
        settings = new SettingsScreenController(this, this);
        screenContainer.addView(home.getView());
        screenContainer.addView(check.getView());
        screenContainer.addView(learn.getView());
        screenContainer.addView(settings.getView());
        navHome.setOnClickListener(v -> switchTab(NavigationTab.HOME, true));
        navCheck.setOnClickListener(v -> switchTab(NavigationTab.CHECK, true));
        navLearn.setOnClickListener(v -> switchTab(NavigationTab.LEARN, true));
        navSettings.setOnClickListener(v -> switchTab(NavigationTab.SETTINGS, true));

        NavigationTab start = NavigationTab.HOME;
        if (savedInstanceState != null) {
            try {
                start = NavigationTab.valueOf(savedInstanceState.getString(STATE_TAB, "HOME"));
            } catch (IllegalArgumentException ignored) {
                // keep HOME
            }
        }
        switchTab(start, false);
        if (!KidsServices.get(this).repo.isOnboardingCompleted()) showOnboarding();
        if (savedInstanceState == null) handleIncomingIntent(getIntent());
    }

    @Override
    protected void onSaveInstanceState(Bundle out) {
        super.onSaveInstanceState(out);
        out.putString(STATE_TAB, currentTab.name());
    }

    private void bindViews() {
        screenContainer = findViewById(R.id.screen_container);
        overlayContainer = findViewById(R.id.overlay_container);
        navHome = findViewById(R.id.nav_item_home);
        navCheck = findViewById(R.id.nav_item_check);
        navLearn = findViewById(R.id.nav_item_learn);
        navSettings = findViewById(R.id.nav_item_settings);
        ivHome = findViewById(R.id.iv_nav_home);
        ivCheck = findViewById(R.id.iv_nav_check);
        ivLearn = findViewById(R.id.iv_nav_learn);
        ivSettings = findViewById(R.id.iv_nav_settings);
        tvHome = findViewById(R.id.tv_nav_home);
        tvCheck = findViewById(R.id.tv_nav_check);
        tvLearn = findViewById(R.id.tv_nav_learn);
        tvSettings = findViewById(R.id.tv_nav_settings);
    }

    private void preferHighRefreshRate() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return;
        try {
            WindowManager.LayoutParams p = getWindow().getAttributes();
            Display d = getDisplay();
            if (d != null) {
                float best = 0;
                for (Display.Mode m : d.getSupportedModes()) {
                    if (m.getRefreshRate() > best && m.getPhysicalWidth() == d.getMode().getPhysicalWidth()) {
                        best = m.getRefreshRate();
                        p.preferredDisplayModeId = m.getModeId();
                    }
                }
            }
            getWindow().setAttributes(p);
        } catch (RuntimeException ignored) {
            // display mode selection is best-effort
        }
    }

    @Override
    public void switchTab(NavigationTab tab, boolean addToStack) {
        if (addToStack && currentTab != tab) backStack.push(currentTab);
        currentTab = tab;
        haptic();
        home.getView().setVisibility(tab == NavigationTab.HOME ? View.VISIBLE : View.GONE);
        check.getView().setVisibility(tab == NavigationTab.CHECK ? View.VISIBLE : View.GONE);
        learn.getView().setVisibility(tab == NavigationTab.LEARN ? View.VISIBLE : View.GONE);
        settings.getView().setVisibility(tab == NavigationTab.SETTINGS ? View.VISIBLE : View.GONE);
        if (tab == NavigationTab.HOME) home.render();
        else if (tab == NavigationTab.LEARN) learn.render();
        else if (tab == NavigationTab.SETTINGS) settings.render();
        highlight(tab);
    }

    private void highlight(NavigationTab tab) {
        int on = 0xFF141414, off = 0xFF888888;
        ImageView[] icons = {ivHome, ivCheck, ivLearn, ivSettings};
        TextView[] labels = {tvHome, tvCheck, tvLearn, tvSettings};
        NavigationTab[] tabs = {NavigationTab.HOME, NavigationTab.CHECK, NavigationTab.LEARN, NavigationTab.SETTINGS};
        for (int i = 0; i < tabs.length; i++) {
            boolean a = tabs[i] == tab;
            icons[i].setColorFilter(a ? on : off);
            labels[i].setTextColor(a ? on : off);
            labels[i].setTypeface(null, a ? android.graphics.Typeface.BOLD : android.graphics.Typeface.NORMAL);
        }
    }

    private void haptic() {
        try {
            if (vibrator != null && vibrator.hasVibrator()) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) vibrator.vibrate(VibrationEffect.createOneShot(12, VibrationEffect.DEFAULT_AMPLITUDE));
            }
        } catch (RuntimeException ignored) {
            // haptics are optional
        }
    }

    // ---------------------------------------------------------------- overlays

    private boolean overlayVisible() {
        return overlayContainer.getVisibility() == View.VISIBLE;
    }

    @Override
    public void dismissOverlay() {
        overlayContainer.setVisibility(View.GONE);
        overlayContainer.removeAllViews();
        if (sos != null) {
            sos.release();
            sos = null;
        }
        safety = null;
        if (currentTab == NavigationTab.HOME) home.render();
        else if (currentTab == NavigationTab.LEARN) learn.render();
    }

    private void showOnboarding() {
        new KidsOnboardingOverlay(this, overlayContainer, this::dismissOverlay).show();
    }

    @Override
    public void showSosFlow() {
        safety = null;
        if (sos != null) sos.release();
        sos = new SosFlowOverlay(this, overlayContainer, this);
        sos.show();
    }

    @Override
    public void openSafetyAlerts() {
        if (sos != null) {
            sos.release();
            sos = null;
        }
        safety = new SafetyEventsOverlay(this, overlayContainer, this);
        safety.showList();
    }

    private void openSafetyEvent(String id) {
        safety = new SafetyEventsOverlay(this, overlayContainer, this);
        safety.showEvent(id);
    }

    @Override
    public void openSafeBrowser() {
        startActivity(new Intent(this, SafeBrowserActivity.class));
    }

    /** Called by AlertDispatcher on the main thread when an alert arrives while Saathi is on screen. */
    @Override
    public void presentSafetyEvent(SafetyEvent e, FlagEngine.AlertKind kind) {
        if (isFinishing()) return;
        String title = kind == FlagEngine.AlertKind.SELF_HARM_SUPPORT ? "Saathi is here for you"
                : kind == FlagEngine.AlertKind.THREAT_ALERT ? "A message may be a threat" : "Something to look at";
        String body = kind == FlagEngine.AlertKind.SELF_HARM_SUPPORT
                ? "Something sounded really hard. Would you like to see some ways to get support?"
                : "Saathi noticed warning signs in a message" + (e.sourceApp.isEmpty() ? "" : " in " + e.sourceApp) + ".";
        new android.app.AlertDialog.Builder(this)
                .setTitle(title)
                .setMessage(body)
                .setPositiveButton("See details", (d, w) -> openSafetyEvent(e.eventId))
                .setNegativeButton("Later", null)
                .show();
    }

    @Override
    public void requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, REQ_POST_NOTIFICATIONS);
        } else {
            try {
                startActivity(dev.saathi.kids.safety.MonitoringState.appNotificationSettings(this));
            } catch (android.content.ActivityNotFoundException ignored) {
                // settings screen unavailable on this device
            }
        }
    }

    @Override
    public void openNotificationAccessSettings() {
        try {
            startActivity(dev.saathi.kids.safety.MonitoringState.notificationAccessSettings(this));
        } catch (android.content.ActivityNotFoundException e) {
            startActivity(new Intent(android.provider.Settings.ACTION_SETTINGS));
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        AlertDispatcher.setInAppPresenter(this);
        settings.render(); // permission changes made in system settings show up immediately
    }

    @Override
    protected void onPause() {
        AlertDispatcher.clearInAppPresenter(this);
        super.onPause();
    }

    @Override
    public void showLessonDetail(String lessonId) {
        new LessonDetailOverlay(this, overlayContainer, lessonId, this::dismissOverlay).show();
    }

    @Override
    public void openCheckMode(int modeIndex) {
        switchTab(NavigationTab.CHECK, true);
        check.setMode(modeIndex);
    }

    @Override
    public void applyTextSize() {
        recreate();
    }

    // ---------------------------------------------------------------- file picker (Storage Access Framework)

    @Override
    public void requestFilePick() {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("*/*");
        i.putExtra(Intent.EXTRA_MIME_TYPES, new String[]{"application/vnd.android.package-archive", "application/zip", "application/octet-stream"});
        try {
            startActivityForResult(i, REQ_PICK_FILE);
        } catch (android.content.ActivityNotFoundException e) {
            android.widget.Toast.makeText(this, "No file picker is available on this device", android.widget.Toast.LENGTH_LONG).show();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQ_PICK_FILE) return;
        Uri uri = resultCode == RESULT_OK && data != null ? data.getData() : null;
        switchTab(NavigationTab.CHECK, false);
        if (uri != null) check.checkFileUri(uri);
        else check.onFilePickCancelled();
    }

    // ---------------------------------------------------------------- location permission (help requests only)

    @Override
    public void requestCoarseLocation(Runnable onGranted, Runnable onDenied) {
        pendingLocationGranted = onGranted;
        pendingLocationDenied = onDenied;
        requestPermissions(new String[]{Manifest.permission.ACCESS_COARSE_LOCATION}, REQ_LOCATION);
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] results) {
        super.onRequestPermissionsResult(requestCode, permissions, results);
        if (requestCode == REQ_POST_NOTIFICATIONS) {
            settings.render();
            return;
        }
        if (requestCode != REQ_LOCATION) return;
        boolean granted = results.length > 0 && results[0] == PackageManager.PERMISSION_GRANTED;
        Runnable r = granted ? pendingLocationGranted : pendingLocationDenied;
        pendingLocationGranted = null;
        pendingLocationDenied = null;
        if (r != null) r.run();
    }

    // ---------------------------------------------------------------- shared content (never auto-checked)

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleIncomingIntent(intent);
    }

    private void handleIncomingIntent(Intent intent) {
        if (intent == null) return;
        String eventId = intent.getStringExtra(AlertDispatcher.EXTRA_EVENT_ID);
        if (eventId != null) {
            intent.removeExtra(AlertDispatcher.EXTRA_EVENT_ID); // don't reopen on rotation/recreate
            openSafetyEvent(eventId);
            return;
        }
        if (intent.getBooleanExtra(EXTRA_OPEN_HELP, false)) {
            intent.removeExtra(EXTRA_OPEN_HELP);
            showSosFlow();
            return;
        }
        String action = intent.getAction();
        if (Intent.ACTION_SEND.equals(action)) {
            if ("text/plain".equals(intent.getType())) {
                String text = intent.getStringExtra(Intent.EXTRA_TEXT);
                if (text != null && !text.trim().isEmpty()) {
                    switchTab(NavigationTab.CHECK, true);
                    check.prefillSharedText(text);
                }
            } else {
                Uri u;
                if (Build.VERSION.SDK_INT >= 33) u = intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri.class);
                else u = legacyStream(intent);
                if (u != null && "content".equals(u.getScheme())) {
                    switchTab(NavigationTab.CHECK, true);
                    check.offerSharedFile(u);
                }
            }
        } else if (Intent.ACTION_VIEW.equals(action) && intent.getData() != null && "content".equals(intent.getData().getScheme())) {
            switchTab(NavigationTab.CHECK, true);
            check.offerSharedFile(intent.getData());
        }
    }

    @SuppressWarnings("deprecation")
    private static Uri legacyStream(Intent i) {
        return i.getParcelableExtra(Intent.EXTRA_STREAM);
    }

    // ---------------------------------------------------------------- lifecycle

    @Override
    public void onBackPressed() {
        if (overlayVisible()) {
            if (sos != null && sos.onBack()) return;
            if (safety != null && safety.onBack()) return;
            if (!KidsServices.get(this).repo.isOnboardingCompleted()) {
                super.onBackPressed();
                return;
            }
            dismissOverlay();
            return;
        }
        if (!backStack.isEmpty()) {
            switchTab(backStack.pop(), false);
            return;
        }
        if (currentTab != NavigationTab.HOME) {
            switchTab(NavigationTab.HOME, false);
            return;
        }
        super.onBackPressed();
    }

    @Override
    public void onTrimMemory(int level) {
        super.onTrimMemory(level);
        KidsServices.get(this).model.onTrimMemory(level);
    }

    @Override
    protected void onDestroy() {
        check.onDestroy();
        home.onDestroy();
        learn.onDestroy();
        settings.onDestroy();
        if (sos != null) sos.release();
        if (isFinishing()) KidsServices.get(this).model.release();
        super.onDestroy();
    }
}
