package dev.saathi.personal.ui.state;

import android.content.Context;

import dev.saathi.engine.SaathiApkIntelligence;
import dev.saathi.model.ThreatSeverity;
import dev.saathi.personal.data.db.FindingRecord;
import dev.saathi.personal.data.db.ScanRecord;
import dev.saathi.personal.data.db.SecurityAuditRepository;
import dev.saathi.personal.data.prefs.PreferencesManager;
import dev.saathi.personal.ui.model.ActivityEvent;
import dev.saathi.personal.ui.model.ChatMessage;
import dev.saathi.personal.ui.model.ChildProfile;
import dev.saathi.personal.ui.model.FamilyDevice;
import dev.saathi.personal.ui.model.NavigationTab;
import dev.saathi.personal.ui.model.SafetyReport;
import dev.saathi.personal.ui.model.ScanMode;
import dev.saathi.sense.SaathiSenseEngine;
import dev.saathi.shield.network.LocalFirewallEngine;
import dev.saathi.shield.network.PhishingUrlScanner;
import dev.saathi.shield.message.MessageRiskAnalyzer;
import dev.saathi.shield.message.RuleBasedMessageRiskAnalyzer;
import dev.saathi.ai.OnDeviceLanguageModel;
import dev.saathi.ai.SecurityFindingContext;
import dev.saathi.personal.ai.LiteRtLmAndroidModel;
import dev.saathi.family.FamilyRepository;
import dev.saathi.personal.data.family.FirebaseFamilyRepository;
import dev.saathi.storage.LocalStorageRepository;
import dev.saathi.storage.TrustedHelper;

import java.util.*;

public class AppState {

    private static AppState instance;

    public static synchronized AppState get() {
        if (instance == null) {
            instance = new AppState();
        }
        return instance;
    }

    private PreferencesManager preferencesManager;
    private SecurityAuditRepository auditRepository;
    private OnDeviceLanguageModel languageModel;
    private SecurityFindingContext activeFindingContext;

    private final SaathiApkIntelligence apkEngine;
    private final SaathiSenseEngine senseEngine;
    private final MessageRiskAnalyzer messageRiskAnalyzer;
    private final PhishingUrlScanner phishingScanner;
    private final LocalFirewallEngine firewallEngine;
    private final FamilyRepository familyRepository;
    private final LocalStorageRepository storageRepository;

    private ChildProfile currentProfile = ChildProfile.AARAV;
    private NavigationTab currentTab = NavigationTab.HOME;
    private ScanMode currentScanMode = ScanMode.APK_CHECK;

    private boolean isSeniorMode = false;
    private boolean isLargeText = false;
    private boolean isHighContrast = false;
    private boolean isHindi = false;
    private int safetyScore = 96;

    private String familyPairingCode = "SAATHI-FAM-7482";
    private boolean safetyAgreementAccepted = true;

    private final List<FamilyDevice> familyDevices = new ArrayList<>();
    private final List<SafetyReport> safetyReports = new ArrayList<>();
    private final List<ActivityEvent> activityEvents = new ArrayList<>();
    private final List<ChatMessage> chatMessages = new ArrayList<>();
    private final List<Runnable> stateListeners = new ArrayList<>();

    private AppState() {
        this.apkEngine = new SaathiApkIntelligence();
        this.senseEngine = new SaathiSenseEngine();
        this.messageRiskAnalyzer = new RuleBasedMessageRiskAnalyzer();
        this.phishingScanner = new PhishingUrlScanner();
        this.firewallEngine = new LocalFirewallEngine();
        this.familyRepository = new FirebaseFamilyRepository();
        this.storageRepository = new LocalStorageRepository();

        // Seed initial trusted helpers
        storageRepository.addTrustedHelper(new TrustedHelper("th-1", "Sunita (Mother)", "PRIMARY_PARENT", "+91 98101 23456", true));
        storageRepository.addTrustedHelper(new TrustedHelper("th-2", "Rajesh (Father)", "GUARDIAN", "+91 98202 34567", true));

        // Seed initial family devices (transparent, mutual safety)
        familyDevices.add(new FamilyDevice("dev-1", "Aarav's Phone (iQOO Z9)", "Aarav (Teen)", "Protected • Online", "12 mins ago", false));
        familyDevices.add(new FamilyDevice("dev-2", "Ananya's Tablet (Galaxy Tab)", "Ananya (Child)", "Protected • Online", "45 mins ago", false));
        familyDevices.add(new FamilyDevice("dev-3", "Dadaji's Phone (Redmi Note)", "Dadaji (Elderly)", "Senior Mode Active", "2 hours ago", true));

        // Seed child-initiated transparent safety reports
        safetyReports.add(new SafetyReport(
                "rep-201",
                "Aarav",
                new Date(System.currentTimeMillis() - 1000 * 60 * 45),
                "Suspicious Discord Contact",
                "User 'ModHelper_99' sent link claiming free Discord Nitro and asked Aarav to keep it secret.",
                "Reviewed with Parents",
                "Link neutralized & contact blocked"
        ));
        safetyReports.add(new SafetyReport(
                "rep-202",
                "Dadaji",
                new Date(System.currentTimeMillis() - 1000 * 60 * 180),
                "Electricity Bill SMS Inquiry",
                "Received SMS warning electricity will be disconnected tonight at 9 PM unless ₹12 fee paid via link.",
                "Verified Scam",
                "Marked as phishing, no payment made"
        ));

        // Note: Production activityEvents start with an honest empty state!
        // No mock hardcoded events seeded here.

        // Seed initial assistant greeting
        seedInitialChatMessages();
    }

    public void initContext(Context context) {
        if (context == null || preferencesManager != null) return;
        Context appCtx = context.getApplicationContext();
        preferencesManager = PreferencesManager.getInstance(appCtx);
        auditRepository = SecurityAuditRepository.getInstance(appCtx);

        isSeniorMode = preferencesManager.isSeniorMode();
        isLargeText = preferencesManager.isLargeText();
        isHighContrast = preferencesManager.isHighContrast();
        isHindi = preferencesManager.isHindi();
        currentProfile = preferencesManager.getCurrentProfile();

        // Initialize on-device language model provider (LiteRT-LM Gemma)
        if (languageModel == null) {
            languageModel = new LiteRtLmAndroidModel(appCtx);
            languageModel.initializeAsync((st, msg) -> notifyListeners());
        }

        // Refresh activity events from the local SQLite repository
        refreshActivityFromRepository();
    }

    public OnDeviceLanguageModel getLanguageModel() {
        return languageModel;
    }

    public SecurityFindingContext getActiveFindingContext() {
        return activeFindingContext;
    }

    public void setActiveFindingContext(SecurityFindingContext context) {
        this.activeFindingContext = context;
        notifyListeners();
    }

    public void clearActiveFindingContext() {
        this.activeFindingContext = null;
        notifyListeners();
    }

    public PreferencesManager getPreferencesManager() {
        return preferencesManager;
    }

    public SecurityAuditRepository getAuditRepository() {
        return auditRepository;
    }

    public void refreshActivityFromRepository() {
        if (auditRepository != null) {
            auditRepository.getAllScans(records -> {
                activityEvents.clear();
                if (records != null) {
                    for (ScanRecord scan : records) {
                        activityEvents.add(mapScanRecordToActivityEvent(scan, null));
                    }
                }
                notifyListeners();
            });
        } else {
            notifyListeners();
        }
    }

    public void recordScan(ScanRecord scan, List<FindingRecord> findings) {
        if (scan == null) return;
        if (auditRepository != null) {
            auditRepository.insertScan(scan, findings, v -> refreshActivityFromRepository());
        } else {
            activityEvents.add(0, mapScanRecordToActivityEvent(scan, findings));
            notifyListeners();
        }
    }

    public void clearLocalAuditCache(Runnable onComplete) {
        if (auditRepository != null) {
            auditRepository.clearAllScans(v -> {
                activityEvents.clear();
                notifyListeners();
                if (onComplete != null) onComplete.run();
            });
        } else {
            activityEvents.clear();
            notifyListeners();
            if (onComplete != null) onComplete.run();
        }
    }

    public static ActivityEvent mapScanRecordToActivityEvent(ScanRecord scan, List<FindingRecord> findings) {
        ActivityEvent.EventCategory category;
        String op = scan.getOperationType().toUpperCase(Locale.ROOT);
        switch (op) {
            case "APK":
            case "FILE":
                category = ActivityEvent.EventCategory.APK;
                break;
            case "LINK":
            case "PHISHING":
                category = ActivityEvent.EventCategory.PHISHING;
                break;
            case "MESSAGE":
            case "SMS":
                category = ActivityEvent.EventCategory.SENSE;
                break;
            case "NETWORK_FIREWALL":
            case "FIREWALL":
            case "PERMISSION_AUDIT":
            case "DEVICE":
                category = ActivityEvent.EventCategory.FIREWALL;
                break;
            default:
                category = ActivityEvent.EventCategory.SYSTEM;
                break;
        }

        ThreatSeverity severity;
        try {
            severity = ThreatSeverity.valueOf(scan.getSeverity().toUpperCase(Locale.ROOT));
        } catch (Exception e) {
            severity = ThreatSeverity.INFO;
        }

        String title;
        if ("KNOWN_MALICIOUS".equalsIgnoreCase(scan.getVerdict()) || severity == ThreatSeverity.CRITICAL) {
            title = "🚨 Intercepted Threat: " + scan.getSource();
        } else if ("SUSPICIOUS".equalsIgnoreCase(scan.getVerdict()) || severity == ThreatSeverity.HIGH) {
            title = "⚠️ Suspicious Indicator: " + scan.getSource();
        } else {
            title = "✅ Verified Clean: " + scan.getSource();
        }

        List<String> details = new ArrayList<>();
        details.add("Verdict: " + scan.getVerdict());
        details.add("Operation: " + scan.getOperationType());
        details.add("Status: " + scan.getProcessingStatus());
        if (findings != null) {
            for (FindingRecord f : findings) {
                details.add(f.getIndicatorType() + " (" + f.getSeverity() + "): " + f.getExplanation());
            }
        }

        String actionLabel = scan.getActionTaken();
        if (actionLabel == null || actionLabel.isBlank()) {
            actionLabel = "View Scan Details";
        }

        return new ActivityEvent(
                scan.getId(),
                new Date(scan.getTimestamp()),
                category,
                severity,
                title,
                scan.getSummary(),
                details,
                actionLabel
        );
    }

    private void seedInitialChatMessages() {
        chatMessages.add(new ChatMessage(
                false,
                "Namaste! I am your Saathi Digital Safety Copilot, running locally on your Snapdragon 8 Elite.\n\nI can help explain suspicious messages, verify APK sideloads, guide you through banking scam recovery, and help you report fraud on the 1930 National Portal. How can I help you today?",
                "Saathi Safety Copilot"
        ));
    }

    public SaathiApkIntelligence getApkEngine() {
        return apkEngine;
    }

    public SaathiSenseEngine getSenseEngine() {
        return senseEngine;
    }

    public MessageRiskAnalyzer getMessageRiskAnalyzer() {
        return messageRiskAnalyzer;
    }

    public PhishingUrlScanner getPhishingScanner() {
        return phishingScanner;
    }

    public LocalFirewallEngine getFirewallEngine() {
        return firewallEngine;
    }

    public FamilyRepository getFamilyRepository() {
        return familyRepository;
    }

    public LocalStorageRepository getStorageRepository() {
        return storageRepository;
    }

    public ChildProfile getCurrentProfile() {
        return currentProfile;
    }

    public void setCurrentProfile(ChildProfile currentProfile) {
        this.currentProfile = currentProfile;
        this.safetyScore = currentProfile.getDefaultSafetyScore();
        if (preferencesManager != null) {
            preferencesManager.setCurrentProfile(currentProfile);
        }
        if (currentProfile == ChildProfile.DADAJI) {
            setSeniorMode(true);
        } else {
            notifyListeners();
        }
    }

    public NavigationTab getCurrentTab() {
        return currentTab;
    }

    public void setCurrentTab(NavigationTab currentTab) {
        this.currentTab = currentTab;
        notifyListeners();
    }

    public ScanMode getCurrentScanMode() {
        return currentScanMode;
    }

    public void setCurrentScanMode(ScanMode currentScanMode) {
        this.currentScanMode = currentScanMode;
        notifyListeners();
    }

    public void navigateToScan(ScanMode scanMode) {
        this.currentScanMode = scanMode;
        this.currentTab = NavigationTab.SCAN;
        notifyListeners();
    }

    public boolean isSeniorMode() {
        return isSeniorMode;
    }

    public void setSeniorMode(boolean seniorMode) {
        this.isSeniorMode = seniorMode;
        if (preferencesManager != null) {
            preferencesManager.setSeniorMode(seniorMode);
        }
        notifyListeners();
    }

    public boolean isLargeText() {
        return isLargeText || isSeniorMode;
    }

    public void setLargeText(boolean largeText) {
        this.isLargeText = largeText;
        if (preferencesManager != null) {
            preferencesManager.setLargeText(largeText);
        }
        notifyListeners();
    }

    public boolean isHighContrast() {
        return isHighContrast || isSeniorMode;
    }

    public void setHighContrast(boolean highContrast) {
        this.isHighContrast = highContrast;
        if (preferencesManager != null) {
            preferencesManager.setHighContrast(highContrast);
        }
        notifyListeners();
    }

    public boolean isHindi() {
        return isHindi;
    }

    public void setHindi(boolean hindi) {
        this.isHindi = hindi;
        if (preferencesManager != null) {
            preferencesManager.setHindi(hindi);
        }
        notifyListeners();
    }

    public int getSafetyScore() {
        return safetyScore;
    }

    public void setSafetyScore(int safetyScore) {
        this.safetyScore = safetyScore;
        notifyListeners();
    }

    public String getFamilyPairingCode() {
        return familyPairingCode;
    }

    public void setFamilyPairingCode(String familyPairingCode) {
        this.familyPairingCode = familyPairingCode;
        notifyListeners();
    }

    public boolean isSafetyAgreementAccepted() {
        return safetyAgreementAccepted;
    }

    public void setSafetyAgreementAccepted(boolean safetyAgreementAccepted) {
        this.safetyAgreementAccepted = safetyAgreementAccepted;
        notifyListeners();
    }

    public List<FamilyDevice> getFamilyDevices() {
        return Collections.unmodifiableList(familyDevices);
    }

    public void addFamilyDevice(FamilyDevice device) {
        familyDevices.add(device);
        notifyListeners();
    }

    public List<SafetyReport> getSafetyReports() {
        return Collections.unmodifiableList(safetyReports);
    }

    public void addSafetyReport(SafetyReport report) {
        safetyReports.add(0, report);
        notifyListeners();
    }

    public List<ActivityEvent> getActivityEvents() {
        return Collections.unmodifiableList(activityEvents);
    }

    public void addActivityEvent(ActivityEvent event) {
        activityEvents.add(0, event);
        notifyListeners();
    }

    public List<ChatMessage> getChatMessages() {
        return Collections.unmodifiableList(chatMessages);
    }

    public void addChatMessage(ChatMessage message) {
        chatMessages.add(message);
        notifyListeners();
    }

    public void updateLastAssistantMessage(String newText, String badge) {
        for (int i = chatMessages.size() - 1; i >= 0; i--) {
            if (!chatMessages.get(i).isUser) {
                chatMessages.set(i, new ChatMessage(false, newText, badge));
                notifyListeners();
                return;
            }
        }
        chatMessages.add(new ChatMessage(false, newText, badge));
        notifyListeners();
    }

    public void addListener(Runnable listener) {
        if (!stateListeners.contains(listener)) {
            stateListeners.add(listener);
        }
    }

    public void removeListener(Runnable listener) {
        stateListeners.remove(listener);
    }

    public void notifyListeners() {
        for (Runnable r : stateListeners) {
            try {
                r.run();
            } catch (Exception ignored) {}
        }
    }
}
