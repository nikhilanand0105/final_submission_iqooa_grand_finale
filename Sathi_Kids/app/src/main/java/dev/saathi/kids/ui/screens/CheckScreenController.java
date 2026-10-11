package dev.saathi.kids.ui.screens;

import android.app.Activity;
import android.app.AlertDialog;
import android.database.Cursor;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.Uri;
import android.provider.OpenableColumns;
import android.text.InputFilter;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;

import dev.saathi.ai.explain.ExplanationService;
import dev.saathi.ai.explain.Finding;
import dev.saathi.ai.explain.FindingSet;
import dev.saathi.ai.explain.ModelState;
import dev.saathi.ai.explain.SafetyExplanation;
import dev.saathi.kids.KidsServices;
import dev.saathi.kids.storage.model.CheckHistoryRecord;
import dev.saathi.kids.ui.Ui;
import dev.saathi.kids.ui.model.CheckVerdict;
import dev.saathi.sense.analyzer.MessageAnalysisResult;
import dev.saathi.sense.analyzer.SafetyIndicator;
import dev.saathi.shield.apk.AnalysisStatus;
import dev.saathi.shield.apk.ApkAnalysisResult;
import dev.saathi.shield.apk.ApkIndicator;
import dev.saathi.shield.apk.SigningInfo;
import dev.saathi.shield.url.ParsedUrl;
import dev.saathi.shield.url.ReputationStatus;
import dev.saathi.shield.url.UrlAnalysisResult;
import dev.saathi.shield.url.UrlStructuralIndicator;
import dev.saathi.util.CancellationToken;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Check screen: Message / Link / File. Every result shown here is produced by running the real analyzer on the
 * exact input the child entered or selected. Nothing is checked until the child taps a Check/Choose button.
 */
public class CheckScreenController {

    public interface CheckNavigationHost {
        void showSosFlow();
        void requestFilePick();
    }

    public static final int MODE_MESSAGE = 0, MODE_LINK = 1, MODE_FILE = 2;
    private static final int MAX_MESSAGE_CHARS = 5000;

    private final Activity activity;
    private final CheckNavigationHost host;
    private final KidsServices svc;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final ExecutorService aiWorker = Executors.newSingleThreadExecutor();

    private ScrollView root;
    private LinearLayout content;
    private TextView tabMessage, tabLink, tabFile;
    private LinearLayout inputCard;
    private LinearLayout resultBox;
    private EditText input;
    private int mode = MODE_MESSAGE;
    private int generation = 0;              // ignores results from superseded checks
    private CancellationToken fileToken;
    private CancellationToken aiToken;
    private Uri pendingFileUri;              // file shared/opened into the app, waiting for the child to tap Check

    // last result, for the explanation card
    private FindingSet lastFindings;
    private String lastSubmittedText;
    private boolean lastThreatMatch;

    public CheckScreenController(Activity activity, CheckNavigationHost host) {
        this.activity = activity;
        this.host = host;
        this.svc = KidsServices.get(activity);
        build();
    }

    public View getView() {
        return root;
    }

    private int dp(int v) {
        return Ui.dp(activity, v);
    }

    // ---------------------------------------------------------------------------------------- layout

    private void build() {
        root = new ScrollView(activity);
        root.setFillViewport(true);
        root.setBackgroundColor(Ui.BG);
        content = new LinearLayout(activity);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(dp(20), dp(20), dp(20), dp(60));
        root.addView(content);

        TextView h = Ui.text(activity, "Safety Check 🔍", 24f, Ui.INK, true);
        h.setTypeface(Typeface.create("sans-serif-black", Typeface.BOLD));
        content.addView(h);
        TextView sub = Ui.text(activity, "Paste a message or a link, or choose a downloaded file. Saathi looks for warning signs and explains what to do next.", 13.5f, Color.parseColor("#555555"), false);
        sub.setPadding(0, dp(4), 0, dp(14));
        content.addView(sub);

        LinearLayout tabs = Ui.row(activity);
        tabs.setBackground(Ui.card(activity, Color.parseColor("#ECECE8"), Color.parseColor("#E0E0DC"), 12));
        tabs.setPadding(dp(4), dp(4), dp(4), dp(4));
        tabMessage = tab("💬 Message", MODE_MESSAGE);
        tabLink = tab("🔗 Link", MODE_LINK);
        tabFile = tab("📁 File", MODE_FILE);
        tabs.addView(tabMessage);
        tabs.addView(tabLink);
        tabs.addView(tabFile);
        LinearLayout.LayoutParams tlp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        tlp.bottomMargin = dp(14);
        content.addView(tabs, tlp);

        inputCard = Ui.vcard(activity);
        content.addView(inputCard);
        resultBox = new LinearLayout(activity);
        resultBox.setOrientation(LinearLayout.VERTICAL);
        content.addView(resultBox);
        setMode(MODE_MESSAGE);
    }

    private TextView tab(String label, int m) {
        TextView t = Ui.text(activity, label, 13f, Ui.MUTED, true);
        t.setGravity(Gravity.CENTER);
        t.setPadding(0, dp(10), 0, dp(10));
        t.setLayoutParams(Ui.weight(1f));
        t.setOnClickListener(v -> setMode(m));
        return t;
    }

    public void setMode(int m) {
        mode = m;
        generation++;
        cancelRunning();
        for (TextView t : new TextView[]{tabMessage, tabLink, tabFile}) {
            boolean on = (t == tabMessage && m == MODE_MESSAGE) || (t == tabLink && m == MODE_LINK) || (t == tabFile && m == MODE_FILE);
            t.setBackground(on ? Ui.card(activity, Color.WHITE, Color.parseColor("#DCDCD8"), 8) : null);
            t.setTextColor(on ? Ui.INK : Color.parseColor("#777777"));
        }
        renderInput();
        resultBox.removeAllViews();
    }

    private void cancelRunning() {
        if (fileToken != null) fileToken.cancel();
        if (aiToken != null) aiToken.cancel();
    }

    private void renderInput() {
        inputCard.removeAllViews();
        input = null;
        if (mode == MODE_FILE) {
            renderFileInput();
            return;
        }
        input = new EditText(activity);
        input.setTextSize(14f);
        input.setTextColor(Ui.INK);
        input.setHintTextColor(Color.parseColor("#999999"));
        input.setGravity(Gravity.TOP | Gravity.START);
        input.setBackground(Ui.card(activity, Color.parseColor("#F9F9F8"), Color.parseColor("#E4E4DF"), 10));
        input.setPadding(dp(14), dp(12), dp(14), dp(12));
        if (mode == MODE_MESSAGE) {
            input.setHint("Paste a chat, game message or text here…");
            input.setMinLines(4);
            input.setFilters(new InputFilter[]{new InputFilter.LengthFilter(MAX_MESSAGE_CHARS)});
        } else {
            input.setHint("Paste a web link here, e.g. https://example.com");
            input.setMinLines(2);
            input.setFilters(new InputFilter[]{new InputFilter.LengthFilter(8192)});
            input.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_VARIATION_URI
                    | android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE);
        }
        inputCard.addView(input);
        if (mode == MODE_MESSAGE) {
            inputCard.addView(Ui.note(activity, "Checked on this phone; the text isn't uploaded. If a concern is found, a short quote is kept in Safety alerts for 30 days."));
        } else {
            addLinkPrivacyControls();
        }
        LinearLayout btns = Ui.row(activity);
        Button check = Ui.primary(activity, "Check now  →", v -> runTextCheck());
        LinearLayout.LayoutParams c = Ui.weight(2f);
        c.rightMargin = dp(8);
        btns.addView(check, c);
        Button clear = Ui.secondary(activity, "Clear", v -> {
            if (input != null) input.setText("");
            resultBox.removeAllViews();
        });
        btns.addView(clear, Ui.weight(1f));
        inputCard.addView(btns);
    }

    private void addLinkPrivacyControls() {
        inputCard.addView(Ui.note(activity, "Saathi never opens the link. It reads the address only."));
        if (!svc.urlAnalyzer.getProvider().isConfigured()) {
            inputCard.addView(Ui.note(activity, "The online safety list isn't set up in this version of the app, so only this phone's checks will run."));
            return;
        }
        LinearLayout r = Ui.row(activity);
        TextView label = Ui.text(activity, "Also ask the online safety list (" + svc.urlAnalyzer.getProvider().getName() + ")", 12.5f, Color.parseColor("#333333"), false);
        r.addView(label, Ui.weight(1f));
        Switch sw = new Switch(activity);
        sw.setChecked(svc.repo.isOnlineLinkCheckAllowed());
        sw.setOnCheckedChangeListener((CompoundButton b, boolean on) -> {
            if (!on) {
                svc.repo.setOnlineLinkCheckAllowed(false);
                return;
            }
            b.setChecked(false);
            new AlertDialog.Builder(activity)
                    .setTitle("Send link to the online safety list?")
                    .setMessage(svc.urlAnalyzer.getProvider().getDisclosure() + "\n\nYou can turn this off any time.")
                    .setPositiveButton("Yes, allow", (d, w) -> {
                        svc.repo.setOnlineLinkCheckAllowed(true);
                        b.setOnCheckedChangeListener(null);
                        b.setChecked(true);
                        renderInput();
                    })
                    .setNegativeButton("No, phone only", null)
                    .show();
        });
        r.addView(sw);
        inputCard.addView(r);
    }

    private void renderFileInput() {
        inputCard.addView(Ui.title(activity, "Check a downloaded app file (.apk)"));
        inputCard.addView(Ui.body(activity, "Choose the file yourself. Saathi reads it to look for warning signs. It never installs or opens the app."));
        if (pendingFileUri != null) {
            String name = queryName(pendingFileUri);
            inputCard.addView(Ui.badge(activity, "Shared with Saathi: " + name, Ui.INK, Color.parseColor("#ECECE8")));
            Uri u = pendingFileUri;
            inputCard.addView(Ui.primary(activity, "Check this file  →", v -> {
                pendingFileUri = null;
                checkFileUri(u);
            }));
        }
        inputCard.addView(Ui.secondary(activity, "📁  Choose a file from this phone", v -> {
            if (host != null) host.requestFilePick();
        }));
        inputCard.addView(Ui.note(activity, "Files up to " + Ui.formatSize(dev.saathi.shield.apk.DefaultApkStaticAnalyzer.MAX_FILE_BYTES)
                + " can be checked. A temporary copy is made in Saathi's private storage and deleted afterwards."));
    }

    // ---------------------------------------------------------------------------------------- entry points from MainActivity

    /** Text shared from another app. Filled in, not checked, until the child taps Check. */
    public void prefillSharedText(String text) {
        String t = text.trim();
        boolean looksLikeLink = !t.contains(" ") && !t.contains("\n") && (t.startsWith("http://") || t.startsWith("https://") || t.startsWith("www."));
        setMode(looksLikeLink ? MODE_LINK : MODE_MESSAGE);
        if (input != null) input.setText(t.length() > MAX_MESSAGE_CHARS ? t.substring(0, MAX_MESSAGE_CHARS) : t);
        resultBox.removeAllViews();
        LinearLayout c = Ui.vcard(activity);
        c.addView(Ui.body(activity, "Shared from another app. Look it over, then tap Check now."));
        resultBox.addView(c);
    }

    /** A file shared/opened into the app. Shown, not checked, until the child taps "Check this file". */
    public void offerSharedFile(Uri uri) {
        pendingFileUri = uri;
        setMode(MODE_FILE);
    }

    public void onFilePickCancelled() {
        resultBox.removeAllViews();
        LinearLayout c = Ui.vcard(activity);
        c.addView(Ui.body(activity, "No file was chosen. Tap \"Choose a file\" to try again."));
        resultBox.addView(c);
    }

    // ---------------------------------------------------------------------------------------- message & link

    private void runTextCheck() {
        if (input == null) return;
        String text = input.getText() == null ? "" : input.getText().toString();
        if (text.trim().isEmpty()) {
            showError(mode == MODE_LINK ? "Paste a link first." : "Paste a message first.");
            return;
        }
        final int gen = ++generation;
        final int m = mode;
        final boolean live = m == MODE_LINK && svc.repo.isOnlineLinkCheckAllowed();
        showProgress(m == MODE_LINK ? (live ? "Checking the address and asking the online safety list…" : "Checking the address…") : "Checking the message…", null);
        worker.execute(() -> {
            try {
                if (m == MODE_MESSAGE) {
                    MessageAnalysisResult r = svc.messageAnalyzer.analyze(text);
                    // Same Gemma-first pipeline as background notifications; updates the safety flags.
                    dev.saathi.kids.safety.SafetyEventProcessor.Outcome so = dev.saathi.kids.safety.SafetyEventProcessor.get(activity)
                            .analyzeNow(dev.saathi.safety.SafetyTypes.SourceType.MANUAL_MESSAGE, "", text, false);
                    activity.runOnUiThread(() -> { if (gen == generation) { showMessageResult(r, text); addSafetyClassification(so); } });
                } else {
                    UrlAnalysisResult r = svc.urlAnalyzer.analyze(text, live);
                    activity.runOnUiThread(() -> { if (gen == generation) showUrlResult(r); });
                }
            } catch (RuntimeException e) {
                activity.runOnUiThread(() -> { if (gen == generation) showError("The check couldn't be completed. Nothing was found either way."); });
            }
        });
    }

    private void showMessageResult(MessageAnalysisResult r, String text) {
        CheckVerdict v;
        switch (r.getVerdict()) {
            case WARNING_SIGNS_DETECTED: v = CheckVerdict.WARNING_SIGNS; break;
            case BE_CAREFUL: v = CheckVerdict.BE_CAREFUL; break;
            case NO_FLAGS_DETECTED: v = CheckVerdict.LOOKS_OKAY; break;
            default: v = CheckVerdict.CANNOT_TELL; break;
        }
        List<String[]> signs = new ArrayList<>();
        for (SafetyIndicator i : r.getMatchedIndicators()) signs.add(new String[]{i.getName(), i.getDescription(), i.getEvidenceExcerpt()});
        LinearLayout card = resultCard(v, v.getLabel(), r.getExplanation(), signs, r.getWhyItMatters(), r.getNextSteps());
        card.addView(Ui.note(activity, "ℹ️ " + r.getLimitationsNote() + " • " + r.getAnalyzerType() + " " + r.getAnalyzerVersion()));
        finishResult(card, FindingSet.fromMessage(r), text, false);
        record("MESSAGE", r.getAnalyzerType() + "_" + r.getAnalyzerVersion(), r.getVerdict().name(), r.getMatchedIndicators().size(), idsOfMessage(r));
    }

    /** Adds the pipeline's threat / self-harm classification (with its true source) to the current result card. */
    private void addSafetyClassification(dev.saathi.kids.safety.SafetyEventProcessor.Outcome o) {
        if (resultBox.getChildCount() == 0) return;
        LinearLayout card = (LinearLayout) resultBox.getChildAt(0);
        dev.saathi.safety.SafetyClassification c = o.result.classification;
        LinearLayout box = new LinearLayout(activity);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(0, dp(10), 0, 0);
        boolean selfHarm = c.selfHarm.isPersonalRisk();
        boolean threat = c.threat != dev.saathi.safety.SafetyTypes.ThreatKind.NONE;
        if (selfHarm) {
            box.addView(Ui.text(activity, "💚 This sounds really hard", 13.5f, Ui.GREEN, true));
            box.addView(Ui.body(activity, "If this is about you or a friend, you don't have to handle it alone. Talking to someone can help."));
            box.addView(Ui.secondary(activity, "📞 " + dev.saathi.kids.safety.SupportResources.TELE_MANAS_LABEL,
                    v -> activity.startActivity(new android.content.Intent(android.content.Intent.ACTION_DIAL,
                            Uri.parse("tel:" + dev.saathi.kids.safety.SupportResources.TELE_MANAS_NUMBER)))));
        } else if (threat) {
            box.addView(Ui.text(activity, "⚠️ Threat check: " + c.threat.name().toLowerCase(Locale.ROOT).replace('_', ' '), 13.5f, Ui.RED, true));
            box.addView(Ui.body(activity, c.explanation));
        } else {
            box.addView(Ui.text(activity, "Threat and self-harm check: nothing found", 12.5f, Ui.MUTED, true));
        }
        for (String n : c.guardNotes) box.addView(Ui.note(activity, n));
        box.addView(Ui.note(activity, "Checked by: " + c.source.label()
                + (o.result.modelNote.isEmpty() ? "" : " (" + o.result.modelNote + ")")
                + (c.status == dev.saathi.safety.SafetyTypes.Status.NEEDS_REVIEW ? " • not sure — worth asking an adult" : "")
                + (o.decision.event != null ? " • saved to Safety alerts" : "")));
        card.addView(box, Math.max(0, card.getChildCount() - 2));
    }

    private void showUrlResult(UrlAnalysisResult r) {
        CheckVerdict v;
        switch (r.getVerdict()) {
            case WARNING_SIGNS: v = CheckVerdict.WARNING_SIGNS; break;
            case BE_CAREFUL: v = CheckVerdict.BE_CAREFUL; break;
            case NO_WARNING_SIGNS_FOUND: v = CheckVerdict.LOOKS_OKAY; break;
            default: v = CheckVerdict.CANNOT_TELL; break;
        }
        List<String[]> signs = new ArrayList<>();
        for (UrlStructuralIndicator i : r.getLocalIndicators()) signs.add(new String[]{i.getName(), i.getDescription(), i.getEvidenceExcerpt()});
        LinearLayout card = resultCard(v, r.getVerdict().getLabel(), r.getSummary(), signs, r.getWhyItMatters(), r.getNextSteps());

        dev.saathi.shield.url.DomainTrust trust = dev.saathi.shield.url.DomainTrust.evaluate(r, dev.saathi.shield.url.OfficialDomainRegistry.bundled());
        TextView tr = Ui.text(activity, trustLabel(trust), 12.5f,
                trust.outcome == dev.saathi.shield.url.DomainTrust.Outcome.RECOGNISED_OFFICIAL || trust.outcome == dev.saathi.shield.url.DomainTrust.Outcome.OFFICIALLY_LINKED_LEGACY ? Ui.GREEN
                        : trust.outcome == dev.saathi.shield.url.DomainTrust.Outcome.UNKNOWN ? Ui.MUTED : Ui.RED, true);
        tr.setPadding(0, dp(10), 0, 0);
        card.addView(tr);
        card.addView(Ui.note(activity, trust.reason));

        // Online reputation is shown separately from the on-phone findings.
        TextView online = Ui.text(activity, "Online safety list: " + r.getStatus().getTitle(), 12.5f, Ui.INK, true);
        online.setPadding(0, dp(10), 0, 0);
        card.addView(online);
        card.addView(Ui.body(activity, r.getLiveCheckNote()));
        card.addView(Ui.note(activity, "ℹ️ " + r.getLimitations()));

        ParsedUrl p = r.getParsedUrl();
        if (p.isValid()) {
            StringBuilder d = new StringBuilder();
            d.append("Website: ").append(p.getDisplayHost());
            if (!p.getUnicodeHost().equals(p.getAsciiHost())) d.append("\nPunycode form: ").append(p.getAsciiHost());
            d.append("\nScheme: ").append(p.getScheme()).append(p.isSchemeExplicit() ? "" : " (assumed)");
            if (p.getPort() > 0) d.append("\nPort: ").append(p.getPort());
            d.append("\nPath: ").append(clip(p.getPath(), 120));
            if (!p.getQuery().isEmpty()) d.append("\nQuery: ").append(p.getQuery().length()).append(" characters (not shown, may contain private data)");
            addDetails(card, "Address parts", d.toString());
        }
        finishResult(card, FindingSet.fromUrl(r), null, r.getStatus() == ReputationStatus.THREAT_MATCH);
        List<String> ids = new ArrayList<>();
        for (UrlStructuralIndicator i : r.getLocalIndicators()) ids.add(i.getId());
        record("LINK", "url-heuristics+" + r.getStatus().name(), r.getVerdict().name(), r.getLocalIndicators().size(), ids);
    }

    private static String trustLabel(dev.saathi.shield.url.DomainTrust t) {
        switch (t.outcome) {
            case RECOGNISED_OFFICIAL: return "Recognised official domain" + (t.organisation != null ? " (" + t.organisation + ")" : "");
            case OFFICIALLY_LINKED_LEGACY: return "Officially linked legacy domain" + (t.organisation != null ? " (" + t.organisation + ")" : "");
            case SUSPECTED_SPOOF: return "Suspected fake site" + (t.organisation != null ? " pretending to be " + t.organisation : "");
            case KNOWN_HARMFUL: return "Known harmful site";
            case UNAVAILABLE: return "Site check unavailable";
            default: return "Unknown site";
        }
    }

    // ---------------------------------------------------------------------------------------- file

    public void checkFileUri(Uri uri) {
        if (uri == null) return;
        if (mode != MODE_FILE) setMode(MODE_FILE);
        cancelRunning();
        final int gen = ++generation;
        final CancellationToken token = new CancellationToken();
        fileToken = token;
        String name = queryName(uri);
        long size = querySize(uri);
        final ProgressBar[] bar = new ProgressBar[1];
        final TextView[] stageView = new TextView[1];
        showProgress("Checking " + name + (size >= 0 ? " (" + Ui.formatSize(size) + ")" : ""), token);
        bar[0] = (ProgressBar) resultBox.findViewWithTag("bar");
        stageView[0] = (TextView) resultBox.findViewWithTag("stage");
        worker.execute(() -> {
            ApkAnalysisResult r;
            try (InputStream in = activity.getContentResolver().openInputStream(uri)) {
                if (in == null) throw new java.io.FileNotFoundException();
                r = svc.apkAnalyzer.analyze(in, name, size, activity.getCacheDir(), token, (stage, done, total) ->
                        activity.runOnUiThread(() -> {
                            if (gen != generation) return;
                            if (stageView[0] != null) stageView[0].setText(stage + (total > 0 && stage.startsWith("Reading")
                                    ? " — " + Ui.formatSize(done) + " of " + Ui.formatSize(total) : ""));
                            if (bar[0] != null) {
                                if (total > 0) {
                                    bar[0].setIndeterminate(false);
                                    bar[0].setMax(1000);
                                    bar[0].setProgress((int) Math.min(1000, done * 1000 / Math.max(1, total)));
                                } else {
                                    bar[0].setIndeterminate(true);
                                }
                            }
                        }));
            } catch (SecurityException e) {
                r = null;
                activity.runOnUiThread(() -> { if (gen == generation) showError("Android didn't allow Saathi to read that file. Try choosing it again with the file picker."); });
                return;
            } catch (java.io.FileNotFoundException e) {
                activity.runOnUiThread(() -> { if (gen == generation) showError("That file couldn't be found. It may have been moved or deleted."); });
                return;
            } catch (Exception e) {
                activity.runOnUiThread(() -> { if (gen == generation) showError("The file couldn't be read."); });
                return;
            }
            final ApkAnalysisResult res = r;
            activity.runOnUiThread(() -> { if (gen == generation) showApkResult(res); });
        });
    }

    private void showApkResult(ApkAnalysisResult r) {
        CheckVerdict v;
        switch (r.verdict) {
            case KNOWN_THREAT_MATCH: v = CheckVerdict.WARNING_SIGNS; break;
            case STATIC_INDICATORS_FOUND:
                v = r.highestSeverity().getWeight() >= dev.saathi.model.ThreatSeverity.HIGH.getWeight() ? CheckVerdict.WARNING_SIGNS : CheckVerdict.BE_CAREFUL;
                break;
            case NO_SUSPICIOUS_STATIC_INDICATORS: v = CheckVerdict.LOOKS_OKAY; break;
            default: v = CheckVerdict.CANNOT_TELL; break;
        }
        List<String[]> signs = new ArrayList<>();
        for (ApkIndicator i : r.indicators) {
            if (i.severity == dev.saathi.model.ThreatSeverity.INFO) continue;
            signs.add(new String[]{i.title, i.explanation, i.evidence});
        }
        LinearLayout card = resultCard(v, r.verdict.getLabel(), r.summary, signs, r.whyItMatters, r.nextSteps);
        card.addView(Ui.note(activity, "File: " + r.fileName + " • " + Ui.formatSize(r.sizeBytes)));
        card.addView(Ui.note(activity, "ℹ️ " + r.limitations));
        if (r.status != AnalysisStatus.CANCELLED) addDetails(card, "Technical details (for an adult)", technical(r));
        finishResult(card, FindingSet.fromApk(r), null, false);
        List<String> ids = new ArrayList<>();
        for (ApkIndicator i : r.indicators) ids.add(i.id);
        record("FILE", r.analyzerVersion + "+" + r.status.name(), r.verdict.name(), signs.size(), ids);
    }

    private String technical(ApkAnalysisResult r) {
        StringBuilder b = new StringBuilder();
        b.append("Status: ").append(r.status.getDescription());
        if (r.sha256 != null) b.append("\nSHA-256: ").append(r.sha256);
        if (r.manifest != null) {
            b.append("\nPackage: ").append(r.manifest.packageName);
            b.append("\nVersion: ").append(r.manifest.versionName != null ? r.manifest.versionName : "not stated")
                    .append(r.manifest.versionCode != null ? " (code " + r.manifest.versionCode + ")" : "");
            b.append("\nMin / target Android SDK: ").append(r.manifest.minSdk != null ? r.manifest.minSdk : "not stated")
                    .append(" / ").append(r.manifest.targetSdk != null ? r.manifest.targetSdk : "not stated");
            b.append("\nComponents: ").append(r.manifest.activities).append(" screens, ").append(r.manifest.services).append(" services, ")
                    .append(r.manifest.receivers).append(" receivers, ").append(r.manifest.providers).append(" providers");
            b.append("\nPermissions (").append(r.manifest.permissions.size()).append("):");
            for (String p : r.manifest.permissions) b.append("\n  • ").append(p);
        } else if (r.manifestError != null) {
            b.append("\nManifest: ").append(r.manifestError);
        }
        if (r.signing != null) {
            b.append("\nSigning schemes found: ").append(r.signing.schemes());
            for (SigningInfo.Cert c : r.signing.certificates) {
                b.append("\nCertificate: ").append(c.subject).append("\n  SHA-256: ").append(c.sha256)
                        .append(c.androidDebug ? "\n  (Android debug key)" : "").append(c.expired ? "\n  (expired)" : "");
            }
        }
        if (r.inventory != null) {
            b.append("\nArchive: ").append(r.inventory.totalEntries).append(" entries, ").append(r.inventory.dexFiles).append(" code (DEX) files, ")
                    .append(r.inventory.nativeLibs).append(" native libraries");
            if (!r.inventory.abis.isEmpty()) b.append(" ").append(r.inventory.abis);
        }
        if (r.dex != null) {
            b.append("\nCode: ").append(r.dex.classDefs).append(" classes, ").append(r.dex.strings).append(" strings inspected");
            if (!r.dex.urls.isEmpty()) {
                b.append("\nWeb addresses found in code (not opened):");
                int n = 0;
                for (String u : r.dex.urls) {
                    if (n++ == 8) { b.append("\n  …"); break; }
                    b.append("\n  • ").append(clip(u, 80));
                }
            }
        }
        b.append("\nThreat database: ").append(r.hashLookup == dev.saathi.shield.apk.FileHashReputationProvider.Outcome.NOT_CHECKED ? "not checked (not configured)" : r.hashLookup.name());
        if (!r.notExtracted.isEmpty()) {
            b.append("\nNot checked by this version:");
            for (String s : r.notExtracted) b.append("\n  • ").append(s);
        }
        b.append("\nAnalyzer: ").append(r.analyzerVersion).append(" in ").append(r.durationMs).append(" ms");
        return b.toString();
    }

    // ---------------------------------------------------------------------------------------- shared result UI

    private LinearLayout resultCard(CheckVerdict v, String label, String summary, List<String[]> signs, String why, List<String> steps) {
        resultBox.removeAllViews();
        LinearLayout card = Ui.vcard(activity);
        card.addView(Ui.badge(activity, v.getBadgeEmoji() + "  " + label, Color.parseColor(v.getTextColorHex()), Color.parseColor(v.getBgColorHex())));
        TextView s = Ui.text(activity, summary, 15f, Ui.INK, true);
        s.setPadding(0, 0, 0, dp(8));
        card.addView(s);
        if (!signs.isEmpty()) {
            card.addView(Ui.text(activity, "Warning signs found:", 12.5f, Ui.AMBER, true));
            for (String[] sg : signs) {
                card.addView(Ui.text(activity, "•  " + sg[0], 13f, Color.parseColor("#222222"), true));
                card.addView(Ui.body(activity, "   " + sg[1]));
                if (sg[2] != null && !sg[2].isEmpty()) {
                    TextView ev = Ui.text(activity, "   Seen: " + clip(sg[2], 140), 12f, Color.parseColor("#555555"), false);
                    ev.setTypeface(Typeface.create("sans-serif-medium", Typeface.ITALIC));
                    card.addView(ev);
                }
            }
        }
        if (why != null && !why.isEmpty()) {
            TextView wt = Ui.text(activity, "Why this matters:", 12.5f, Ui.INK, true);
            wt.setPadding(0, dp(10), 0, 0);
            card.addView(wt);
            card.addView(Ui.body(activity, why));
        }
        if (steps != null && !steps.isEmpty()) {
            TextView st = Ui.text(activity, "What you can do now:", 12.5f, Ui.GREEN, true);
            st.setPadding(0, dp(10), 0, 0);
            card.addView(st);
            for (String step : steps) card.addView(Ui.body(activity, "✔  " + step));
        }
        return card;
    }

    private void finishResult(LinearLayout card, FindingSet fs, String submitted, boolean threatMatch) {
        lastFindings = fs;
        lastSubmittedText = submitted;
        lastThreatMatch = threatMatch;
        card.addView(buildExplanationSection());
        card.addView(Ui.danger(activity, "🚨  Ask a trusted adult for help", v -> { if (host != null) host.showSosFlow(); }));
        resultBox.addView(card);
        root.post(() -> root.smoothScrollTo(0, resultBox.getTop()));
    }

    private void addDetails(LinearLayout card, String title, String body) {
        TextView toggle = Ui.text(activity, "▸ " + title, 12.5f, Ui.MUTED, true);
        toggle.setPadding(0, dp(10), 0, dp(4));
        TextView details = Ui.text(activity, body, 11.5f, Color.parseColor("#444444"), false);
        details.setTypeface(Typeface.MONOSPACE);
        details.setTextIsSelectable(true);
        details.setVisibility(View.GONE);
        toggle.setOnClickListener(v -> {
            boolean show = details.getVisibility() != View.VISIBLE;
            details.setVisibility(show ? View.VISIBLE : View.GONE);
            toggle.setText((show ? "▾ " : "▸ ") + title);
        });
        card.addView(toggle);
        card.addView(details);
    }

    // ---------------------------------------------------------------------------------------- explanation (model or rules)

    private View buildExplanationSection() {
        LinearLayout box = new LinearLayout(activity);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setBackground(Ui.card(activity, Color.parseColor("#F9F8F6"), Color.parseColor("#E4DFD7"), 12));
        box.setPadding(dp(14), dp(12), dp(14), dp(12));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(12);
        lp.bottomMargin = dp(6);
        box.setLayoutParams(lp);

        box.addView(Ui.text(activity, "✨ Explain this to me", 13.5f, Ui.INK, true));
        ModelState st = svc.model.getState();
        String status = st == ModelState.READY ? "On-device AI model ready (" + svc.model.getModelId() + ")"
                : st.getDescription() + (st == ModelState.UNAVAILABLE ? " — you'll get rules-based guidance" : "");
        box.addView(Ui.note(activity, status));

        TextView out = Ui.body(activity, "");
        out.setVisibility(View.GONE);
        TextView source = Ui.note(activity, "");
        source.setVisibility(View.GONE);
        EditText question = new EditText(activity);
        question.setHint("Ask a question about this result (optional)");
        question.setTextSize(13f);
        question.setFilters(new InputFilter[]{new InputFilter.LengthFilter(300)});
        Button go = Ui.secondary(activity, "Explain", null);
        Button stop = Ui.secondary(activity, "Stop", null);
        stop.setVisibility(View.GONE);
        go.setOnClickListener(v -> {
            FindingSet fs = lastFindings;
            if (fs == null) return;
            if (aiToken != null) aiToken.cancel();
            CancellationToken t = new CancellationToken();
            aiToken = t;
            go.setEnabled(false);
            stop.setVisibility(View.VISIBLE);
            out.setVisibility(View.VISIBLE);
            out.setText(svc.model.getState() == ModelState.READY ? "The on-device model is writing…" : "Preparing guidance…");
            source.setVisibility(View.GONE);
            String q = question.getText() == null ? "" : question.getText().toString();
            String lang = svc.repo.getLanguage();
            String submitted = lastSubmittedText;
            boolean threat = lastThreatMatch;
            aiWorker.execute(() -> {
                ExplanationService.Outcome o = svc.explanations.explain(fs, submitted, q, lang, threat, t);
                activity.runOnUiThread(() -> {
                    go.setEnabled(true);
                    stop.setVisibility(View.GONE);
                    if (o.cancelled) {
                        out.setText("Stopped.");
                        return;
                    }
                    out.setText(formatExplanation(o.explanation, fs));
                    source.setVisibility(View.VISIBLE);
                    source.setText(o.explanation.sourceLabel() + (o.note.isEmpty() ? "" : "\n" + o.note)
                            + "\nThis explanation can't change the result above and doesn't contact anyone.");
                });
            });
        });
        stop.setOnClickListener(v -> { if (aiToken != null) aiToken.cancel(); });
        box.addView(question);
        LinearLayout r = Ui.row(activity);
        LinearLayout.LayoutParams g = Ui.weight(2f);
        g.rightMargin = dp(8);
        r.addView(go, g);
        r.addView(stop, Ui.weight(1f));
        box.addView(r);
        box.addView(out);
        box.addView(source);
        return box;
    }

    private static String formatExplanation(SafetyExplanation e, FindingSet fs) {
        StringBuilder b = new StringBuilder(e.summary);
        if (!e.evidenceRefs.isEmpty()) {
            b.append("\n\nBased on:");
            for (String id : e.evidenceRefs) {
                Finding f = fs.byId(id);
                if (f != null) b.append("\n•  ").append(f.title);
            }
        }
        b.append("\n\nNext steps:");
        for (String s : e.nextSteps) b.append("\n✔  ").append(s);
        if (!e.limitations.isEmpty()) b.append("\n\n").append(e.limitations);
        return b.toString();
    }

    // ---------------------------------------------------------------------------------------- misc

    private void showProgress(String label, CancellationToken cancel) {
        resultBox.removeAllViews();
        LinearLayout c = Ui.vcard(activity);
        TextView t = Ui.text(activity, label, 14f, Ui.INK, true);
        c.addView(t);
        ProgressBar bar = new ProgressBar(activity, null, android.R.attr.progressBarStyleHorizontal);
        bar.setIndeterminate(true);
        bar.setTag("bar");
        c.addView(bar);
        TextView stage = Ui.note(activity, "");
        stage.setTag("stage");
        c.addView(stage);
        if (cancel != null) {
            c.addView(Ui.secondary(activity, "Cancel", v -> {
                cancel.cancel();
                stage.setText("Cancelling…");
            }));
        }
        resultBox.addView(c);
    }

    private void showError(String msg) {
        resultBox.removeAllViews();
        LinearLayout c = Ui.vcard(activity);
        c.addView(Ui.badge(activity, CheckVerdict.CANNOT_TELL.getBadgeEmoji() + "  " + CheckVerdict.CANNOT_TELL.getLabel(), Ui.MUTED, Color.parseColor("#F0F0EE")));
        c.addView(Ui.body(activity, msg));
        resultBox.addView(c);
    }

    private void record(String type, String engine, String verdict, int signCount, List<String> indicatorIds) {
        String summary = type.charAt(0) + type.substring(1).toLowerCase(Locale.ROOT) + " check: "
                + (signCount == 0 ? "no warning signs" : signCount + " warning sign" + (signCount == 1 ? "" : "s"));
        svc.repo.recordCheck(new CheckHistoryRecord(UUID.randomUUID().toString(), type, System.currentTimeMillis(), engine, verdict,
                summary, String.join(",", indicatorIds), "EVALUATED"));
    }

    private static List<String> idsOfMessage(MessageAnalysisResult r) {
        List<String> ids = new ArrayList<>();
        for (SafetyIndicator i : r.getMatchedIndicators()) ids.add(i.getId());
        return ids;
    }

    private String queryName(Uri uri) {
        try (Cursor c = activity.getContentResolver().query(uri, new String[]{OpenableColumns.DISPLAY_NAME}, null, null, null)) {
            if (c != null && c.moveToFirst() && !c.isNull(0)) return c.getString(0);
        } catch (RuntimeException ignored) {
            // provider without metadata
        }
        String last = uri.getLastPathSegment();
        return last == null ? "selected file" : last;
    }

    private long querySize(Uri uri) {
        try (Cursor c = activity.getContentResolver().query(uri, new String[]{OpenableColumns.SIZE}, null, null, null)) {
            if (c != null && c.moveToFirst() && !c.isNull(0)) return c.getLong(0);
        } catch (RuntimeException ignored) {
            // size unknown
        }
        return -1;
    }

    private static String clip(String s, int n) {
        return s == null ? "" : (s.length() <= n ? s : s.substring(0, n) + "…");
    }

    public void onDestroy() {
        cancelRunning();
        worker.shutdownNow();
        aiWorker.shutdownNow();
    }
}
