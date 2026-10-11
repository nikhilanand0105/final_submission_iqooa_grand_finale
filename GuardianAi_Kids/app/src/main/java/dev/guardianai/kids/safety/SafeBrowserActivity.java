package dev.guardianai.kids.safety;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.view.Gravity;
import android.view.KeyEvent;
import android.view.View;
import android.view.inputmethod.EditorInfo;
import android.webkit.SafeBrowsingResponse;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;

import dev.guardianai.kids.KidsServices;
import dev.guardianai.kids.ui.MainActivity;
import dev.guardianai.kids.ui.Ui;
import dev.guardianai.safety.FlagEngine;
import dev.guardianai.safety.SafetyClassification;
import dev.guardianai.safety.SafetyEvent;
import dev.guardianai.safety.SafetyTypes;
import dev.guardianai.safety.WebSafety;
import dev.guardianai.shield.url.DomainTrust;
import dev.guardianai.shield.url.OfficialDomainRegistry;
import dev.guardianai.shield.url.ParsedUrl;
import dev.guardianai.shield.url.UrlAnalysisResult;
import dev.guardianai.shield.url.UrlParser;

import java.util.Collections;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * GuardianAi Safe Browser: a WebView whose every main-frame navigation (including redirects) is checked before it loads,
 * whose search queries and visible page text go through the shared Gemma-first pipeline, and which also uses the
 * system WebView's Safe Browsing. Only websites opened here get this protection. No browsing history is saved;
 * only safety events (host name, never the full address) are stored.
 */
public class SafeBrowserActivity extends Activity {

    private static final String TAG = "SafeBrowserActivity";
    public static final String EXTRA_URL = "url";
    private static final int MAX_PAGE_TEXT = 4000;

    private WebView web;
    private EditText address;
    private ProgressBar progress;
    private FrameLayout interstitialHost;
    private TextView note;
    private KidsServices svc;
    private SafetyEventProcessor processor;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private String approvedUrl; // the one URL the child chose to continue to after a warning
    private int navGeneration;

    @SuppressLint("SetJavaScriptEnabled")
    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        svc = KidsServices.get(this);
        processor = SafetyEventProcessor.get(this);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Ui.BG);
        LinearLayout bar = Ui.row(this);
        bar.setPadding(Ui.dp(this, 8), Ui.dp(this, 8), Ui.dp(this, 8), Ui.dp(this, 4));
        Button close = new Button(this);
        close.setText("✕");
        close.setOnClickListener(v -> finish());
        bar.addView(close);
        address = new EditText(this);
        address.setSingleLine(true);
        address.setHint("Search or type a web address");
        address.setImeOptions(EditorInfo.IME_ACTION_GO);
        address.setOnEditorActionListener((v, id, ev) -> {
            go(address.getText().toString());
            return true;
        });
        bar.addView(address, Ui.weight(1f));
        Button go = new Button(this);
        go.setText("Go");
        go.setOnClickListener(v -> go(address.getText().toString()));
        bar.addView(go);
        root.addView(bar);
        note = Ui.note(this, "🛡️ GuardianAi Safe Browser checks websites before they open. Other browsers aren't checked by GuardianAi.");
        note.setPadding(Ui.dp(this, 12), 0, Ui.dp(this, 12), Ui.dp(this, 4));
        root.addView(note);
        progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        progress.setIndeterminate(true);
        progress.setVisibility(View.GONE);
        root.addView(progress);

        FrameLayout stack = new FrameLayout(this);
        web = new WebView(this);
        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setAllowFileAccess(false);
        s.setAllowContentAccess(false);
        s.setGeolocationEnabled(false);
        s.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        s.setSupportMultipleWindows(false);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) s.setSafeBrowsingEnabled(true);
        web.setWebViewClient(new Client());
        stack.addView(web);
        interstitialHost = new FrameLayout(this);
        interstitialHost.setVisibility(View.GONE);
        stack.addView(interstitialHost);
        root.addView(stack, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));
        setContentView(root);

        String start = getIntent().getStringExtra(EXTRA_URL);
        if (start != null && !start.isEmpty()) go(start);
    }

    /** Turns typed text into a URL (or a search) and checks it before loading. */
    private void go(String typed) {
        String t = typed == null ? "" : typed.trim();
        if (t.isEmpty()) return;
        String url;
        ParsedUrl p = new UrlParser().parse(t);
        if (!t.contains(" ") && p.isValid() && p.getHostKind() != ParsedUrl.HostKind.NONE) url = p.isSchemeExplicit() ? t : "https://" + t;
        else url = "https://duckduckgo.com/?q=" + Uri.encode(t);
        checkThenLoad(url);
    }

    private void checkThenLoad(String url) {
        final int gen = ++navGeneration;
        hideInterstitial();
        progress.setVisibility(View.VISIBLE);
        address.setText(url);
        boolean live = svc.repo.isOnlineLinkCheckAllowed();
        worker.execute(() -> {
            UrlAnalysisResult ua = svc.urlAnalyzer.analyze(url, live);
            DomainTrust trust = DomainTrust.evaluate(ua, OfficialDomainRegistry.bundled());
            WebSafety.Decision d = WebSafety.forUrl(trust);
            String host = ua.getParsedUrl().isValid() ? ua.getParsedUrl().getDisplayHost() : "";
            Log.i(TAG, "NavDecision [stage=URL_CHECK, host=" + host + ", outcome=" + trust.outcome
                    + ", action=" + d.action + ", reason=" + d.reason + ", note=" + trust.reason + "]");
            if (d.action != WebSafety.Action.ALLOW) recordWebsiteEvent(trust, host);
            // Search queries are the child's own words: run them through the shared pipeline.
            WebSafety.Decision searchDecision = null;
            String q = WebSafety.searchQuery(url);
            if (q != null && d.action == WebSafety.Action.ALLOW) {
                SafetyEventProcessor.Outcome o = processor.analyzeNow(SafetyTypes.SourceType.BROWSER_SEARCH, host, q, false);
                searchDecision = WebSafety.forContent(o.result.classification);
                Log.i(TAG, "NavDecision [stage=SEARCH_QUERY, host=" + host + ", action=" + searchDecision.action + ", reason=" + searchDecision.reason + "]");
            }
            final WebSafety.Decision fd = searchDecision != null && searchDecision.action != WebSafety.Action.ALLOW ? searchDecision : d;
            runOnUiThread(() -> {
                if (gen != navGeneration || isFinishing()) return;
                progress.setVisibility(View.GONE);
                if (fd.action == WebSafety.Action.ALLOW) {
                    approvedUrl = url;
                    web.loadUrl(url);
                } else {
                    showInterstitial(fd, url);
                }
            });
        });
    }

    private void recordWebsiteEvent(DomainTrust t, String host) {
        SafetyTypes.WebsiteConcern wc = t.outcome == DomainTrust.Outcome.KNOWN_HARMFUL ? SafetyTypes.WebsiteConcern.KNOWN_HARMFUL
                : t.outcome == DomainTrust.Outcome.SUSPECTED_SPOOF ? SafetyTypes.WebsiteConcern.SUSPECTED_SPOOF : SafetyTypes.WebsiteConcern.UNKNOWN;
        SafetyClassification c = new SafetyClassification(SafetyTypes.SourceType.BROWSER_URL, SafetyTypes.ThreatKind.NONE, SafetyTypes.Severity.NONE,
                SafetyTypes.SelfHarmKind.NONE, SafetyTypes.Severity.NONE, SafetyTypes.ScamKind.NONE, wc, SafetyTypes.AgeConcern.NONE,
                SafetyTypes.Confidence.MEDIUM, Collections.singletonList(host), t.reason,
                Collections.singletonList("Don't type passwords or OTPs on this site"), SafetyTypes.Status.COMPLETE,
                SafetyTypes.Source.TECHNICAL_CHECKS, null, null);
        long now = System.currentTimeMillis();
        String key = FlagEngine.dedupeKey(SafetyTypes.SourceType.BROWSER_URL, host, t.outcome.name());
        FlagEngine.Decision d = FlagEngine.decide(c, "NOT_USED", SafetyTypes.SourceType.BROWSER_URL, host, key,
                dev.guardianai.kids.storage.SafetyEventStore.get(this).recentByKey(key, now), now);
        if (d.event != null) dev.guardianai.kids.storage.SafetyEventStore.get(this).save(d.event.withAlert(SafetyEvent.Alert.SHOWN_IN_APP, now));
    }

    private final class Client extends WebViewClient {
        @Override
        public boolean shouldOverrideUrlLoading(WebView v, WebResourceRequest r) {
            if (!r.isForMainFrame()) return false;
            String url = r.getUrl().toString();
            String scheme = r.getUrl().getScheme();
            Log.i(TAG, "NavDecision [stage=REDIRECT_INTERCEPT, scheme=" + scheme + ", url=" + sanitizeUrl(url) + "]");
            if (!"https".equals(scheme) && !"http".equals(scheme)) {
                // intent:, market:, file:, javascript: etc. are not opened from the Safe Browser
                note.setText("GuardianAi blocked a link that tried to open another app or file.");
                return true;
            }
            if (url.equals(approvedUrl)) return false;
            checkThenLoad(url); // every hop, including server redirects, is checked before it loads
            return true;
        }

        @Override
        public void onPageFinished(WebView v, String url) {
            approvedUrl = null;
            address.setText(url);
            final int gen = navGeneration;
            v.evaluateJavascript("(function(){try{return (document.body&&document.body.innerText||'').slice(0," + MAX_PAGE_TEXT + ");}catch(e){return ''}})()",
                    raw -> analysePage(gen, url, unquote(raw)));
        }

        @Override
        public void onSafeBrowsingHit(WebView v, WebResourceRequest r, int threatType, SafeBrowsingResponse cb) {
            if (Build.VERSION.SDK_INT < 27) return;
            String host = r.getUrl().getHost() == null ? "" : r.getUrl().getHost();
            Log.w(TAG, "NavDecision [stage=NATIVE_SAFE_BROWSING, host=" + host + ", threatType=" + threatType + "]");
            DomainTrust t = DomainTrust.knownHarmful("Android WebView Safe Browsing");
            worker.execute(() -> recordWebsiteEvent(t, host));
            cb.backToSafety(true);
            runOnUiThread(() -> showInterstitial(WebSafety.forUrl(t), null));
        }

        @Override
        public void onReceivedError(WebView v, WebResourceRequest r, android.webkit.WebResourceError error) {
            if (r.isForMainFrame() && Build.VERSION.SDK_INT >= 23) {
                Log.w(TAG, "NavDecision [stage=NETWORK_LOAD_ERROR, url=" + sanitizeUrl(r.getUrl().toString())
                        + ", err=" + error.getDescription() + "]");
            }
        }
    }

    /** Page text is analysed after load; the warning appears over the page if the policy requires it. */
    private void analysePage(int gen, String url, String text) {
        if (text == null || text.trim().length() < 40) return; // nothing readable: no fabricated verdict
        String host = Uri.parse(url).getHost() == null ? "" : Uri.parse(url).getHost();
        worker.execute(() -> {
            SafetyEventProcessor.Outcome o = processor.analyzeNow(SafetyTypes.SourceType.BROWSER_PAGE, host, text, false);
            WebSafety.Decision d = WebSafety.forContent(o.result.classification);
            Log.i(TAG, "NavDecision [stage=PAGE_CONTENT_ANALYSIS, host=" + host + ", action=" + d.action + ", reason=" + d.reason + "]");
            if (d.action == WebSafety.Action.ALLOW) return;
            runOnUiThread(() -> {
                if (gen != navGeneration || isFinishing()) return;
                if (!d.canContinue) web.loadUrl("about:blank");
                showInterstitial(d, null);
            });
        });
    }

    static String sanitizeUrl(String url) {
        if (url == null) return "";
        try {
            Uri u = Uri.parse(url);
            return u.getScheme() + "://" + u.getHost() + (u.getPath() != null ? u.getPath() : "");
        } catch (Exception e) {
            return "sanitized";
        }
    }

    private void showInterstitial(WebSafety.Decision d, String continueUrl) {
        interstitialHost.removeAllViews();
        ScrollView sv = new ScrollView(this);
        sv.setBackgroundColor(Color.parseColor(d.reason == WebSafety.Reason.SELF_HARM_SUPPORT ? "#EAF3ED" : "#FFF6E5"));
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(Ui.dp(this, 24), Ui.dp(this, 40), Ui.dp(this, 24), Ui.dp(this, 24));
        sv.addView(box);
        String emoji = d.reason == WebSafety.Reason.SELF_HARM_SUPPORT ? "💚" : d.action == WebSafety.Action.BLOCK ? "🛑" : "⚠️";
        box.addView(Ui.text(this, emoji, 48f, Ui.INK, false));
        box.addView(Ui.text(this, d.title, 20f, Ui.INK, true));
        box.addView(Ui.body(this, d.message));
        if (d.reason == WebSafety.Reason.SELF_HARM_SUPPORT) {
            box.addView(Ui.primary(this, "Talk to a trusted adult", v -> startActivity(new Intent(this, MainActivity.class)
                    .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP).putExtra(MainActivity.EXTRA_OPEN_HELP, true))));
            box.addView(Ui.secondary(this, "📞 " + SupportResources.TELE_MANAS_LABEL, v -> dial(SupportResources.TELE_MANAS_NUMBER)));
            box.addView(Ui.secondary(this, "📞 " + SupportResources.EMERGENCY_LABEL, v -> dial(SupportResources.EMERGENCY_NUMBER)));
            box.addView(Ui.note(this, SupportResources.SOURCE_NOTE));
        }
        box.addView(Ui.secondary(this, "← Go back", v -> {
            hideInterstitial();
            if (web.canGoBack()) web.goBack();
            else web.loadUrl("about:blank");
        }));
        if (d.canContinue && continueUrl != null) {
            box.addView(Ui.secondary(this, "Continue anyway", v -> {
                hideInterstitial();
                approvedUrl = continueUrl;
                web.loadUrl(continueUrl);
            }));
        } else if (d.canContinue) {
            box.addView(Ui.secondary(this, "Stay on this page", v -> hideInterstitial()));
        }
        box.addView(Ui.note(this, "GuardianAi checked this on your phone. Warnings can be wrong sometimes; ask a trusted adult if unsure."));
        interstitialHost.addView(sv);
        interstitialHost.setVisibility(View.VISIBLE);
    }

    private void hideInterstitial() {
        interstitialHost.setVisibility(View.GONE);
        interstitialHost.removeAllViews();
    }

    private void dial(String n) {
        try {
            startActivity(new Intent(Intent.ACTION_DIAL, Uri.parse("tel:" + n)));
        } catch (ActivityNotFoundException ignored) {
            // device without a dialer
        }
    }

    static String unquote(String js) {
        if (js == null || js.equals("null") || js.length() < 2) return "";
        try {
            java.util.Map<String, Object> o = dev.guardianai.util.Json.parseObject("{\"v\":" + js + "}");
            String v = dev.guardianai.util.Json.str(o, "v");
            return v == null ? "" : v;
        } catch (dev.guardianai.util.Json.ParseException e) {
            return "";
        }
    }

    @Override
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        if (keyCode == KeyEvent.KEYCODE_BACK) {
            if (interstitialHost.getVisibility() == View.VISIBLE) {
                hideInterstitial();
                if (web.canGoBack()) web.goBack();
                return true;
            }
            if (web.canGoBack()) {
                web.goBack();
                return true;
            }
        }
        return super.onKeyDown(keyCode, event);
    }

    @Override
    protected void onDestroy() {
        navGeneration++;
        worker.shutdownNow();
        web.stopLoading();
        web.destroy();
        super.onDestroy();
    }
}
