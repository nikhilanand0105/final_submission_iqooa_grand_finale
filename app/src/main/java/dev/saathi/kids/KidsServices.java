package dev.saathi.kids;

import android.content.Context;
import android.content.SharedPreferences;

import dev.saathi.ai.explain.ExplanationService;
import dev.saathi.family.BackendClient;
import dev.saathi.family.PairingService;
import dev.saathi.help.HelpRequestService;
import dev.saathi.kids.ai.GemmaModelManager;
import dev.saathi.kids.storage.KidsLocalRepository;
import dev.saathi.kids.storage.LessonRepository;
import dev.saathi.net.FirebaseAnonymousAuth;
import dev.saathi.net.HttpTransport;
import dev.saathi.net.UrlConnectionTransport;
import dev.saathi.sense.analyzer.MessageSafetyAnalyzer;
import dev.saathi.sense.analyzer.RuleBasedMessageSafetyAnalyzer;
import dev.saathi.shield.apk.ApkStaticAnalyzer;
import dev.saathi.shield.apk.DefaultApkStaticAnalyzer;
import dev.saathi.shield.url.BackendUrlReputationProvider;
import dev.saathi.shield.url.UrlReputationProvider;
import dev.saathi.shield.url.UrlSafetyAnalyzer;

/**
 * Wires the real analyzers, repositories and backend clients together from BuildConfig.
 * When the backend is not configured, the network-backed services report NOT_CONFIGURED states.
 */
public final class KidsServices {

    private static volatile KidsServices instance;

    public final KidsLocalRepository repo;
    public final LessonRepository lessons;
    public final MessageSafetyAnalyzer messageAnalyzer = new RuleBasedMessageSafetyAnalyzer();
    public final UrlSafetyAnalyzer urlAnalyzer;
    public final ApkStaticAnalyzer apkAnalyzer = new DefaultApkStaticAnalyzer();
    public final GemmaModelManager model;
    public final ExplanationService explanations;
    public final FirebaseAnonymousAuth auth;
    public final BackendClient backend;
    public final PairingService pairing;
    public final HelpRequestService help;

    private KidsServices(Context ctx) {
        Context app = ctx.getApplicationContext();
        repo = KidsLocalRepository.getInstance(app);
        repo.removeLegacyDemoPreferences();
        lessons = new LessonRepository(app);
        model = GemmaModelManager.get(app);
        explanations = new ExplanationService(model);

        HttpTransport http = new UrlConnectionTransport();
        final SharedPreferences authPrefs = app.getSharedPreferences("saathi_auth", Context.MODE_PRIVATE);
        auth = new FirebaseAnonymousAuth(BuildConfig.FIREBASE_WEB_API_KEY, http, new FirebaseAnonymousAuth.Store() {
            @Override public String get(String k) { return authPrefs.getString(k, null); }
            @Override public void put(String k, String v) { authPrefs.edit().putString(k, v).apply(); }
        });
        boolean configured = auth.isConfigured() && BuildConfig.SAATHI_BACKEND_URL.startsWith("https://");
        backend = new BackendClient(configured ? BuildConfig.SAATHI_BACKEND_URL : "", auth, http, BackendClient.DEFAULT_TIMEOUT_MS);
        UrlReputationProvider urlProvider = configured
                ? new BackendUrlReputationProvider(BuildConfig.SAATHI_BACKEND_URL, auth, http, BackendUrlReputationProvider.DEFAULT_TIMEOUT_MS)
                : UrlReputationProvider.NONE;
        urlAnalyzer = new UrlSafetyAnalyzer(urlProvider);
        pairing = new PairingService(backend);
        help = new HelpRequestService(backend);
    }

    public static KidsServices get(Context ctx) {
        if (instance == null) {
            synchronized (KidsServices.class) {
                if (instance == null) instance = new KidsServices(ctx);
            }
        }
        return instance;
    }

    public boolean isBackendConfigured() {
        return backend.isConfigured();
    }
}
