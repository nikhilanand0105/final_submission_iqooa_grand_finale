package dev.guardianai.kids;

import android.content.Context;
import android.content.SharedPreferences;

import dev.guardianai.ai.explain.ExplanationService;
import dev.guardianai.family.BackendClient;
import dev.guardianai.family.PairingService;
import dev.guardianai.help.HelpRequestService;
import dev.guardianai.kids.ai.GemmaModelManager;
import dev.guardianai.kids.storage.KidsLocalRepository;
import dev.guardianai.kids.storage.LessonRepository;
import dev.guardianai.net.FirebaseAnonymousAuth;
import dev.guardianai.net.HttpTransport;
import dev.guardianai.net.UrlConnectionTransport;
import dev.guardianai.sense.analyzer.MessageSafetyAnalyzer;
import dev.guardianai.sense.analyzer.RuleBasedMessageSafetyAnalyzer;
import dev.guardianai.shield.apk.ApkStaticAnalyzer;
import dev.guardianai.shield.apk.DefaultApkStaticAnalyzer;
import dev.guardianai.shield.url.BackendUrlReputationProvider;
import dev.guardianai.shield.url.UrlReputationProvider;
import dev.guardianai.shield.url.UrlSafetyAnalyzer;

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
        final SharedPreferences authPrefs = app.getSharedPreferences("guardianai_auth", Context.MODE_PRIVATE);
        auth = new FirebaseAnonymousAuth(BuildConfig.FIREBASE_WEB_API_KEY, http, new FirebaseAnonymousAuth.Store() {
            @Override public String get(String k) { return authPrefs.getString(k, null); }
            @Override public void put(String k, String v) { authPrefs.edit().putString(k, v).apply(); }
        });
        boolean configured = auth.isConfigured() && BuildConfig.GUARDIANAI_BACKEND_URL.startsWith("https://");
        backend = new BackendClient(configured ? BuildConfig.GUARDIANAI_BACKEND_URL : "", auth, http, BackendClient.DEFAULT_TIMEOUT_MS);
        UrlReputationProvider urlProvider = configured
                ? new BackendUrlReputationProvider(BuildConfig.GUARDIANAI_BACKEND_URL, auth, http, BackendUrlReputationProvider.DEFAULT_TIMEOUT_MS)
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
