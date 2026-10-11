package dev.saathi.kids.ui.screens;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.Typeface;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;

import dev.saathi.help.HelpRequest;
import dev.saathi.help.HelpRequestStatus;
import dev.saathi.kids.KidsServices;
import dev.saathi.kids.storage.model.CheckHistoryRecord;
import dev.saathi.kids.ui.Ui;
import dev.saathi.kids.ui.model.NavigationTab;
import dev.saathi.learn.LessonCatalog;

import java.util.List;
import java.util.Set;

/** Home: entry points plus summaries computed from real stored data (checks, lessons, help requests). */
public class HomeScreenController {

    public interface HomeNavigationHost {
        void switchTab(NavigationTab tab, boolean addToStack);
        void showSosFlow();
        void showLessonDetail(String lessonId);
        void openCheckMode(int modeIndex);
        void openSafetyAlerts();
        void openSafeBrowser();
    }

    private final Activity activity;
    private final HomeNavigationHost host;
    private final KidsServices svc;
    private final Runnable listener = this::render;

    private ScrollView root;
    private TextView greeting, checkStats, helpStatus, threatFlag, selfHarmFlag, protectionLine;
    private TextView featuredTitle, featuredSub, featuredState, progressText;
    private Button featuredBtn;
    private ProgressBar progressBar;
    private LinearLayout featuredCard;

    public HomeScreenController(Activity activity, HomeNavigationHost host) {
        this.activity = activity;
        this.host = host;
        this.svc = KidsServices.get(activity);
        build();
        svc.repo.addListener(listener);
        dev.saathi.kids.storage.SafetyEventStore.get(activity).addListener(listener);
    }

    public View getView() {
        return root;
    }

    private int dp(int v) {
        return Ui.dp(activity, v);
    }

    private void build() {
        root = new ScrollView(activity);
        root.setFillViewport(true);
        root.setBackgroundColor(Ui.BG);
        LinearLayout l = new LinearLayout(activity);
        l.setOrientation(LinearLayout.VERTICAL);
        l.setPadding(dp(20), dp(20), dp(20), dp(40));
        root.addView(l);

        greeting = Ui.text(activity, "Hi there! 👋", 26f, Ui.INK, true);
        greeting.setTypeface(Typeface.create("sans-serif-black", Typeface.BOLD));
        l.addView(greeting);
        TextView sub = Ui.text(activity, "Check something. Understand it. Know what to do next.", 14f, Color.parseColor("#555555"), false);
        sub.setPadding(0, dp(4), 0, dp(16));
        l.addView(sub);

        // Check
        LinearLayout check = Ui.vcard(activity);
        check.addView(Ui.title(activity, "Check something suspicious 🔍"));
        check.addView(Ui.body(activity, "Got an odd message, a prize link, or a strange downloaded app? Check it here."));
        LinearLayout pills = Ui.row(activity);
        pills.setPadding(0, dp(10), 0, dp(10));
        pills.addView(pill("💬 Message", 0));
        pills.addView(pill("🔗 Link", 1));
        pills.addView(pill("📁 File", 2));
        check.addView(pills);
        checkStats = Ui.note(activity, "");
        check.addView(checkStats);
        l.addView(check);

        // Help
        LinearLayout help = Ui.vcard(activity);
        help.setBackground(Ui.card(activity, Color.parseColor("#FFF8F8"), Color.parseColor("#F0D6D6"), 16));
        help.addView(Ui.text(activity, "🚨 Need help or feeling unsafe?", 16f, Ui.RED, true));
        help.addView(Ui.text(activity, "No trouble, no blame. Reach someone you trust.", 12f, Color.parseColor("#774444"), false));
        helpStatus = Ui.note(activity, "");
        help.addView(helpStatus);
        help.addView(Ui.danger(activity, "I need help", v -> host.showSosFlow()));
        l.addView(help);

        // Safety flags (from stored events) + background protection state
        LinearLayout flags = Ui.vcard(activity);
        flags.addView(Ui.title(activity, "Safety alerts 🛡️"));
        threatFlag = Ui.text(activity, "", 13f, Ui.INK, true);
        selfHarmFlag = Ui.text(activity, "", 13f, Ui.INK, true);
        protectionLine = Ui.note(activity, "");
        flags.addView(threatFlag);
        flags.addView(selfHarmFlag);
        flags.addView(protectionLine);
        flags.addView(Ui.secondary(activity, "See alerts →", v -> host.openSafetyAlerts()));
        flags.addView(Ui.secondary(activity, "🌐 Open Saathi Safe Browser", v -> host.openSafeBrowser()));
        l.addView(flags);

        // Next lesson
        featuredCard = Ui.vcard(activity);
        featuredCard.addView(Ui.text(activity, "NEXT LESSON 🎯", 10f, Ui.GREEN, true));
        featuredTitle = Ui.title(activity, "");
        featuredSub = Ui.text(activity, "", 12.5f, Ui.MUTED, false);
        featuredState = Ui.note(activity, "");
        featuredCard.addView(featuredTitle);
        featuredCard.addView(featuredSub);
        featuredCard.addView(featuredState);
        featuredBtn = Ui.secondary(activity, "Start lesson →", null);
        featuredCard.addView(featuredBtn);
        l.addView(featuredCard);

        // Progress
        LinearLayout prog = Ui.vcard(activity);
        LinearLayout r = Ui.row(activity);
        r.addView(Ui.text(activity, "Lesson progress 📚", 15f, Ui.INK, true), Ui.weight(1f));
        progressText = Ui.text(activity, "", 12.5f, Ui.GREEN, true);
        r.addView(progressText);
        prog.addView(r);
        progressBar = new ProgressBar(activity, null, android.R.attr.progressBarStyleHorizontal);
        prog.addView(progressBar, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(10)));
        prog.addView(Ui.secondary(activity, "See all lessons →", v -> host.switchTab(NavigationTab.LEARN, true)));
        l.addView(prog);

        TextView foot = Ui.text(activity, "🔒 Saathi Kids doesn't read your chats or track where you go.\nYou choose what to check and what to share.",
                11.5f, Ui.FAINT, false);
        foot.setGravity(Gravity.CENTER);
        foot.setPadding(dp(10), dp(10), dp(10), dp(20));
        l.addView(foot);
        render();
    }

    private View pill(String label, int mode) {
        TextView p = Ui.text(activity, label, 12f, Ui.INK, true);
        p.setGravity(Gravity.CENTER);
        p.setBackground(Ui.card(activity, Color.parseColor("#F5F5F3"), Color.parseColor("#E0E0DC"), 20));
        p.setPadding(dp(8), dp(8), dp(8), dp(8));
        LinearLayout.LayoutParams lp = Ui.weight(1f);
        if (mode < 2) lp.rightMargin = dp(8);
        p.setLayoutParams(lp);
        p.setOnClickListener(v -> host.openCheckMode(mode));
        return p;
    }

    public void render() {
        boolean hi = "hi".equals(svc.repo.getLanguage());
        greeting.setText(hi ? "नमस्ते! 👋" : "Hi there! 👋");

        List<CheckHistoryRecord> checks = svc.repo.getCheckHistory();
        if (checks.isEmpty()) {
            checkStats.setText("No checks yet.");
        } else {
            int warn = 0;
            for (CheckHistoryRecord c : checks) {
                String r = c.getResultCategory();
                if (r.contains("WARNING") || r.equals("BE_CAREFUL") || r.equals("STATIC_INDICATORS_FOUND") || r.equals("KNOWN_THREAT_MATCH")) warn++;
            }
            checkStats.setText(checks.size() + " check" + (checks.size() == 1 ? "" : "s") + " saved on this phone • " + warn + " had warning signs");
        }

        List<HelpRequest> help = svc.repo.getHelpRequests();
        if (!help.isEmpty()) {
            HelpRequest last = help.get(0);
            helpStatus.setText("Last request to " + last.recipientName + ": " + last.status.childLabel());
            helpStatus.setVisibility(last.status == HelpRequestStatus.CANCELLED ? View.GONE : View.VISIBLE);
        } else {
            helpStatus.setVisibility(View.GONE);
        }

        dev.saathi.kids.storage.SafetyEventStore store = dev.saathi.kids.storage.SafetyEventStore.get(activity);
        dev.saathi.safety.FlagEngine.FlagState th = store.flag(dev.saathi.safety.SafetyEvent.Flag.THREATS);
        dev.saathi.safety.FlagEngine.FlagState sh = store.flag(dev.saathi.safety.SafetyEvent.Flag.SELF_HARM);
        threatFlag.setText("Threats: " + flagLabel(th));
        threatFlag.setTextColor(th.level == dev.saathi.safety.SafetyEvent.Level.ACTIVE ? Ui.RED : th.level == dev.saathi.safety.SafetyEvent.Level.NEEDS_REVIEW ? Ui.AMBER : Ui.FAINT);
        selfHarmFlag.setText("Feeling unsafe or very sad: " + flagLabel(sh));
        selfHarmFlag.setTextColor(sh.level == dev.saathi.safety.SafetyEvent.Level.CLEAR ? Ui.FAINT : Ui.GREEN);
        dev.saathi.safety.MonitoringStatus ms = dev.saathi.kids.safety.MonitoringState.compute(activity);
        protectionLine.setText(ms.overall == dev.saathi.safety.MonitoringStatus.Overall.ACTIVE
                ? "Background notification checks are on."
                : "Background notification checks are not fully on — see Settings → Background protection.");

        LessonCatalog cat = svc.lessons.getCatalog();
        if (cat == null) {
            featuredTitle.setText("Lessons unavailable");
            featuredSub.setText(svc.lessons.getError());
            featuredBtn.setVisibility(View.GONE);
            progressText.setText("");
            return;
        }
        Set<String> done = svc.repo.getCompletedLessonIds();
        int completed = cat.completedCount(done);
        progressText.setText(completed + " of " + cat.lessons.size() + " done");
        progressBar.setMax(cat.lessons.size());
        progressBar.setProgress(completed);
        LessonCatalog.Lesson next = cat.nextIncomplete(done);
        String lang = svc.repo.getLanguage();
        if (next == null) {
            featuredTitle.setText("All lessons done 🎉");
            featuredSub.setText("You can review any lesson from the Learn tab.");
            featuredState.setText("");
            featuredBtn.setText("Go to lessons →");
            featuredBtn.setOnClickListener(v -> host.switchTab(NavigationTab.LEARN, true));
        } else {
            LessonCatalog.Text t = next.text(lang);
            featuredTitle.setText(next.icon + "  " + t.title);
            featuredSub.setText(t.subtitle);
            featuredState.setText("Not started");
            featuredBtn.setText("Start lesson →");
            featuredBtn.setOnClickListener(v -> host.showLessonDetail(next.id));
        }
        featuredBtn.setVisibility(View.VISIBLE);
    }

    private static String flagLabel(dev.saathi.safety.FlagEngine.FlagState s) {
        switch (s.level) {
            case ACTIVE: return "raised (" + s.openEvents + ")";
            case NEEDS_REVIEW: return "needs a look (" + s.openEvents + ")";
            default: return "not raised";
        }
    }

    public void onDestroy() {
        svc.repo.removeListener(listener);
        dev.saathi.kids.storage.SafetyEventStore.get(activity).removeListener(listener);
    }
}
