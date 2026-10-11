package dev.guardianai.kids.ui.screens;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.Typeface;
import android.view.Gravity;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;

import dev.guardianai.kids.KidsServices;
import dev.guardianai.kids.ui.Ui;
import dev.guardianai.learn.LessonCatalog;

import java.util.Set;

/** Learn screen: lessons from the bundled versioned content, progress from stored completions. */
public class LearnScreenController {

    public interface LearnNavigationHost {
        void showLessonDetail(String lessonId);
    }

    private enum Filter { ALL, TODO, DONE }

    private final Activity activity;
    private final LearnNavigationHost host;
    private final KidsServices svc;
    private final Runnable listener = this::render;

    private ScrollView root;
    private LinearLayout list;
    private TextView progressText;
    private ProgressBar progressBar;
    private LinearLayout filters;
    private Filter filter = Filter.ALL;

    public LearnScreenController(Activity activity, LearnNavigationHost host) {
        this.activity = activity;
        this.host = host;
        this.svc = KidsServices.get(activity);
        build();
        svc.repo.addListener(listener);
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
        l.setPadding(dp(20), dp(20), dp(20), dp(60));
        root.addView(l);

        TextView h = Ui.text(activity, "Safety Lessons 🛡️", 24f, Ui.INK, true);
        h.setTypeface(Typeface.create("sans-serif-black", Typeface.BOLD));
        l.addView(h);
        TextView sub = Ui.text(activity, "Short stories about tricky situations online, and what you can do.", 13.5f, Color.parseColor("#555555"), false);
        sub.setPadding(0, dp(4), 0, dp(14));
        l.addView(sub);

        LinearLayout card = Ui.vcard(activity);
        progressText = Ui.text(activity, "", 14f, Ui.GREEN, true);
        card.addView(progressText);
        progressBar = new ProgressBar(activity, null, android.R.attr.progressBarStyleHorizontal);
        card.addView(progressBar);
        l.addView(card);

        filters = Ui.row(activity);
        filters.setPadding(0, 0, 0, dp(10));
        l.addView(filters);
        list = new LinearLayout(activity);
        list.setOrientation(LinearLayout.VERTICAL);
        l.addView(list);
        render();
    }

    public void render() {
        LessonCatalog cat = svc.lessons.getCatalog();
        list.removeAllViews();
        if (cat == null) {
            progressText.setText("Lessons unavailable");
            progressBar.setProgress(0);
            LinearLayout c = Ui.vcard(activity);
            c.addView(Ui.body(activity, svc.lessons.getError()));
            list.addView(c);
            return;
        }
        Set<String> done = svc.repo.getCompletedLessonIds();
        int completed = cat.completedCount(done);
        int total = cat.lessons.size();
        progressText.setText(completed + " of " + total + " lessons done");
        progressBar.setMax(total);
        progressBar.setProgress(completed);

        filters.removeAllViews();
        addFilter("All (" + total + ")", Filter.ALL);
        addFilter("To do (" + (total - completed) + ")", Filter.TODO);
        addFilter("Done (" + completed + ")", Filter.DONE);

        String lang = svc.repo.getLanguage();
        int shown = 0;
        for (LessonCatalog.Lesson lesson : cat.lessons) {
            boolean isDone = done.contains(lesson.id);
            if (filter == Filter.TODO && isDone) continue;
            if (filter == Filter.DONE && !isDone) continue;
            list.addView(item(lesson, isDone, lang));
            shown++;
        }
        if (shown == 0) {
            list.addView(Ui.body(activity, filter == Filter.DONE ? "No lessons finished yet." : "You've finished every lesson. 🎉"));
        }
    }

    private void addFilter(String label, Filter f) {
        TextView t = Ui.text(activity, label, 12f, f == filter ? Color.WHITE : Ui.INK, true);
        t.setBackground(f == filter ? Ui.solid(activity, Ui.INK, 16) : Ui.card(activity, Color.WHITE, Color.parseColor("#E0E0DC"), 16));
        t.setPadding(dp(12), dp(6), dp(12), dp(6));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.rightMargin = dp(8);
        t.setOnClickListener(v -> {
            filter = f;
            render();
        });
        filters.addView(t, lp);
    }

    private View item(LessonCatalog.Lesson lesson, boolean isDone, String lang) {
        LessonCatalog.Text txt = lesson.text(lang);
        LinearLayout card = Ui.row(activity);
        card.setBackground(Ui.card(activity, Color.WHITE, Color.parseColor("#E6E6E2"), 14));
        card.setPadding(dp(16), dp(14), dp(16), dp(14));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = dp(10);
        card.setLayoutParams(lp);
        TextView icon = Ui.text(activity, lesson.icon, 24f, Ui.INK, false);
        icon.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams ilp = new LinearLayout.LayoutParams(dp(44), dp(44));
        ilp.rightMargin = dp(12);
        card.addView(icon, ilp);
        LinearLayout col = new LinearLayout(activity);
        col.setOrientation(LinearLayout.VERTICAL);
        col.addView(Ui.text(activity, txt.title, 14.5f, Ui.INK, true));
        col.addView(Ui.text(activity, txt.subtitle, 12f, Ui.MUTED, false));
        if (!lesson.hasLanguage(lang)) col.addView(Ui.note(activity, "Not translated yet — shown in English"));
        TextView status = Ui.text(activity, isDone ? "DONE ✅" : "NOT STARTED", 10f, isDone ? Ui.GREEN : Ui.AMBER, true);
        status.setPadding(0, dp(4), 0, 0);
        col.addView(status);
        card.addView(col, Ui.weight(1f));
        card.addView(Ui.text(activity, "→", 18f, Color.parseColor("#999999"), false));
        card.setOnClickListener(v -> host.showLessonDetail(lesson.id));
        return card;
    }

    public void onDestroy() {
        svc.repo.removeListener(listener);
    }
}
