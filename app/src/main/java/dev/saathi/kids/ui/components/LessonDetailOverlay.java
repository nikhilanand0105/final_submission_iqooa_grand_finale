package dev.saathi.kids.ui.components;

import android.content.Context;
import android.graphics.Color;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import dev.saathi.kids.KidsServices;
import dev.saathi.kids.ui.Ui;
import dev.saathi.learn.LessonCatalog;

import java.text.DateFormat;
import java.util.Date;

/**
 * One lesson: introduction, story, warning signs, a choice with supportive feedback for whichever option was
 * picked, safe next steps, and an explicit "Mark as complete" action. Opening a lesson never completes it.
 */
public class LessonDetailOverlay {

    public interface Callback {
        void onClosed();
    }

    private final Context context;
    private final FrameLayout container;
    private final String lessonId;
    private final Callback callback;
    private final KidsServices svc;
    private int selected = -1;

    public LessonDetailOverlay(Context context, FrameLayout container, String lessonId, Callback callback) {
        this.context = context;
        this.container = container;
        this.lessonId = lessonId;
        this.callback = callback;
        this.svc = KidsServices.get(context);
    }

    public void show() {
        container.setVisibility(View.VISIBLE);
        render();
    }

    private int dp(int v) {
        return Ui.dp(context, v);
    }

    private void render() {
        container.removeAllViews();
        LessonCatalog cat = svc.lessons.getCatalog();
        LessonCatalog.Lesson lesson = cat == null ? null : cat.byId(lessonId);
        ScrollView scroll = new ScrollView(context);
        scroll.setBackgroundColor(Ui.BG);
        LinearLayout root = new LinearLayout(context);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(24), dp(32), dp(24), dp(40));
        scroll.addView(root);

        LinearLayout top = Ui.row(context);
        long doneAt = svc.repo.getLessonCompletedAt(lessonId);
        String badge = doneAt > 0 ? "DONE on " + DateFormat.getDateInstance(DateFormat.MEDIUM).format(new Date(doneAt)) : "LESSON";
        top.addView(Ui.text(context, badge, 10.5f, doneAt > 0 ? Ui.GREEN : Ui.MUTED, true), Ui.weight(1f));
        Button close = new Button(context);
        close.setText("✕");
        close.setBackgroundColor(Color.TRANSPARENT);
        close.setOnClickListener(v -> dismiss());
        top.addView(close);
        root.addView(top);

        if (lesson == null) {
            root.addView(Ui.body(context, "This lesson couldn't be found. It may have been removed in an update."));
            container.addView(scroll);
            return;
        }
        String lang = svc.repo.getLanguage();
        LessonCatalog.Text t = lesson.text(lang);
        if (!lesson.hasLanguage(lang)) root.addView(Ui.note(context, "This lesson isn't translated yet, so it's shown in English."));

        root.addView(Ui.text(context, lesson.icon + "  " + t.title, 22f, Ui.INK, true));
        root.addView(Ui.text(context, t.subtitle, 14f, Ui.MUTED, false));
        root.addView(section("", t.intro, Color.WHITE));
        root.addView(section("THE STORY", t.scenario, Color.WHITE));
        StringBuilder signs = new StringBuilder();
        for (String s : t.warningSigns) signs.append("• ").append(s).append('\n');
        root.addView(section("WARNING SIGNS", signs.toString().trim(), Color.parseColor("#FFF6E5")));

        root.addView(Ui.title(context, t.question));
        for (int i = 0; i < t.choices.size(); i++) {
            final int idx = i;
            LessonCatalog.Choice ch = t.choices.get(i);
            Button b = Ui.secondary(context, (selected == i ? "●  " : "○  ") + ch.text, v -> {
                selected = idx;
                render();
            });
            b.setGravity(Gravity.START | Gravity.CENTER_VERTICAL);
            if (selected >= 0) {
                if (ch.safe) b.setBackground(Ui.card(context, Color.parseColor("#EAF3ED"), Color.parseColor("#BFD9CB"), 10));
                else if (selected == i) b.setBackground(Ui.card(context, Color.parseColor("#F8F0DF"), Color.parseColor("#E8D8B8"), 10));
            }
            root.addView(b);
        }

        if (selected >= 0) {
            LessonCatalog.Choice ch = t.choices.get(selected);
            LinearLayout fb = Ui.vcard(context);
            fb.setBackground(Ui.card(context, Color.parseColor(ch.safe ? "#EAF3ED" : "#F8F0DF"), Color.parseColor("#E6E6E2"), 12));
            fb.addView(Ui.text(context, ch.safe ? "✅ Good choice" : "💡 Let's think about it", 14f, ch.safe ? Ui.GREEN : Ui.AMBER, true));
            fb.addView(Ui.body(context, ch.feedback));
            if (!ch.safe) fb.addView(Ui.note(context, "You can pick another option to see what happens."));
            root.addView(fb);

            StringBuilder steps = new StringBuilder();
            for (String s : t.nextSteps) steps.append("✔ ").append(s).append('\n');
            root.addView(section("SAFE NEXT STEPS", steps.toString().trim(), Color.WHITE));

            if (doneAt > 0) {
                root.addView(Ui.note(context, "You've already completed this lesson."));
                root.addView(Ui.secondary(context, "Close", v -> dismiss()));
            } else {
                root.addView(Ui.primary(context, "Mark as complete ✓", v -> {
                    svc.repo.markLessonCompleted(lessonId);
                    dismiss();
                }));
            }
        } else {
            root.addView(Ui.note(context, "Pick an answer to see feedback. There's no score."));
        }
        container.addView(scroll);
    }

    private View section(String heading, String body, int bg) {
        LinearLayout c = Ui.vcard(context);
        c.setBackground(Ui.card(context, bg, Color.parseColor("#E6E6E2"), 12));
        if (!heading.isEmpty()) c.addView(Ui.text(context, heading, 11f, Ui.FAINT, true));
        c.addView(Ui.text(context, body, 14f, Color.parseColor("#222222"), false));
        return c;
    }

    private void dismiss() {
        container.setVisibility(View.GONE);
        container.removeAllViews();
        if (callback != null) callback.onClosed();
    }
}
