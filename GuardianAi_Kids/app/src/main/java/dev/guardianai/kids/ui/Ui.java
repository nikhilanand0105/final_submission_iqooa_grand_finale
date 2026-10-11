package dev.guardianai.kids.ui;

import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

/** Small view-building helpers matching the existing GuardianAi Kids card style. */
public final class Ui {

    public static final int INK = Color.parseColor("#141414");
    public static final int MUTED = Color.parseColor("#666666");
    public static final int FAINT = Color.parseColor("#888888");
    public static final int BG = Color.parseColor("#F7F7F5");
    public static final int GREEN = Color.parseColor("#386B57");
    public static final int AMBER = Color.parseColor("#855A12");
    public static final int RED = Color.parseColor("#A63232");

    private Ui() {}

    public static int dp(Context c, int v) {
        return Math.round(v * c.getResources().getDisplayMetrics().density);
    }

    public static GradientDrawable card(Context c, int bg, int stroke, int radiusDp) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(bg);
        g.setStroke(dp(c, 1), stroke);
        g.setCornerRadius(dp(c, radiusDp));
        return g;
    }

    public static GradientDrawable solid(Context c, int bg, int radiusDp) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(bg);
        g.setCornerRadius(dp(c, radiusDp));
        return g;
    }

    public static LinearLayout vcard(Context c) {
        LinearLayout l = new LinearLayout(c);
        l.setOrientation(LinearLayout.VERTICAL);
        l.setBackground(card(c, Color.WHITE, Color.parseColor("#E6E6E2"), 16));
        l.setPadding(dp(c, 18), dp(c, 16), dp(c, 18), dp(c, 16));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = dp(c, 14);
        l.setLayoutParams(lp);
        return l;
    }

    public static TextView text(Context c, String s, float sp, int color, boolean bold) {
        TextView t = new TextView(c);
        t.setText(s);
        t.setTextSize(sp);
        t.setTextColor(color);
        if (bold) t.setTypeface(Typeface.DEFAULT_BOLD);
        t.setLineSpacing(dp(c, 2), 1.12f);
        return t;
    }

    public static TextView title(Context c, String s) {
        TextView t = text(c, s, 16f, INK, true);
        t.setPadding(0, 0, 0, dp(c, 4));
        return t;
    }

    public static TextView body(Context c, String s) {
        TextView t = text(c, s, 13f, Color.parseColor("#444444"), false);
        t.setPadding(0, dp(c, 2), 0, dp(c, 2));
        return t;
    }

    public static TextView note(Context c, String s) {
        TextView t = text(c, s, 11.5f, FAINT, false);
        t.setPadding(0, dp(c, 4), 0, dp(c, 4));
        return t;
    }

    public static TextView badge(Context c, String s, int fg, int bg) {
        TextView t = text(c, s, 11f, fg, true);
        t.setBackground(solid(c, bg, 8));
        t.setPadding(dp(c, 10), dp(c, 4), dp(c, 10), dp(c, 4));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = dp(c, 8);
        t.setLayoutParams(lp);
        return t;
    }

    public static Button primary(Context c, String label, View.OnClickListener l) {
        Button b = new Button(c);
        b.setText(label);
        b.setAllCaps(false);
        b.setTextColor(Color.WHITE);
        b.setTextSize(14f);
        b.setTypeface(Typeface.DEFAULT_BOLD);
        b.setBackground(solid(c, INK, 10));
        b.setOnClickListener(l);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(c, 8);
        b.setLayoutParams(lp);
        return b;
    }

    public static Button danger(Context c, String label, View.OnClickListener l) {
        Button b = primary(c, label, l);
        b.setBackground(solid(c, RED, 10));
        return b;
    }

    public static Button secondary(Context c, String label, View.OnClickListener l) {
        Button b = primary(c, label, l);
        b.setTextColor(INK);
        b.setBackground(card(c, Color.parseColor("#F5F5F3"), Color.parseColor("#DCDCD8"), 10));
        return b;
    }

    public static LinearLayout row(Context c) {
        LinearLayout r = new LinearLayout(c);
        r.setOrientation(LinearLayout.HORIZONTAL);
        r.setGravity(Gravity.CENTER_VERTICAL);
        return r;
    }

    public static LinearLayout.LayoutParams weight(float w) {
        return new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, w);
    }

    public static String formatSize(long bytes) {
        if (bytes < 0) return "unknown size";
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format(java.util.Locale.US, "%.1f KB", bytes / 1024.0);
        return String.format(java.util.Locale.US, "%.1f MB", bytes / (1024.0 * 1024.0));
    }
}
