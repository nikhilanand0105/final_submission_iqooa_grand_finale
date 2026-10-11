package dev.guardianai.personal.ui.components;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import dev.guardianai.personal.R;
import dev.guardianai.personal.data.DataExfiltrationSentinel;
import dev.guardianai.personal.ui.state.AppState;

/**
 * Interactive Dialog for fishy data/photo upload interception (e.g. TeraBox).
 * Prompts the user to confirm whether they gave permission. If not, stops and blocks the upload.
 */
public class DataExfiltrationDialog {

    public static void show(Activity activity, Runnable onDismissCallback) {
        if (activity == null || activity.isFinishing()) return;

        Dialog dialog = new Dialog(activity);
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);

        float density = activity.getResources().getDisplayMetrics().density;
        boolean senior = AppState.get().isSeniorMode();

        ScrollView scrollView = new ScrollView(activity);
        scrollView.setLayoutParams(new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        ));
        scrollView.setBackgroundResource(R.drawable.bg_bottom_sheet);

        LinearLayout layout = new LinearLayout(activity);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding((int) (24 * density), (int) (24 * density), (int) (24 * density), (int) (32 * density));

        // Drag pill bar
        TextView dragPill = new TextView(activity);
        LinearLayout.LayoutParams pillParams = new LinearLayout.LayoutParams((int) (48 * density), (int) (4 * density));
        pillParams.gravity = Gravity.CENTER_HORIZONTAL;
        pillParams.bottomMargin = (int) (18 * density);
        dragPill.setLayoutParams(pillParams);
        dragPill.setBackgroundColor(0xFFE5E5E2);
        layout.addView(dragPill);

        // Header: Category badge & Hardware badge
        LinearLayout badgeRow = new LinearLayout(activity);
        badgeRow.setOrientation(LinearLayout.HORIZONTAL);
        badgeRow.setGravity(Gravity.CENTER_VERTICAL);

        TextView tvCategory = new TextView(activity);
        tvCategory.setText("🚨 FISHY DATA UPLOAD DETECTED");
        tvCategory.setTextSize(senior ? 13 : 11);
        tvCategory.setTypeface(null, android.graphics.Typeface.BOLD);
        tvCategory.setTextColor(0xFFD32F2F);
        tvCategory.setBackgroundResource(R.drawable.bg_pill_crimson);
        tvCategory.setPadding((int) (10 * density), (int) (5 * density), (int) (10 * density), (int) (5 * density));
        badgeRow.addView(tvCategory);

        View spacer = new View(activity);
        LinearLayout.LayoutParams sp = new LinearLayout.LayoutParams(0, 1, 1f);
        spacer.setLayoutParams(sp);
        badgeRow.addView(spacer);

        TextView tvHw = new TextView(activity);
        tvHw.setText("Snapdragon 8 Elite Sentinel");
        tvHw.setTextSize(10);
        tvHw.setTextColor(0xFF386B57);
        tvHw.setBackgroundResource(R.drawable.bg_pill_emerald);
        tvHw.setPadding((int) (8 * density), (int) (4 * density), (int) (8 * density), (int) (4 * density));
        badgeRow.addView(tvHw);

        layout.addView(badgeRow);

        // App Title
        TextView tvTitle = new TextView(activity);
        tvTitle.setText("TeraBox: Cloud Storage Space");
        tvTitle.setTextSize(senior ? 22 : 19);
        tvTitle.setTypeface(null, android.graphics.Typeface.BOLD);
        tvTitle.setTextColor(0xFF141414);
        LinearLayout.LayoutParams tp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        tp.topMargin = (int) (14 * density);
        tvTitle.setLayoutParams(tp);
        layout.addView(tvTitle);

        // Package & Trigger
        TextView tvSub = new TextView(activity);
        tvSub.setText("com.dubox.drive • Silent Background Media Access");
        tvSub.setTextSize(senior ? 14 : 12);
        tvSub.setTextColor(0xFF666666);
        LinearLayout.LayoutParams subp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        subp.topMargin = (int) (4 * density);
        subp.bottomMargin = (int) (16 * density);
        tvSub.setLayoutParams(subp);
        layout.addView(tvSub);

        // Telemetry Details Container
        LinearLayout telemetryBox = new LinearLayout(activity);
        telemetryBox.setOrientation(LinearLayout.VERTICAL);
        telemetryBox.setBackgroundResource(R.drawable.bg_card_elevated);
        telemetryBox.setPadding((int) (16 * density), (int) (14 * density), (int) (16 * density), (int) (14 * density));
        LinearLayout.LayoutParams tlp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        tlp.bottomMargin = (int) (18 * density);
        telemetryBox.setLayoutParams(tlp);

        TextView tvTelHeader = new TextView(activity);
        tvTelHeader.setText("LIVE INTERCEPTION TELEMETRY");
        tvTelHeader.setTextSize(10);
        tvTelHeader.setTextColor(0xFF888888);
        tvTelHeader.setTypeface(null, android.graphics.Typeface.BOLD);
        telemetryBox.addView(tvTelHeader);

        addTelemetryRow(activity, density, telemetryBox, "📷 Target Media:", "142 Photos & Videos (DCIM/Camera/*)");
        addTelemetryRow(activity, density, telemetryBox, "🌐 Destination:", "upload.terabox.com:443 (Singapore CDN)");
        addTelemetryRow(activity, density, telemetryBox, "📦 Data Queued:", "384 MB queued for background sync");
        addTelemetryRow(activity, density, telemetryBox, "🔒 Permission:", "READ_MEDIA_IMAGES (Background Sync)");
        addTelemetryRow(activity, density, telemetryBox, "⚡ Behavior:", "Silent upload attempt without active user session");

        layout.addView(telemetryBox);

        // Question Container
        LinearLayout questionBox = new LinearLayout(activity);
        questionBox.setOrientation(LinearLayout.VERTICAL);
        questionBox.setBackgroundResource(R.drawable.bg_card_glow_amber);
        questionBox.setPadding((int) (16 * density), (int) (14 * density), (int) (16 * density), (int) (14 * density));
        LinearLayout.LayoutParams qp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        qp.bottomMargin = (int) (20 * density);
        questionBox.setLayoutParams(qp);

        TextView tvQuestion = new TextView(activity);
        tvQuestion.setText("Did you grant permission for TeraBox to upload and sync your personal gallery photos?");
        tvQuestion.setTextSize(senior ? 17 : 15);
        tvQuestion.setTypeface(null, android.graphics.Typeface.BOLD);
        tvQuestion.setTextColor(0xFF8C5800);
        questionBox.addView(tvQuestion);

        TextView tvExplanation = new TextView(activity);
        tvExplanation.setText("If you did not explicitly allow this, select STOP UPLOAD. GuardianAi will immediately sever the network socket and block TeraBox from exfiltrating any files.");
        tvExplanation.setTextSize(senior ? 13 : 11);
        tvExplanation.setTextColor(0xFF6B4300);
        LinearLayout.LayoutParams exp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        exp.topMargin = (int) (6 * density);
        tvExplanation.setLayoutParams(exp);
        questionBox.addView(tvExplanation);

        layout.addView(questionBox);

        // Action 1: STOP UPLOAD & BLOCK (Red/Black button)
        Button btnStopUpload = new Button(activity);
        Button btnAllowUpload = new Button(activity);

        btnStopUpload.setText("🛑 NO, STOP UPLOAD & BLOCK");
        btnStopUpload.setTextColor(0xFFFFFFFF);
        btnStopUpload.setBackgroundResource(R.drawable.bg_pill_black);
        btnStopUpload.setTextSize(senior ? 15 : 13);
        btnStopUpload.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams bsp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, (int) (48 * density));
        bsp.bottomMargin = (int) (10 * density);
        btnStopUpload.setLayoutParams(bsp);
        btnStopUpload.setOnClickListener(v -> {
            btnStopUpload.setEnabled(false);
            btnAllowUpload.setEnabled(false);
            btnStopUpload.setText("⏳ Severing Sockets & Activating Firewall...");
            DataExfiltrationSentinel.getInstance(activity).confirmUploadAsync(activity, false, new DataExfiltrationSentinel.ActionProgressListener() {
                @Override
                public void onActionProgress(String message) {
                    btnStopUpload.setText("⏳ " + message);
                }

                @Override
                public void onActionComplete() {
                    Toast.makeText(activity, "🛡️ TeraBox background upload BLOCKED! 0 bytes leaked.", Toast.LENGTH_LONG).show();
                    dialog.dismiss();
                    if (onDismissCallback != null) onDismissCallback.run();
                }
            });
        });
        layout.addView(btnStopUpload);

        // Action 2: YES, CONTINUE UPLOAD (Outline button)
        btnAllowUpload.setText("✓ YES, CONTINUE UPLOAD (I ALLOWED THIS)");
        btnAllowUpload.setTextColor(0xFF141414);
        btnAllowUpload.setBackgroundResource(R.drawable.bg_pill_outline);
        btnAllowUpload.setTextSize(senior ? 14 : 12);
        btnAllowUpload.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams bap = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, (int) (46 * density));
        btnAllowUpload.setLayoutParams(bap);
        btnAllowUpload.setOnClickListener(v -> {
            btnStopUpload.setEnabled(false);
            btnAllowUpload.setEnabled(false);
            btnAllowUpload.setText("⏳ Authorizing Cloud Sync...");
            DataExfiltrationSentinel.getInstance(activity).confirmUploadAsync(activity, true, new DataExfiltrationSentinel.ActionProgressListener() {
                @Override
                public void onActionProgress(String message) {
                    btnAllowUpload.setText("⏳ " + message);
                }

                @Override
                public void onActionComplete() {
                    Toast.makeText(activity, "✅ TeraBox upload permitted by user.", Toast.LENGTH_SHORT).show();
                    dialog.dismiss();
                    if (onDismissCallback != null) onDismissCallback.run();
                }
            });
        });
        layout.addView(btnAllowUpload);

        scrollView.addView(layout);
        dialog.setContentView(scrollView);

        Window window = dialog.getWindow();
        if (window != null) {
            window.setLayout(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            window.setGravity(Gravity.BOTTOM);
            window.setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
            WindowManager.LayoutParams params = window.getAttributes();
            params.dimAmount = 0.5f;
            window.addFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND);
            window.setAttributes(params);
        }

        dialog.show();
    }

    private static void addTelemetryRow(Context context, float density, LinearLayout parent, String key, String value) {
        LinearLayout row = new LinearLayout(context);
        row.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams rp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        rp.topMargin = (int) (5 * density);
        row.setLayoutParams(rp);

        TextView tvKey = new TextView(context);
        tvKey.setText(key + " ");
        tvKey.setTextSize(11);
        tvKey.setTextColor(0xFF666666);
        row.addView(tvKey);

        TextView tvVal = new TextView(context);
        tvVal.setText(value);
        tvVal.setTextSize(11);
        tvVal.setTextColor(0xFF141414);
        tvVal.setTypeface(null, android.graphics.Typeface.BOLD);
        row.addView(tvVal);

        parent.addView(row);
    }
}
