package dev.guardianai.personal.ui.components;

import android.app.Activity;
import android.graphics.Color;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

import dev.guardianai.personal.R;
import dev.guardianai.personal.ui.model.ChildProfile;
import dev.guardianai.personal.ui.state.AppState;

public class OnboardingOverlay {

    public interface OnboardingCompletionListener {
        void onCompleted();
    }

    private final Activity activity;
    private final float density;
    private final OnboardingCompletionListener listener;
    private LinearLayout rootView;

    private int currentStep = 0;
    private TextView tvStepIndicator;
    private TextView tvTitle;
    private TextView tvDesc;
    private LinearLayout containerStepContent;
    private Button btnAction;

    public OnboardingOverlay(Activity activity, OnboardingCompletionListener listener) {
        this.activity = activity;
        this.density = activity.getResources().getDisplayMetrics().density;
        this.listener = listener;
        createView();
    }

    public View getView() {
        return rootView;
    }

    private void createView() {
        rootView = new LinearLayout(activity);
        rootView.setLayoutParams(new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
        ));
        rootView.setOrientation(LinearLayout.VERTICAL);
        rootView.setBackgroundColor(0xF0F7F7F5);
        rootView.setGravity(Gravity.CENTER);
        rootView.setPadding((int) (24 * density), (int) (24 * density), (int) (24 * density), (int) (24 * density));

        LinearLayout card = new LinearLayout(activity);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundResource(R.drawable.bg_card_elevated);
        card.setPadding((int) (24 * density), (int) (28 * density), (int) (24 * density), (int) (24 * density));
        card.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        ));

        tvStepIndicator = new TextView(activity);
        tvStepIndicator.setText("STEP 1 OF 3 • GUARDIANAI GUARDIAN SETUP");
        tvStepIndicator.setTextSize(11);
        tvStepIndicator.setTextColor(0xFF386B57);
        tvStepIndicator.setTypeface(null, android.graphics.Typeface.BOLD);
        card.addView(tvStepIndicator);

        tvTitle = new TextView(activity);
        tvTitle.setText("AI Child Safety & Cybersecurity");
        tvTitle.setTextSize(22);
        tvTitle.setTextColor(0xFF141414);
        tvTitle.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams tp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        tp.topMargin = (int) (8 * density);
        tvTitle.setLayoutParams(tp);
        card.addView(tvTitle);

        tvDesc = new TextView(activity);
        tvDesc.setText("GuardianAi protects your children and elderly parents from predatory online grooming, banking trojans, and fraudulent payment links on iQOO 15.");
        tvDesc.setTextSize(13);
        tvDesc.setTextColor(0xFF666666);
        tvDesc.setLineSpacing(0, 1.3f);
        LinearLayout.LayoutParams dp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        dp.topMargin = (int) (6 * density);
        tvDesc.setLayoutParams(dp);
        card.addView(tvDesc);

        containerStepContent = new LinearLayout(activity);
        containerStepContent.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams cp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        cp.topMargin = (int) (18 * density);
        cp.bottomMargin = (int) (20 * density);
        containerStepContent.setLayoutParams(cp);
        card.addView(containerStepContent);

        btnAction = new Button(activity);
        btnAction.setText("Continue Setup →");
        btnAction.setTextSize(14);
        btnAction.setTextColor(0xFFFFFFFF);
        btnAction.setBackgroundResource(R.drawable.bg_pill_black);
        btnAction.setTypeface(null, android.graphics.Typeface.BOLD);
        btnAction.setOnClickListener(v -> advanceStep());
        LinearLayout.LayoutParams bp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                (int) (48 * density)
        );
        btnAction.setLayoutParams(bp);
        card.addView(btnAction);

        rootView.addView(card);
        renderStep();
    }

    private void advanceStep() {
        if (currentStep < 2) {
            currentStep++;
            renderStep();
        } else {
            rootView.setVisibility(View.GONE);
            if (listener != null) {
                listener.onCompleted();
            }
        }
    }

    private void renderStep() {
        containerStepContent.removeAllViews();

        if (currentStep == 0) {
            tvStepIndicator.setText("STEP 1 OF 3 • WELCOME TO GUARDIANAI");
            tvTitle.setText("AI-Powered Family Guardian");
            tvDesc.setText("Designed with CRED-inspired elegance for iQOO 15. Real-time offline intelligence powered by Qualcomm Snapdragon 8 Elite.");

            TextView p1 = createFeatureItem("🛡️ APK Reverse Engineering", "Catches malicious SMS-stealing and banking trojans before installation.");
            TextView p2 = createFeatureItem("👁️ Sense Grooming NLP", "Detects secrecy demands and manipulation in children's gaming chats.");
            TextView p3 = createFeatureItem("🔒 100% On-Device Privacy", "Zero cloud uploads. All telemetry is stored locally and pruned automatically.");

            containerStepContent.addView(p1);
            containerStepContent.addView(p2);
            containerStepContent.addView(p3);
            btnAction.setText("Select Family Profile →");

        } else if (currentStep == 1) {
            tvStepIndicator.setText("STEP 2 OF 3 • PROFILE SELECTION");
            tvTitle.setText("Choose Monitored Ward Profile");
            tvDesc.setText("Select who you are securing today. You can switch profiles at any time from the top bar.");

            Button bAarav = createProfileButton("Aarav (Teen • 14y)", ChildProfile.AARAV);
            Button bAnanya = createProfileButton("Ananya (Child • 9y)", ChildProfile.ANANYA);
            Button bDadaji = createProfileButton("Dadaji (Elderly • 72y)", ChildProfile.DADAJI);

            containerStepContent.addView(bAarav);
            containerStepContent.addView(bAnanya);
            containerStepContent.addView(bDadaji);
            btnAction.setText("Confirm & Review Permissions →");

        } else {
            tvStepIndicator.setText("STEP 3 OF 3 • HARDWARE HARMONIZATION");
            tvTitle.setText("iQOO 15 Optimization Complete");
            tvDesc.setText("144Hz LTPO synchronization armed. 64-bit ARM64 Oryon registers aligned. National Cyber Crime Helpline (1930) linked.");

            TextView h1 = createFeatureItem("⚡ Display Sync", "144Hz refresh rate configured with zero-jank hardware acceleration.");
            TextView h2 = createFeatureItem("📞 1930 Helpline Linked", "Instant direct dialing for Golden-Hour cyber financial fraud freeze.");
            TextView h3 = createFeatureItem("🧹 Data Pruning", "Automatic 14-day cryptographic record deletion active.");

            containerStepContent.addView(h1);
            containerStepContent.addView(h2);
            containerStepContent.addView(h3);
            btnAction.setText("Enter Command Center 🚀");
        }
    }

    private TextView createFeatureItem(String header, String details) {
        TextView tv = new TextView(activity);
        tv.setText(header + "\n" + details);
        tv.setTextSize(12);
        tv.setTextColor(0xFF141414);
        tv.setLineSpacing(0, 1.25f);
        tv.setPadding((int) (12 * density), (int) (8 * density), (int) (12 * density), (int) (8 * density));
        tv.setBackgroundResource(R.drawable.bg_pill_dark);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        lp.bottomMargin = (int) (8 * density);
        tv.setLayoutParams(lp);
        return tv;
    }

    private Button createProfileButton(String text, ChildProfile profile) {
        Button btn = new Button(activity);
        btn.setText(text);
        btn.setTextSize(13);
        boolean isSelected = (AppState.get().getCurrentProfile() == profile);
        btn.setTextColor(isSelected ? 0xFFFFFFFF : 0xFF141414);
        btn.setBackgroundResource(isSelected ? R.drawable.bg_pill_black : R.drawable.bg_pill_dark);
        btn.setOnClickListener(v -> {
            AppState.get().setCurrentProfile(profile);
            renderStep();
        });
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                (int) (44 * density)
        );
        lp.bottomMargin = (int) (8 * density);
        btn.setLayoutParams(lp);
        return btn;
    }
}
