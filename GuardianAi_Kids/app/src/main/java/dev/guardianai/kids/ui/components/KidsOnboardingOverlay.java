package dev.guardianai.kids.ui.components;

import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;

import dev.guardianai.kids.KidsServices;

/**
 * 4-Step welcoming, reassuring onboarding flow for GuardianAi Kids.
 * Explains purpose, checking limitations, privacy boundaries, and provides a clean Get Started entry.
 */
public class KidsOnboardingOverlay {

    public interface OnboardingCallback {
        void onCompleted();
    }

    private final Context context;
    private final FrameLayout container;
    private final OnboardingCallback callback;
    private int currentStep = 0;

    private static class StepContent {
        final String emoji;
        final String title;
        final String subtitle;
        final String explanation;
        final String highlightBadge;

        StepContent(String emoji, String title, String subtitle, String explanation, String highlightBadge) {
            this.emoji = emoji;
            this.title = title;
            this.subtitle = subtitle;
            this.explanation = explanation;
            this.highlightBadge = highlightBadge;
        }
    }

    private final StepContent[] steps = new StepContent[]{
            new StepContent(
                    "👋",
                    "Welcome to GuardianAi Kids",
                    "Your personal companion for digital safety",
                    "Something online confusing you? You can check it here, learn what to look for, or ask someone you trust for help.",
                    "CHILD-FIRST SAFETY"
            ),
            new StepContent(
                    "🔍",
                    "How Checking Works",
                    "You decide what to check, anytime",
                    "You can paste a strange message, check a website link, or choose a downloaded app file. GuardianAi looks for common warning signs and helps you decide what to do next.\n\nWarning signs aren't proof, and no warning signs doesn't mean something is safe. We don't read your chats automatically — you are always in control.",
                    "USER-INITIATED ONLY"
            ),
            new StepContent(
                    "🔒",
                    "Privacy & Family Sharing",
                    "No secret tracking, no hidden reading",
                    "Message and file checks run on this phone. Link checks do too — the online safety list is only asked if you turn it on.\n\nIf your family is connected through GuardianAi Personal, they only get help requests you choose to send. No one can read your messages through GuardianAi.",
                    "NO SECRET MONITORING"
            ),
            new StepContent(
                    "🛡️",
                    "Protection when GuardianAi is closed",
                    "You choose what to turn on",
                    "With your permission, GuardianAi can check the text that apps show in notifications — even when this app is closed — and warn you about threats, scams, or messages that sound like someone needs help.\n\nIt can't see messages without a notification or what you type. Websites are checked in GuardianAi Safe Browser. You can set this up later in Settings → Background protection.",
                    "OPTIONAL • YOUR CHOICE"
            ),
            new StepContent(
                    "✨",
                    "You're Ready to Explore!",
                    "Check something, learn, or ask for help",
                    "Remember our golden rule:\n\n“Check something. Understand it. Know what to do next.”\n\nIf you ever feel uncomfortable, the 'I Need Help' button is right on your home screen.",
                    "LET'S GET STARTED"
            )
    };

    public KidsOnboardingOverlay(Context context, FrameLayout container, OnboardingCallback callback) {
        this.context = context;
        this.container = container;
        this.callback = callback;
    }

    public void show() {
        container.removeAllViews();
        container.setVisibility(View.VISIBLE);
        currentStep = 0;
        renderCurrentStep();
    }

    private void renderCurrentStep() {
        container.removeAllViews();
        StepContent step = steps[currentStep];

        LinearLayout root = new LinearLayout(context);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Color.parseColor("#F7F7F5"));
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(dp(28), dp(48), dp(28), dp(36));
        FrameLayout.LayoutParams rootLp = new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT);
        root.setLayoutParams(rootLp);

        // Top Step Progress Indicator (Dots)
        LinearLayout dotsRow = new LinearLayout(context);
        dotsRow.setOrientation(LinearLayout.HORIZONTAL);
        dotsRow.setGravity(Gravity.CENTER);
        dotsRow.setPadding(0, 0, 0, dp(32));
        for (int i = 0; i < steps.length; i++) {
            View dot = new View(context);
            int size = (i == currentStep) ? dp(24) : dp(8);
            int height = dp(8);
            LinearLayout.LayoutParams dotLp = new LinearLayout.LayoutParams(size, height);
            dotLp.setMargins(dp(4), 0, dp(4), 0);
            dot.setLayoutParams(dotLp);
            dot.setBackgroundColor(i == currentStep ? Color.parseColor("#151515") : Color.parseColor("#D4D4D0"));
            dotsRow.addView(dot);
        }
        root.addView(dotsRow);

        // Badge
        TextView tvBadge = new TextView(context);
        tvBadge.setText(step.highlightBadge);
        tvBadge.setTextSize(10f);
        tvBadge.setTypeface(Typeface.DEFAULT_BOLD);
        tvBadge.setTextColor(Color.parseColor("#386B57"));
        tvBadge.setBackgroundColor(Color.parseColor("#EAF3ED"));
        tvBadge.setPadding(dp(12), dp(4), dp(12), dp(4));
        LinearLayout.LayoutParams badgeLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        badgeLp.gravity = Gravity.CENTER_HORIZONTAL;
        tvBadge.setLayoutParams(badgeLp);
        root.addView(tvBadge);

        // Emoji Hero Icon
        TextView tvEmoji = new TextView(context);
        tvEmoji.setText(step.emoji);
        tvEmoji.setTextSize(64f);
        tvEmoji.setGravity(Gravity.CENTER);
        tvEmoji.setPadding(0, dp(24), 0, dp(16));
        root.addView(tvEmoji);

        // Title
        TextView tvTitle = new TextView(context);
        tvTitle.setText(step.title);
        tvTitle.setTextSize(24f);
        tvTitle.setTypeface(Typeface.DEFAULT_BOLD);
        tvTitle.setTextColor(Color.parseColor("#141414"));
        tvTitle.setGravity(Gravity.CENTER);
        root.addView(tvTitle);

        // Subtitle
        TextView tvSub = new TextView(context);
        tvSub.setText(step.subtitle);
        tvSub.setTextSize(14f);
        tvSub.setTextColor(Color.parseColor("#666666"));
        tvSub.setGravity(Gravity.CENTER);
        tvSub.setPadding(0, dp(8), 0, dp(24));
        root.addView(tvSub);

        // Content Card
        LinearLayout card = new LinearLayout(context);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundColor(Color.WHITE);
        card.setPadding(dp(20), dp(20), dp(20), dp(20));
        LinearLayout.LayoutParams cardLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1.0f);
        card.setLayoutParams(cardLp);

        TextView tvDesc = new TextView(context);
        tvDesc.setText(step.explanation);
        tvDesc.setTextSize(15f);
        tvDesc.setTextColor(Color.parseColor("#333333"));
        tvDesc.setLineSpacing(dp(4), 1.2f);
        card.addView(tvDesc);

        root.addView(card);

        // Bottom Action Button
        Button btnNext = new Button(context);
        btnNext.setText(currentStep == steps.length - 1 ? "GET STARTED" : "CONTINUE →");
        btnNext.setTextColor(Color.WHITE);
        btnNext.setTextSize(14f);
        btnNext.setTypeface(Typeface.DEFAULT_BOLD);
        btnNext.setBackgroundColor(Color.parseColor("#151515"));
        LinearLayout.LayoutParams btnLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, dp(54));
        btnLp.setMargins(0, dp(24), 0, 0);
        btnNext.setLayoutParams(btnLp);

        btnNext.setOnClickListener(v -> {
            if (currentStep < steps.length - 1) {
                currentStep++;
                renderCurrentStep();
            } else {
                KidsServices.get(context).repo.setOnboardingCompleted(true);
                container.setVisibility(View.GONE);
                container.removeAllViews();
                if (callback != null) callback.onCompleted();
            }
        });

        root.addView(btnNext);
        container.addView(root);
    }

    private int dp(int v) {
        return Math.round(v * context.getResources().getDisplayMetrics().density);
    }
}
