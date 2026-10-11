package dev.saathi.personal.ui.screens;

import android.app.Activity;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import dev.saathi.ai.ExplanationResult;
import dev.saathi.ai.ModelLifecycleState;
import dev.saathi.ai.OnDeviceLanguageModel;
import dev.saathi.ai.SecurityFindingContext;
import dev.saathi.personal.R;
import dev.saathi.personal.ui.model.ChatMessage;
import dev.saathi.personal.ui.state.AppState;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class AssistantScreenController {

    private final Activity activity;
    private final float density;
    private ScrollView rootView;
    private LinearLayout contentLayout;

    private LinearLayout containerMessages;
    private ScrollView svChat;
    private EditText etInput;
    private Button btnSend;
    private Runnable closeCallback;
    private boolean isGenerating = false;

    public AssistantScreenController(Activity activity) {
        this.activity = activity;
        this.density = activity.getResources().getDisplayMetrics().density;
        createView();
    }

    public View getView() {
        return rootView;
    }

    public void setCloseCallback(Runnable closeCallback) {
        this.closeCallback = closeCallback;
        render();
    }

    private void createView() {
        rootView = new ScrollView(activity);
        rootView.setLayoutParams(new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
        ));
        rootView.setFillViewport(true);
        rootView.setBackgroundColor(0xFFF7F7F5);

        contentLayout = new LinearLayout(activity);
        contentLayout.setOrientation(LinearLayout.VERTICAL);
        contentLayout.setPadding((int) (20 * density), (int) (16 * density), (int) (20 * density), (int) (100 * density));
        rootView.addView(contentLayout);

        render();
    }

    public void render() {
        contentLayout.removeAllViews();
        boolean senior = AppState.get().isSeniorMode();

        // 1. Header & Live Model Status
        contentLayout.addView(buildHeader(senior));

        // 2. Attached Context Card (if user clicked 'Ask Copilot' from scan result)
        SecurityFindingContext activeContext = AppState.get().getActiveFindingContext();
        if (activeContext != null) {
            contentLayout.addView(buildActiveContextBanner(activeContext, senior));
        }

        // 3. Suggestion Prompt Pills
        contentLayout.addView(buildSuggestionPills(activeContext, senior));

        // 4. Chat Messages Stream Container
        svChat = new ScrollView(activity);
        LinearLayout.LayoutParams scp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                (int) (380 * density)
        );
        scp.topMargin = (int) (8 * density);
        scp.bottomMargin = (int) (12 * density);
        svChat.setLayoutParams(scp);
        svChat.setBackgroundResource(R.drawable.bg_card_cred);
        svChat.setPadding((int) (12 * density), (int) (12 * density), (int) (12 * density), (int) (12 * density));

        containerMessages = new LinearLayout(activity);
        containerMessages.setOrientation(LinearLayout.VERTICAL);
        svChat.addView(containerMessages);
        contentLayout.addView(svChat);

        // Render message bubbles
        List<ChatMessage> messages = AppState.get().getChatMessages();
        for (ChatMessage msg : messages) {
            containerMessages.addView(createMessageBubble(msg, senior));
        }

        // Auto-scroll to bottom
        svChat.post(() -> svChat.fullScroll(View.FOCUS_DOWN));

        // 5. Input Row
        contentLayout.addView(buildInputRow(senior));
    }

    private View buildHeader(boolean senior) {
        LinearLayout header = new LinearLayout(activity);
        header.setOrientation(LinearLayout.VERTICAL);
        header.setPadding(0, 0, 0, (int) (10 * density));

        LinearLayout topRow = new LinearLayout(activity);
        topRow.setOrientation(LinearLayout.HORIZONTAL);
        topRow.setGravity(Gravity.CENTER_VERTICAL);

        TextView title = new TextView(activity);
        title.setText(senior ? "SAFETY COPILOT" : "SAATHI AI SAFETY COPILOT");
        title.setTextSize(senior ? 24 : 22);
        title.setTextColor(0xFF141414);
        title.setTypeface(null, android.graphics.Typeface.BOLD);
        topRow.addView(title);

        View sp = new View(activity);
        sp.setLayoutParams(new LinearLayout.LayoutParams(0, 1, 1f));
        topRow.addView(sp);

        // Action Buttons: Diagnostics, New Chat, Close
        Button btnDiag = new Button(activity);
        btnDiag.setText("🛠️ Diag");
        btnDiag.setBackgroundResource(R.drawable.bg_pill_dark);
        btnDiag.setTextColor(0xFF141414);
        btnDiag.setTextSize(11);
        btnDiag.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams dp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, (int) (34 * density));
        dp.rightMargin = (int) (6 * density);
        btnDiag.setLayoutParams(dp);
        btnDiag.setOnClickListener(v -> dev.saathi.personal.ui.components.AiDiagnosticsDialog.show(activity));
        topRow.addView(btnDiag);

        Button btnNewChat = new Button(activity);
        btnNewChat.setText("🔄 New Chat");
        btnNewChat.setBackgroundResource(R.drawable.bg_pill_dark);
        btnNewChat.setTextColor(0xFF141414);
        btnNewChat.setTextSize(11);
        btnNewChat.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams ncp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, (int) (34 * density));
        ncp.rightMargin = (int) (6 * density);
        btnNewChat.setLayoutParams(ncp);
        btnNewChat.setOnClickListener(v -> {
            AppState.get().getChatMessages().clear();
            OnDeviceLanguageModel lm = AppState.get().getLanguageModel();
            if (lm != null) {
                lm.resetConversation();
            }
            render();
            Toast.makeText(activity, "Conversation reset.", Toast.LENGTH_SHORT).show();
        });
        topRow.addView(btnNewChat);

        if (closeCallback != null) {
            Button btnClose = new Button(activity);
            btnClose.setText("✕ Close");
            btnClose.setBackgroundResource(R.drawable.bg_pill_dark);
            btnClose.setTextColor(0xFF141414);
            btnClose.setTextSize(11);
            btnClose.setTypeface(null, android.graphics.Typeface.BOLD);
            LinearLayout.LayoutParams cp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, (int) (34 * density));
            btnClose.setLayoutParams(cp);
            btnClose.setOnClickListener(v -> closeCallback.run());
            topRow.addView(btnClose);
        }

        header.addView(topRow);

        TextView sub = new TextView(activity);
        sub.setText("Conversational security intelligence running privately on Snapdragon 8 Elite");
        sub.setTextSize(senior ? 14 : 13);
        sub.setTextColor(0xFF666666);
        LinearLayout.LayoutParams sp2 = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        sp2.topMargin = (int) (4 * density);
        sub.setLayoutParams(sp2);
        header.addView(sub);

        // Dynamic Model Status Pill
        OnDeviceLanguageModel model = AppState.get().getLanguageModel();
        ModelLifecycleState modelState = model != null ? model.getState() : ModelLifecycleState.MISSING;
        String backend = model != null ? model.getBackendName() : "Local Rules";

        LinearLayout statusRow = new LinearLayout(activity);
        statusRow.setOrientation(LinearLayout.HORIZONTAL);
        statusRow.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams srp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        srp.topMargin = (int) (8 * density);
        statusRow.setLayoutParams(srp);

        TextView tvStatus = new TextView(activity);
        if (modelState == ModelLifecycleState.READY) {
            tvStatus.setText("🧠 GEMMA 4-E2B-IT ACTIVE (" + backend + ") • 100% PRIVATE");
            tvStatus.setTextColor(0xFF386B57);
            tvStatus.setBackgroundResource(R.drawable.bg_pill_emerald);
        } else if (modelState == ModelLifecycleState.LOADING) {
            tvStatus.setText("⏳ INITIALIZING GEMMA 4-E2B-IT ON SNAPDRAGON HARDWARE...");
            tvStatus.setTextColor(0xFFB45309);
            tvStatus.setBackgroundResource(R.drawable.bg_pill_amber);
        } else if (model != null && model.getModelPath() != null && !model.getModelPath().isEmpty()) {
            tvStatus.setText("📦 GEMMA MODEL DETECTED (" + (new java.io.File(model.getModelPath()).length() / (1024 * 1024)) + " MB)");
            tvStatus.setTextColor(0xFF141414);
            tvStatus.setBackgroundResource(R.drawable.bg_pill_dark);
        } else {
            tvStatus.setText("⚠️ MODEL_UNAVAILABLE (" + modelState.name() + ")");
            tvStatus.setTextColor(0xFFB91C1C);
            tvStatus.setBackgroundResource(R.drawable.bg_pill_dark);
        }
        tvStatus.setTextSize(senior ? 11 : 10);
        tvStatus.setPadding((int) (10 * density), (int) (5 * density), (int) (10 * density), (int) (5 * density));
        statusRow.addView(tvStatus);

        if (modelState != ModelLifecycleState.READY && modelState != ModelLifecycleState.LOADING && model != null) {
            Button btnInit = new Button(activity);
            btnInit.setText("⚡ Load Model");
            btnInit.setTextSize(10);
            btnInit.setTextColor(0xFF141414);
            btnInit.setBackgroundResource(R.drawable.bg_pill_amber);
            LinearLayout.LayoutParams bip = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    (int) (28 * density)
                    );
            bip.leftMargin = (int) (8 * density);
            btnInit.setLayoutParams(bip);
            btnInit.setOnClickListener(v -> {
                Toast.makeText(activity, "Loading Gemma on Snapdragon hardware...", Toast.LENGTH_SHORT).show();
                model.initializeAsync((st, msg) -> activity.runOnUiThread(this::render));
                render();
            });
            statusRow.addView(btnInit);
        }

        header.addView(statusRow);
        return header;
    }

    private View buildActiveContextBanner(SecurityFindingContext ctx, boolean senior) {
        LinearLayout banner = new LinearLayout(activity);
        banner.setOrientation(LinearLayout.VERTICAL);
        banner.setBackgroundResource(R.drawable.bg_card_cred);
        banner.setPadding((int) (14 * density), (int) (10 * density), (int) (14 * density), (int) (10 * density));
        LinearLayout.LayoutParams bp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        bp.topMargin = (int) (4 * density);
        bp.bottomMargin = (int) (6 * density);
        banner.setLayoutParams(bp);

        LinearLayout topRow = new LinearLayout(activity);
        topRow.setOrientation(LinearLayout.HORIZONTAL);
        topRow.setGravity(Gravity.CENTER_VERTICAL);

        TextView tvTitle = new TextView(activity);
        tvTitle.setText("📌 Attached Finding: " + ctx.getTargetIdentifier() + " [" + ctx.getVerdict().getDisplayName() + "]");
        tvTitle.setTextSize(senior ? 12 : 11);
        tvTitle.setTypeface(null, android.graphics.Typeface.BOLD);
        tvTitle.setTextColor(0xFF141414);
        topRow.addView(tvTitle);

        View sp = new View(activity);
        sp.setLayoutParams(new LinearLayout.LayoutParams(0, 1, 1f));
        topRow.addView(sp);

        Button btnClear = new Button(activity);
        btnClear.setText("✕ Clear");
        btnClear.setTextSize(10);
        btnClear.setTextColor(0xFF888888);
        btnClear.setBackgroundResource(R.drawable.bg_pill_dark);
        LinearLayout.LayoutParams cp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, (int) (26 * density));
        btnClear.setLayoutParams(cp);
        btnClear.setOnClickListener(v -> {
            AppState.get().clearActiveFindingContext();
            render();
        });
        topRow.addView(btnClear);
        banner.addView(topRow);

        if (!ctx.getRawUntrustedSnippet().isEmpty()) {
            TextView tvSnippet = new TextView(activity);
            String snippet = ctx.getRawUntrustedSnippet();
            if (snippet.length() > 100) {
                snippet = snippet.substring(0, 97) + "...";
            }
            tvSnippet.setText("\"" + snippet + "\"");
            tvSnippet.setTextSize(11);
            tvSnippet.setTextColor(0xFF666666);
            LinearLayout.LayoutParams sp2 = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
            );
            sp2.topMargin = (int) (4 * density);
            tvSnippet.setLayoutParams(sp2);
            banner.addView(tvSnippet);
        }

        return banner;
    }

    private View buildSuggestionPills(SecurityFindingContext activeContext, boolean senior) {
        HorizontalScrollView hsv = new HorizontalScrollView(activity);
        hsv.setHorizontalScrollBarEnabled(false);
        LinearLayout.LayoutParams hp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        hp.topMargin = (int) (4 * density);
        hp.bottomMargin = (int) (4 * density);
        hsv.setLayoutParams(hp);

        LinearLayout row = new LinearLayout(activity);
        row.setOrientation(LinearLayout.HORIZONTAL);

        if (activeContext != null) {
            row.addView(createSuggestionChip("Explain this finding", "Please explain why this finding is flagged and how it affects me.", senior));
            row.addView(createSuggestionChip("Why is it dangerous?", "What specific harm or fraud tactics are involved in this case?", senior));
            row.addView(createSuggestionChip("What should I do?", "Give me calm, step-by-step practical actions I should take right now.", senior));
            row.addView(createSuggestionChip("National Helpline 1930", "How and when should I report this to the 1930 Cyber Helpline?", senior));
        } else {
            row.addView(createSuggestionChip("What is a Trojan APK?", "What is an Android Banking Trojan APK and why is it dangerous?", senior));
            row.addView(createSuggestionChip("When to call 1930?", "What is the 1930 National Cyber Helpline and how quickly should I call?", senior));
            row.addView(createSuggestionChip("Recognize Phishing Links", "How do I recognize fake banking, electricity bill, and KYC update links?", senior));
            row.addView(createSuggestionChip("Is GB WhatsApp safe?", "Is modified WhatsApp or GB WhatsApp safe to install?", senior));
            row.addView(createSuggestionChip("साइबर सुरक्षा टिप्स", "कृपया मुझे ऑनलाइन फ्रॉड से बचने के ज़रूरी टिप्स बताइए।", senior));
        }

        hsv.addView(row);
        return hsv;
    }

    private Button createSuggestionChip(String label, String prompt, boolean senior) {
        Button chip = new Button(activity);
        chip.setText(label);
        chip.setTextSize(senior ? 12 : 11);
        chip.setTextColor(0xFF141414);
        chip.setBackgroundResource(R.drawable.bg_pill_dark);
        chip.setOnClickListener(v -> sendMessage(prompt));

        LinearLayout.LayoutParams cp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                (int) (36 * density)
        );
        cp.rightMargin = (int) (8 * density);
        chip.setLayoutParams(cp);
        return chip;
    }

    private View buildInputRow(boolean senior) {
        LinearLayout row = new LinearLayout(activity);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams rp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        row.setLayoutParams(rp);

        etInput = new EditText(activity);
        etInput.setHint("Ask Copilot about any security question...");
        etInput.setHintTextColor(0xFF888888);
        etInput.setTextColor(0xFF141414);
        etInput.setTextSize(senior ? 15 : 13);
        etInput.setBackgroundResource(R.drawable.bg_input_field);
        etInput.setPadding((int) (16 * density), (int) (12 * density), (int) (16 * density), (int) (12 * density));
        LinearLayout.LayoutParams ep = new LinearLayout.LayoutParams(0, (int) (48 * density), 1f);
        ep.rightMargin = (int) (8 * density);
        etInput.setLayoutParams(ep);
        row.addView(etInput);

        btnSend = new Button(activity);
        btnSend.setText(isGenerating ? "■ Stop" : "Send");
        btnSend.setTextSize(senior ? 14 : 12);
        btnSend.setTextColor(0xFFFFFFFF);
        btnSend.setBackgroundResource(isGenerating ? R.drawable.bg_pill_dark : R.drawable.bg_pill_black);
        btnSend.setTypeface(null, android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams bp = new LinearLayout.LayoutParams((int) (72 * density), (int) (48 * density));
        btnSend.setLayoutParams(bp);
        btnSend.setOnClickListener(v -> {
            if (isGenerating) {
                OnDeviceLanguageModel lm = AppState.get().getLanguageModel();
                if (lm != null) {
                    lm.cancelInference();
                }
                deliverResponse("[Inference stopped by user]");
            } else {
                String text = etInput.getText().toString().trim();
                if (!text.isEmpty()) {
                    etInput.setText("");
                    sendMessage(text);
                }
            }
        });
        row.addView(btnSend);

        return row;
    }

    private View createMessageBubble(ChatMessage msg, boolean senior) {
        LinearLayout bubbleContainer = new LinearLayout(activity);
        bubbleContainer.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams bcp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        bcp.bottomMargin = (int) (10 * density);
        bubbleContainer.setLayoutParams(bcp);
        bubbleContainer.setGravity(msg.isUser ? Gravity.END : Gravity.START);

        LinearLayout bubble = new LinearLayout(activity);
        bubble.setOrientation(LinearLayout.VERTICAL);
        bubble.setPadding((int) (14 * density), (int) (10 * density), (int) (14 * density), (int) (10 * density));
        bubble.setBackgroundResource(msg.isUser ? R.drawable.bg_pill_black : R.drawable.bg_pill_dark);

        LinearLayout.LayoutParams bp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        bp.width = (int) (activity.getResources().getDisplayMetrics().widthPixels * 0.78f);
        bubble.setLayoutParams(bp);

        TextView tvSender = new TextView(activity);
        tvSender.setText(msg.badge);
        tvSender.setTextSize(senior ? 11 : 10);
        tvSender.setTextColor(msg.isUser ? 0xFFFFFFFF : 0xFF386B57);
        tvSender.setTypeface(null, android.graphics.Typeface.BOLD);
        bubble.addView(tvSender);

        TextView tvText = new TextView(activity);
        tvText.setText(msg.text);
        tvText.setTextSize(senior ? 15 : 13);
        tvText.setTextColor(msg.isUser ? 0xFFFFFFFF : 0xFF141414);
        tvText.setLineSpacing(0, 1.25f);
        tvText.setTag("bubble_text");
        LinearLayout.LayoutParams tp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        tp.topMargin = (int) (4 * density);
        tvText.setLayoutParams(tp);
        bubble.addView(tvText);

        TextView tvTime = new TextView(activity);
        SimpleDateFormat sdf = new SimpleDateFormat("hh:mm a", Locale.getDefault());
        tvTime.setText(sdf.format(msg.timestamp));
        tvTime.setTextSize(senior ? 10 : 9);
        tvTime.setTextColor(msg.isUser ? 0xFFCCCCCC : 0xFF888888);
        LinearLayout.LayoutParams tmp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        tmp.topMargin = (int) (4 * density);
        tmp.gravity = Gravity.END;
        tvTime.setLayoutParams(tmp);
        bubble.addView(tvTime);

        bubbleContainer.addView(bubble);
        return bubbleContainer;
    }

    public void promptAssistant(String prompt) {
        if (prompt != null && !prompt.isBlank()) {
            sendMessage(prompt);
        }
    }

    private void sendMessage(String prompt) {
        AppState.get().addChatMessage(new ChatMessage(true, prompt, "You"));

        // Truthful thinking indicator
        ChatMessage thinkingMsg = new ChatMessage(false, "Saathi is thinking...", "Saathi Safety Copilot");
        AppState.get().addChatMessage(thinkingMsg);

        isGenerating = true;
        render();

        OnDeviceLanguageModel model = AppState.get().getLanguageModel();
        SecurityFindingContext context = AppState.get().getActiveFindingContext();

        if (model == null) {
            deliverResponse("⚠️ MODEL_UNAVAILABLE\n\nOn-device model provider is uninitialized.");
            return;
        }

        StringBuilder streamBuffer = new StringBuilder();

        model.answerQueryAsync(prompt, context, new OnDeviceLanguageModel.ExplanationCallback() {
            @Override
            public void onPartialToken(String tokenChunk) {
                activity.runOnUiThread(() -> {
                    streamBuffer.append(tokenChunk);
                    AppState.get().updateLastAssistantMessage(streamBuffer.toString(), "Saathi Safety Copilot");
                    updateStreamingBubble(streamBuffer.toString());
                });
            }

            @Override
            public void onSuccess(ExplanationResult result) {
                activity.runOnUiThread(() -> deliverResponse(result.toFormattedDisplay()));
            }

            @Override
            public void onError(Throwable throwable, ExplanationResult fallbackResult) {
                activity.runOnUiThread(() -> {
                    String errorText = (fallbackResult != null) ? fallbackResult.toFormattedDisplay() : ("❌ INFERENCE_FAILED: " + (throwable != null ? throwable.getMessage() : "Unknown error"));
                    deliverResponse(errorText);
                });
            }
        });
    }

    private void updateStreamingBubble(String text) {
        if (containerMessages == null || containerMessages.getChildCount() == 0) return;
        View lastChild = containerMessages.getChildAt(containerMessages.getChildCount() - 1);
        if (lastChild instanceof LinearLayout) {
            View bubble = ((LinearLayout) lastChild).getChildAt(0);
            if (bubble instanceof LinearLayout) {
                View tv = bubble.findViewWithTag("bubble_text");
                if (tv instanceof TextView) {
                    ((TextView) tv).setText(text);
                }
            }
        }
        if (svChat != null) {
            svChat.post(() -> svChat.fullScroll(View.FOCUS_DOWN));
        }
    }

    private void deliverResponse(String responseText) {
        isGenerating = false;
        AppState.get().updateLastAssistantMessage(responseText, "Saathi Safety Copilot");
        render();
    }
}
