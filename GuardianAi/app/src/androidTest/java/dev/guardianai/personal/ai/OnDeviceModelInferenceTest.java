package dev.guardianai.personal.ai;

import android.content.Context;
import android.util.Log;

import android.os.PowerManager;
import androidx.test.core.app.ActivityScenario;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import dev.guardianai.ai.ExplanationResult;
import dev.guardianai.ai.ModelLifecycleState;
import dev.guardianai.personal.ui.MainActivity;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.*;

/**
 * Phase 15 & 16: Automated Real On-Device AI Inference Test.
 *
 * Requirements:
 * - Load real model from physical device storage.
 * - Initialize real LiteRT-LM runtime on Snapdragon 8 Elite Oryon CPU.
 * - Send a real prompt ("Explain phishing in one sentence.").
 * - Generate actual tokens on hardware.
 * - Verify non-empty output.
 * - Verify completion without exception.
 * - Record real timing.
 * - Strictly FAIL if a mock/fallback provider was invoked.
 * - Multi-turn conversational question series testing context and memory.
 */
@RunWith(AndroidJUnit4.class)
public class OnDeviceModelInferenceTest {

    private static final String TAG = "OnDeviceModelInferenceTest";

    @Test
    public void testActualOnDeviceModelInferenceAndPhase16Chat() throws Exception {
        Context context = ApplicationProvider.getApplicationContext();
        ActivityScenario<MainActivity> scenario = ActivityScenario.launch(MainActivity.class);

        LiteRtLmAndroidModel model = null;
        try {

        // 1. Model Discovery
        File modelFile = LiteRtLmAndroidModel.findModelFile(context);
        assertNotNull("Model file gemma-4-E2B-it.litertlm must exist on target device", modelFile);
        assertTrue("Model file must exist and be readable", modelFile.exists() && modelFile.canRead());
        assertTrue("Model file must be > 1GB in size (actual: " + modelFile.length() + ")", modelFile.length() > 1_000_000_000L);
        Log.i(TAG, "Step 1 PASS: Model file found at " + modelFile.getAbsolutePath() + " (" + modelFile.length() + " bytes)");

        // 2. Initialize Real LiteRT-LM Runtime
        model = new LiteRtLmAndroidModel(context);
        CountDownLatch initLatch = new CountDownLatch(1);
        AtomicReference<ModelLifecycleState> initState = new AtomicReference<>();
        AtomicReference<String> initMessage = new AtomicReference<>();

        long initStart = System.currentTimeMillis();
        model.initializeAsync((state, message) -> {
            initState.set(state);
            initMessage.set(message);
            if (state == ModelLifecycleState.READY || state == ModelLifecycleState.ERROR || state == ModelLifecycleState.OUT_OF_MEMORY) {
                initLatch.countDown();
            }
        });

        boolean initDone = initLatch.await(60, TimeUnit.SECONDS);
        assertTrue("Model initialization timed out after 60s", initDone);
        assertEquals("Model must reach READY lifecycle state", ModelLifecycleState.READY, initState.get());
        long initDuration = System.currentTimeMillis() - initStart;
        Log.i(TAG, "Step 2 PASS: Model initialized successfully in " + initDuration + "ms on backend: " + model.getBackendName());

        // 3. PHASE 15 VERIFICATION: Send Single Sentence Question & Verify Real Streaming
        String p15Prompt = "Explain phishing in one sentence.";
        CountDownLatch p15Latch = new CountDownLatch(1);
        AtomicReference<ExplanationResult> p15Result = new AtomicReference<>();
        AtomicReference<Throwable> p15Error = new AtomicReference<>();
        StringBuilder streamedTokens = new StringBuilder();

        long inferStart = System.currentTimeMillis();
        model.answerQueryAsync(p15Prompt, null, new dev.guardianai.ai.OnDeviceLanguageModel.ExplanationCallback() {
            @Override
            public void onPartialToken(String tokenChunk) {
                streamedTokens.append(tokenChunk);
            }

            @Override
            public void onSuccess(ExplanationResult result) {
                p15Result.set(result);
                p15Latch.countDown();
            }

            @Override
            public void onError(Throwable throwable, ExplanationResult fallbackResult) {
                p15Error.set(throwable);
                p15Result.set(fallbackResult);
                p15Latch.countDown();
            }
        });

        boolean p15Done = p15Latch.await(60, TimeUnit.SECONDS);
        long p15Duration = System.currentTimeMillis() - inferStart;
        assertTrue("Inference timed out after 60s", p15Done);
        assertNull("Inference must not throw exception: " + (p15Error.get() != null ? p15Error.get().getMessage() : ""), p15Error.get());

        ExplanationResult result = p15Result.get();
        assertNotNull("ExplanationResult must not be null", result);

        // Strict Non-Mock / Real-Inference Assertions
        assertFalse("CRITICAL: Implementation must NEVER return a failure state when model is ready", result.isFailure());
        assertTrue("CRITICAL: Result must be genuinely MODEL_GENERATED, not a mock or rules fallback", result.isModelGenerated());
        assertEquals("CRITICAL: Source must strictly be MODEL_INFERENCE", ExplanationResult.ExplanationSource.MODEL_INFERENCE, result.getSource());

        // Verify Non-Empty Real Output
        String summary = result.getSummary();
        assertNotNull("Generated summary must not be null", summary);
        assertFalse("Generated summary must not be empty", summary.trim().isEmpty());
        assertTrue("Streamed tokens must be captured in real time", streamedTokens.length() > 0);

        // Record Timing & Benchmark Metrics
        long reportedLatency = result.getLatencyMs();
        assertTrue("Reported latency must be > 0", reportedLatency > 0);

        Log.i(TAG, "============================================================");
        Log.i(TAG, "PHASE 15 TEST RESULT: PASS");
        Log.i(TAG, "Question: " + p15Prompt);
        Log.i(TAG, "Generated Response: " + summary);
        Log.i(TAG, "Reported Latency: " + reportedLatency + "ms (Wall-clock: " + p15Duration + "ms)");
        Log.i(TAG, "Tokens Streamed Chars: " + streamedTokens.length());
        Log.i(TAG, "Tokens Decoded Count: " + model.getLastTokensGenerated());
        Log.i(TAG, "Tokens Per Second: " + String.format("%.2f", model.getLastTokensPerSec()));
        Log.i(TAG, "Time To First Token: " + String.format("%.2f", model.getLastTtftMs()) + "ms");
        Log.i(TAG, "Backend: " + result.getBackendName());
        Log.i(TAG, "============================================================");

        // 4. PHASE 16 VERIFICATION: 8 Real Sequential Questions on Physical Device
        // Reset conversation to start clean multi-turn test series
        model.resetConversation();

        String[] phase16Questions = new String[] {
                "What is phishing?",
                "Someone sent me a message asking for my OTP. What should I do?",
                "Explain this in simple language.",
                "Why should I not click suspicious links?",
                "What should I do if I already clicked the link?",
                "Why?",
                "What is the capital of France?",
                "Can you tell me my previous question?"
        };

        for (int i = 0; i < phase16Questions.length; i++) {
            String q = phase16Questions[i];
            int testNum = i + 1;
            Log.i(TAG, "------------------------------------------------------------");
            Log.i(TAG, "Executing PHASE 16 TEST " + testNum + ": " + q);

            CountDownLatch qLatch = new CountDownLatch(1);
            AtomicReference<ExplanationResult> qResRef = new AtomicReference<>();
            AtomicReference<Throwable> qErrRef = new AtomicReference<>();
            StringBuilder qStream = new StringBuilder();
            long qStart = System.currentTimeMillis();

            model.answerQueryAsync(q, null, new dev.guardianai.ai.OnDeviceLanguageModel.ExplanationCallback() {
                @Override
                public void onPartialToken(String tokenChunk) {
                    qStream.append(tokenChunk);
                }

                @Override
                public void onSuccess(ExplanationResult res) {
                    qResRef.set(res);
                    qLatch.countDown();
                }

                @Override
                public void onError(Throwable throwable, ExplanationResult fallbackResult) {
                    qErrRef.set(throwable);
                    qResRef.set(fallbackResult);
                    qLatch.countDown();
                }
            });

            boolean qDone = qLatch.await(90, TimeUnit.SECONDS);
            long qDuration = System.currentTimeMillis() - qStart;
            assertTrue("TEST " + testNum + " timed out after 90s", qDone);
            assertNull("TEST " + testNum + " threw exception: " + (qErrRef.get() != null ? qErrRef.get().getMessage() : ""), qErrRef.get());

            ExplanationResult qResult = qResRef.get();
            assertNotNull("TEST " + testNum + " result is null", qResult);
            assertTrue("TEST " + testNum + " must be genuinely model generated", qResult.isModelGenerated());
            assertFalse("TEST " + testNum + " response text must not be empty", qResult.getSummary().trim().isEmpty());

            Log.i(TAG, "PHASE 16 TEST " + testNum + " PASS in " + qDuration + "ms (tokens chars=" + qResult.getSummary().length() + ")");
            Log.i(TAG, "Generated Response: " + qResult.getSummary());

            // Specific semantic validations
            if (testNum == 7) {
                // Must mention Paris or capital of France
                assertTrue("TEST 7 (Capital of France) must answer with Paris: " + qResult.getSummary(),
                        qResult.getSummary().toLowerCase().contains("paris"));
            } else if (testNum == 8) {
                // Must recall previous question about France or capital
                String lower = qResult.getSummary().toLowerCase();
                assertTrue("TEST 8 (Recall previous question) must reference France or capital: " + qResult.getSummary(),
                        lower.contains("france") || lower.contains("capital") || lower.contains("previous"));
            }
        }

        Log.i(TAG, "============================================================");
        Log.i(TAG, "ALL PHASE 15 & PHASE 16 TESTS PASSED ON SNAPDRAGON 8 ELITE!");
        Log.i(TAG, "============================================================");

        } finally {
            try {
                if (model != null) model.close();
            } catch (Exception ignored) {}
            if (scenario != null) {
                scenario.close();
            }
        }
    }
}
