package dev.guardianai.safety;

import dev.guardianai.ai.explain.LanguageModel;
import dev.guardianai.ai.explain.ModelState;
import dev.guardianai.safety.SafetyEvent.Flag;
import dev.guardianai.safety.SafetyEvent.Level;
import dev.guardianai.safety.SafetyTypes.SelfHarmKind;
import dev.guardianai.safety.SafetyTypes.Source;
import dev.guardianai.safety.SafetyTypes.SourceType;
import dev.guardianai.safety.SafetyTypes.Status;
import dev.guardianai.safety.SafetyTypes.ThreatKind;
import dev.guardianai.util.CancellationToken;
import org.junit.jupiter.api.Test;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class SafetyPipelineTest {

    /** Scripted stand-in for the LiteRT-LM adapter; records the exact prompts it received. */
    static class FakeModel implements LanguageModel {
        ModelState state = ModelState.READY;
        final Deque<Object> replies = new ArrayDeque<>();
        final List<String> prompts = new ArrayList<>();

        public ModelState getState() { return state; }
        public String getModelId() { return "gemma-test.litertlm"; }
        public String generate(String sys, String user, CancellationToken t) throws ModelException {
            prompts.add(user);
            Object r = replies.isEmpty() ? "" : replies.poll();
            if (r instanceof ModelException) throw (ModelException) r;
            return (String) r;
        }
    }

    static String json(String threat, String ts, String sh, String ss, String conf, String evidence) {
        return "{\"threat\":\"" + threat + "\",\"threat_severity\":\"" + ts + "\",\"self_harm\":\"" + sh + "\",\"self_harm_severity\":\"" + ss
                + "\",\"scam\":\"NONE\",\"age\":\"NONE\",\"confidence\":\"" + conf + "\",\"evidence\":[" + evidence + "],"
                + "\"explanation\":\"This message is asking for something and threatening you.\",\"actions\":[\"Tell a trusted adult\"]}";
    }

    @Test
    void gemmaIsTriedFirstWithTheActualContent() {
        FakeModel m = new FakeModel();
        String msg = "Send 3000 or I post your pics";
        m.replies.add(json("BLACKMAIL", "HIGH", "NONE", "NONE", "HIGH", "\"I post your pics\""));
        SafetyPipeline.Result r = new SafetyPipeline(m).analyze(SourceType.NOTIFICATION, msg, null, null);
        assertEquals(1, m.prompts.size());
        assertTrue(m.prompts.get(0).contains(msg), "model must receive the real input");
        assertEquals(SafetyPipeline.ModelOutcome.USED, r.modelOutcome);
        assertTrue(r.classification.source.usedModel());
        assertEquals(ThreatKind.BLACKMAIL, r.classification.threat);
        assertEquals("gemma-test.litertlm", r.classification.modelId);
    }

    @Test
    void modelUnavailableUsesLabelledRules() {
        FakeModel m = new FakeModel();
        m.state = ModelState.UNAVAILABLE;
        SafetyPipeline.Result r = new SafetyPipeline(m).analyze(SourceType.NOTIFICATION, "Send me 5000 rupees or I'll post your photos everywhere", null, null);
        assertEquals(0, m.prompts.size());
        assertEquals(SafetyPipeline.ModelOutcome.NOT_AVAILABLE, r.modelOutcome);
        assertFalse(r.classification.source.usedModel());
        assertTrue(r.classification.source.label().contains("AI model not used"));
        assertEquals(ThreatKind.BLACKMAIL, r.classification.threat);
        assertTrue(r.eligibleForModelReanalysis());
        assertNull(r.classification.modelId);
    }

    @Test
    void timeoutAndFailureFallBack() {
        for (LanguageModel.ModelException e : new LanguageModel.ModelException[]{
                new LanguageModel.ModelException("t", true, false), new LanguageModel.ModelException("x", false, false)}) {
            FakeModel m = new FakeModel();
            m.replies.add(e);
            SafetyPipeline.Result r = new SafetyPipeline(m).analyze(SourceType.NOTIFICATION, "I want to die, nobody cares", null, null);
            assertEquals(e.timedOut ? SafetyPipeline.ModelOutcome.TIMED_OUT : SafetyPipeline.ModelOutcome.FAILED, r.modelOutcome);
            assertFalse(r.classification.source.usedModel());
            assertEquals(SelfHarmKind.PERSONAL_IDEATION, r.classification.selfHarm);
        }
    }

    @Test
    void invalidModelOutputIsRejected() {
        String msg = "pay 500 warna account delete";
        String[] bad = {
                "not json at all",
                "{\"threat\":\"MURDER\",\"threat_severity\":\"HIGH\"}",
                json("BLACKMAIL", "HIGH", "NONE", "NONE", "HIGH", "\"words that are not in the message\""),
                json("BLACKMAIL", "NONE", "NONE", "NONE", "HIGH", "\"pay 500\""),
                json("NONE", "NONE", "INFORMATIONAL", "HIGH", "HIGH", ""),
                "{\"threat\":\"NONE\",\"threat_severity\":\"NONE\",\"self_harm\":\"NONE\",\"self_harm_severity\":\"NONE\",\"scam\":\"NONE\","
                        + "\"confidence\":\"HIGH\",\"evidence\":[],\"explanation\":\"This is 100% safe\",\"actions\":[]}",
        };
        for (String b : bad) {
            FakeModel m = new FakeModel();
            m.replies.add(b);
            SafetyPipeline.Result r = new SafetyPipeline(m).analyze(SourceType.MANUAL_MESSAGE, msg, null, null);
            assertEquals(SafetyPipeline.ModelOutcome.REJECTED, r.modelOutcome, b);
            assertFalse(r.classification.source.usedModel(), b);
            assertFalse(r.modelNote.isEmpty());
        }
    }

    @Test
    void guardKeepsStrongConcernTheModelMissed() {
        FakeModel m = new FakeModel();
        m.replies.add("{\"threat\":\"NONE\",\"threat_severity\":\"NONE\",\"self_harm\":\"NONE\",\"self_harm_severity\":\"NONE\",\"scam\":\"NONE\","
                + "\"age\":\"NONE\",\"confidence\":\"HIGH\",\"evidence\":[],\"explanation\":\"Looks like a normal message.\",\"actions\":[\"Carry on\"]}");
        SafetyPipeline.Result r = new SafetyPipeline(m).analyze(SourceType.NOTIFICATION, "im going to kill myself tonight", null, null);
        assertEquals(SafetyPipeline.ModelOutcome.USED, r.modelOutcome);
        assertEquals(Source.GEMMA_WITH_GUARD, r.classification.source);
        assertEquals(SelfHarmKind.PERSONAL_INTENT, r.classification.selfHarm);
        assertFalse(r.classification.guardNotes.isEmpty());
    }

    @Test
    void contradictoryModelClaimOnNewsGoesToReview() {
        FakeModel m = new FakeModel();
        String news = "News report: police said the student died by suicide; helpline numbers listed for support";
        m.replies.add(json("NONE", "NONE", "PERSONAL_INTENT", "HIGH", "HIGH", "\"died by suicide\""));
        SafetyPipeline.Result r = new SafetyPipeline(m).analyze(SourceType.NOTIFICATION, news, null, null);
        assertEquals(Status.NEEDS_REVIEW, r.classification.status);
        FlagEngine.Decision d = FlagEngine.decide(r.classification, r.modelOutcome.name(), SourceType.NOTIFICATION, "app", "k", null, 1);
        assertEquals(Level.NEEDS_REVIEW, d.event.level, "no automatic high-severity flag for news");
    }

    @Test
    void inconclusiveModelWithNoRuleFindingNeedsReview() {
        FakeModel m = new FakeModel();
        m.replies.add("{\"threat\":\"NONE\",\"threat_severity\":\"NONE\",\"self_harm\":\"NONE\",\"self_harm_severity\":\"NONE\",\"scam\":\"NONE\","
                + "\"age\":\"NONE\",\"confidence\":\"LOW\",\"evidence\":[],\"explanation\":\"Hard to say.\",\"actions\":[]}");
        SafetyPipeline.Result r = new SafetyPipeline(m).analyze(SourceType.NOTIFICATION, "you know what you did. last chance.", null, null);
        assertEquals(SafetyPipeline.ModelOutcome.INCONCLUSIVE, r.modelOutcome);
        assertEquals(Status.NEEDS_REVIEW, r.classification.status);
        assertFalse(r.classification.source.usedModel());
    }

    @Test
    void overLongInputSkipsModelButIsStillAnalysed() {
        FakeModel m = new FakeModel();
        StringBuilder b = new StringBuilder("hello ");
        while (b.length() < 2000) b.append("filler text ");
        b.append(" send money now or I will share your photos with everyone");
        SafetyPipeline.Result r = new SafetyPipeline(m).analyze(SourceType.NOTIFICATION, b.toString(), null, null);
        assertEquals(0, m.prompts.size());
        assertTrue(r.modelNote.contains("input limit"));
        assertNotEquals(ThreatKind.NONE, r.classification.threat);
    }

    @Test
    void emptyContentIsUnavailableNotSafe() {
        SafetyPipeline.Result r = new SafetyPipeline(new FakeModel()).analyze(SourceType.NOTIFICATION, "   ", null, null);
        assertEquals(Status.CONTENT_UNAVAILABLE, r.classification.status);
        assertFalse(r.classification.hasAnyConcern());
        assertNull(FlagEngine.decide(r.classification, "", SourceType.NOTIFICATION, "a", "k", null, 1).event, "nothing fabricated");
    }

    @Test
    void cancellationLeavesPendingNotSafe() {
        FakeModel m = new FakeModel();
        m.replies.add(new LanguageModel.ModelException("c", false, true));
        SafetyPipeline.Result r = new SafetyPipeline(m).analyze(SourceType.NOTIFICATION, "hello there", null, new CancellationToken());
        assertEquals(Status.PENDING, r.classification.status);
    }

    @Test
    void browserPageFirstPersonIsNotTheChildsStatement() {
        SafetyPipeline.Result r = new SafetyPipeline(null).analyze(SourceType.BROWSER_PAGE,
                "Forum post: I want to die. Reply: please reach out, you are not alone, there is a helpline.", null, null);
        assertFalse(r.classification.selfHarm.isPersonalRisk());
        SafetyPipeline.Result s = new SafetyPipeline(null).analyze(SourceType.BROWSER_SEARCH, "how to kill myself", null, null);
        assertTrue(s.classification.selfHarm.isPersonalRisk(), "a search typed by the child is their own words");
    }

    @Test
    void ordinaryMessagesRaiseNothing() {
        SafetyPipeline p = new SafetyPipeline(null);
        for (String s : new String[]{"Are we still meeting at 5?", "Mummy: dinner is ready", "Your order has been shipped", "kal school aa raha hai?"}) {
            SafetyPipeline.Result r = p.analyze(SourceType.NOTIFICATION, s, null, null);
            assertFalse(r.classification.hasAnyConcern(), s);
            assertNull(FlagEngine.decide(r.classification, "", SourceType.NOTIFICATION, "a", "k", null, 1).event, s);
        }
    }

    @Test
    void flagsAreIndependent() {
        SafetyPipeline p = new SafetyPipeline(null);
        SafetyClassification t = p.analyze(SourceType.NOTIFICATION, "Send me 5000 rupees or I'll post your photos everywhere", null, null).classification;
        SafetyClassification s = p.analyze(SourceType.NOTIFICATION, "I want to die, nobody cares about me", null, null).classification;
        assertEquals(Flag.THREATS, FlagEngine.decide(t, "", SourceType.NOTIFICATION, "a", "k1", null, 1).event.flag);
        assertEquals(Flag.SELF_HARM, FlagEngine.decide(s, "", SourceType.NOTIFICATION, "a", "k2", null, 1).event.flag);
    }
}
