package dev.guardianai.ai.explain;

import java.util.ArrayList;
import java.util.List;

/**
 * Deterministic explanation built directly from the analyzer output. Used whenever the model is unavailable or
 * its output fails validation. Always labelled as rules-based guidance.
 */
public final class RulesBasedExplainer {

    private RulesBasedExplainer() {}

    public static SafetyExplanation explain(FindingSet fs, String language) {
        List<String> refs = new ArrayList<>();
        for (int i = 0; i < fs.findings.size() && i < 3; i++) refs.add(fs.findings.get(i).id);
        if (!"hi".equals(language)) {
            String summary = fs.analyzerSummary.isEmpty() ? fs.verdictLabel + "." : fs.analyzerSummary;
            List<String> steps = fs.analyzerNextSteps.isEmpty()
                    ? java.util.Collections.singletonList("If you're unsure, ask a trusted adult.")
                    : fs.analyzerNextSteps;
            return new SafetyExplanation(SafetyExplanation.Source.RULES, null, summary, refs, steps, fs.limitations, "en");
        }
        boolean strong = false;
        for (Finding f : fs.findings) if (f.severity.equals("CRITICAL") || f.severity.equals("HIGH")) strong = true;
        String what = fs.kind == FindingSet.Kind.LINK ? "इस लिंक" : fs.kind == FindingSet.Kind.FILE ? "इस फ़ाइल" : "इस मैसेज";
        String summary;
        List<String> steps = new ArrayList<>();
        if (fs.findings.isEmpty()) {
            summary = what + " में जाँच को कोई चेतावनी संकेत नहीं मिला। फिर भी यह जाँच हर चीज़ नहीं देख सकती।";
            steps.add("अगर कोई पासवर्ड, OTP या पैसे माँगे, तो रुक जाएँ।");
            steps.add("कुछ अजीब लगे तो किसी भरोसेमंद बड़े से बात करें।");
        } else {
            summary = what + " में " + fs.findings.size() + " चेतावनी संकेत मिले" + (strong ? ", जिनमें कुछ गंभीर हैं।" : "।")
                    + " संकेतों के नाम नीचे अंग्रेज़ी में दिखाए गए हैं।";
            steps.add("अपना पासवर्ड, OTP या निजी जानकारी किसी के साथ साझा न करें।");
            steps.add(fs.kind == FindingSet.Kind.FILE ? "इसे खुद से इंस्टॉल न करें।" : "जल्दबाज़ी में कुछ न खोलें या भेजें।");
            steps.add("किसी भरोसेमंद बड़े को दिखाएँ।");
        }
        return new SafetyExplanation(SafetyExplanation.Source.RULES, null, summary, refs, steps,
                "यह जाँच केवल चेतावनी संकेत देखती है; यह पक्का सबूत नहीं है।", "hi");
    }
}
