package dev.saathi.ai;

import dev.saathi.model.ApkAnalysisReport;
import dev.saathi.model.ScanVerdict;
import dev.saathi.model.ThreatIndicator;
import dev.saathi.sense.ConversationRiskReport;
import dev.saathi.shield.network.PhishingUrlScanner;
import dev.saathi.shield.network.url.UrlAnalysisResult;

/**
 * Generates plain-language Hindi and Hinglish explanations for Indian regional users and seniors,
 * converting complex technical indicators into actionable, reassuring guidance.
 */
public class HindiExplanationSynthesizer {

    public static String explainApkInHindi(ApkAnalysisReport report) {
        ScanVerdict verdict = report.getVerdict();

        switch (verdict) {
            case KNOWN_MALICIOUS:
            case HIGH_RISK:
                boolean isWhatsAppMod = false;
                boolean hasAccessibility = false;
                boolean hasSms = false;
                for (ThreatIndicator ti : report.getIndicators()) {
                    if (ti.getId().contains("WHATSAPP_MOD")) isWhatsAppMod = true;
                    if (ti.getId().contains("ATS") || ti.getId().contains("ACCESSIBILITY")) hasAccessibility = true;
                    if (ti.getId().contains("SMS") || ti.getId().contains("OTP")) hasSms = true;
                }

                if (isWhatsAppMod) {
                    return "🛑 खतरनाक वॉट्सऐप मॉड (WhatsApp MOD) मिला: यह ऐप असली वॉट्सऐप नहीं है (जैसे GBWhatsApp, WhatsApp Plus या Gold)। इसमें आपके गुप्त चैट्स और बैंक OTP चुराने वाले जासूसी कोड होते हैं, और आपका वॉट्सऐप नंबर हमेशा के लिए बैन हो सकता है। इसे तुरंत डिलीट करें।";
                } else if (hasAccessibility && hasSms) {
                    return "🛑 चेतावनी: इस ऐप को बिल्कुल इंस्टॉल न करें। यह ऐप आपके बैंक के गुप्त OTP पढ़ने और आपकी स्क्रीन देखने की इजाज़त मांग रहा है। अनजान लोगों या कॉल पर कहने पर इसे कभी न डालें।";
                } else if (hasAccessibility) {
                    return "🛑 ध्यान दें: यह ऐप आपके फोन की स्क्रीन पर नज़र रखने (Accessibility) की परमिशन मांग रहा है। साइबर अपराधी ऐसे ऐप्स से बैंक पासवर्ड चुराते हैं। इसे तुरंत डिलीट करें।";
                } else {
                    return "🛑 खतरनाक ऐप: यह ऐप आपके फोन और निजी जानकारी के लिए सुरक्षित नहीं है। यदि किसी अनजान कॉलर ने इसे डालने को कहा है, तो तुरंत कॉल काट दें और ऐप हटा दें।";
                }

            case CAUTION:
                return "⚠️ सावधानी बरतें: इस ऐप में कुछ संवेदनशील परमिशन मांगी गई हैं। केवल तभी आगे बढ़ें जब आप इस ऐप को बनाने वाली कंपनी को अच्छी तरह जानते हों।";

            case NO_KNOWN_THREAT_DETECTED:
                return "✅ कोई ज्ञात ख़तरा नहीं मिला: शुरुआती जांच में यह ऐप सामान्य लग रहा है। फिर भी केवल उन्हीं ऐप्स को इंस्टॉल करें जिन पर आपको पूरा भरोसा हो।";

            case UNABLE_TO_DETERMINE:
            default:
                return "❓ फ़ाइल की जांच पूरी नहीं हो सकी: यह फ़ाइल अधूरी या लॉक है। सुरक्षा के लिए इसे इंस्टॉल न करें।";
        }
    }

    public static String explainPhishingLinkInHindi(PhishingUrlScanner.UrlScanResult result) {
        if (result.riskLevel == PhishingUrlScanner.UrlRiskLevel.KNOWN_PHISHING) {
            return "🛑 नकली बैंक लिंक: यह लिंक आपके बैंक या बिजली विभाग के नाम पर बनाया गया फ़र्ज़ी पेज है। इस पर क्लिक न करें और अपना UPI PIN या पासवर्ड किसी के साथ साझा न करें। यदि पैसे कटने का डर हो तो 1930 पर कॉल करें।";
        } else if (result.riskLevel == PhishingUrlScanner.UrlRiskLevel.SUSPICIOUS_DESTINATION) {
            return "⚠️ संदेहास्पद वेबसाइट: यह वेबसाइट सुरक्षित नहीं लग रही है। यहाँ अपनी कोई भी निजी या बैंकिंग जानकारी न भरें।";
        } else {
            return "✅ वेबसाइट की जांच में कोई सीधा ख़तरा नहीं मिला। आधिकारिक पोर्टल पर होने की पुष्टि हमेशा करें।";
        }
    }

    public static String explainUrlAnalysisInHindi(UrlAnalysisResult result) {
        ScanVerdict verdict = result.getCombinedVerdict();
        if (verdict == ScanVerdict.KNOWN_MALICIOUS) {
            return "🛑 खतरनाक या फ़र्ज़ी लिंक: यह लिंक आपके बैंक, बिजली विभाग या सरकारी पोर्टल के नाम पर बनाया गया फ़र्ज़ी पेज है। इस पर क्लिक न करें और अपना UPI PIN, पासवर्ड या OTP किसी के साथ साझा न करें। यदि पैसे कटने का डर हो तो तुरंत 1930 पर कॉल करें।";
        } else if (verdict == ScanVerdict.HIGH_RISK) {
            return "⚠️ अत्यधिक संदेहास्पद वेबसाइट: इस लिंक में कई संदिग्ध संकेत (जैसे अमान्य पता या असामान्य डोमेन) मिले हैं। यहाँ अपनी कोई भी निजी या बैंकिंग जानकारी न भरें।";
        } else if (verdict == ScanVerdict.CAUTION) {
            return "⚠️ सावधानी बरतें: इस लिंक का पता सामान्य आधिकारिक वेबसाइट जैसा नहीं लग रहा है। केवल तभी आगे बढ़ें जब आपको भेजने वाले पर पूरा भरोसा हो।";
        } else {
            return "✅ वेबसाइट की स्थानीय जांच में कोई सीधा ख़तरा नहीं मिला। किसी भी अनजान पेज पर पासवर्ड डालने से पहले आधिकारिक पोर्टल होने की पुष्टि हमेशा करें।";
        }
    }

    public static String explainChildRiskInHindi(ConversationRiskReport report) {
        switch (report.getCategory()) {
            case GROOMING_MANIPULATION:
                return "⚠️ ज़रूरी सलाह: यह व्यक्ति आपसे अकेले में वीडियो कॉल या फ़ोटो मांग रहा है और मम्मी-पापा से छुपाने को कह रहा है। सच्चे दोस्त कभी परिवार से बातें छुपाने का दबाव नहीं डालते। तुरंत अपने माता-पिता या शिक्षक को बताएं।";
            case CHILD_FINANCIAL_SCAM:
                return "🛑 गेमिंग फ्रॉड चेतावनी: 'फ़्री डायमंड्स' या 'UC' के लालच में आकर कभी भी अपने घर का UPI PIN या पासवर्ड न दें। यह आपके परिवार के पैसे चुराने की चाल है।";
            case BENIGN:
            default:
                return "यह बातचीत सुरक्षित लग रही है। ऑनलाइन चैट करते समय हमेशा सतर्क रहें।";
        }
    }
}
