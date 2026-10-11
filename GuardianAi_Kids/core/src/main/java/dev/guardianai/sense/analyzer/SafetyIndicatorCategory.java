package dev.guardianai.sense.analyzer;

/**
 * High-level categories for safety indicators identified by message analysis.
 */
public enum SafetyIndicatorCategory {
    CREDENTIAL_THEFT("Credential or OTP Theft", "Asking for one-time passwords, login PINs, or credentials"),
    FINANCIAL_DEMAND("Urgent Payment Demand", "Demanding money transfer, UPI payment, or financial penalties"),
    PRIZE_SCAM("Fake Prize or Giveaway", "Promising free game currency, gift cards, or fake lottery prizes"),
    SUSPICIOUS_LINK("Suspicious Link or Download", "Promoting unverified web links or file downloads"),
    BULLYING_HARASSMENT("Bullying & Hurtful Language", "Insults, harassment, or mean language aimed to demean the child"),
    PRIVACY_INVASION("Private Photo or Media Request", "Pressuring child for private photos, webcam feeds, or personal location"),
    SECRECY_PRESSURE("Secrecy & Concealment Demand", "Pressuring child to hide conversations from parents and family"),
    PLATFORM_MIGRATION("Platform Migration / Isolation", "Attempting to move conversation to private or disappearing apps"),
    COERCION_INTIMIDATION("Coercion & Blackmail Threat", "Threatening consequences if the child does not comply"),
    INSUFFICIENT_CONTEXT("Insufficient Context", "Text is too brief or ambiguous to determine safety signs");

    private final String displayName;
    private final String description;

    SafetyIndicatorCategory(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDescription() {
        return description;
    }
}
