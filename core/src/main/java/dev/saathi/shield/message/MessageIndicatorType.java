package dev.saathi.shield.message;

/**
 * High-level taxonomy of observable scam, fraud, and coercion indicators.
 */
public enum MessageIndicatorType {
    /**
     * Solicitations for one-time passwords, UPI PINs, passwords, or login tokens.
     */
    CREDENTIAL_OTP_DEMAND,

    /**
     * Coercive or panicked demands for immediate fund transfers or refunds.
     */
    URGENT_PAYMENT_PRESSURE,

    /**
     * Fabricated lures such as lottery prizes, held parcels, or impending account freezes.
     */
    LURE_REWARD_OR_SUSPENSION,

    /**
     * Unverified shortlinks, disposable domains, or requests to sideload apps/tools.
     */
    UNTRUSTED_LINK_OR_ATTACHMENT,

    /**
     * Impersonation of police, CBI, customs, courts, or senior bank officials.
     */
    AUTHORITY_IMPERSONATION,

    /**
     * Instructions to conceal communication from parents, spouses, or advisers.
     */
    SECRECY_ISOLATION,

    /**
     * Explicit intimidation involving arrest warrants, raids, jail threats, or defamation.
     */
    COERCION_OR_THREAT,

    /**
     * Demands for photos of government IDs (Aadhaar, PAN) or private photos/camera feeds.
     */
    SENSITIVE_DATA_REQUEST,

    /**
     * Artificial time limits ("within 15 minutes") or insistence on staying on call.
     */
    ARTIFICIAL_URGENCY_PANIC
}
