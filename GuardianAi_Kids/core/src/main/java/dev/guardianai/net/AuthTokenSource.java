package dev.guardianai.net;

/** Supplies a short-lived bearer token (Firebase ID token) for calls to the GuardianAi backend. */
public interface AuthTokenSource {

    class AuthException extends Exception {
        public final boolean network;

        public AuthException(String msg, boolean network) {
            super(msg);
            this.network = network;
        }
    }

    /** Returns a currently valid ID token, signing in or refreshing if needed. Never returns null. */
    String getIdToken() throws AuthException;

    /** Stable account id of this install (Firebase uid), or null if not signed in yet. */
    String getUserId();

    /** Forces the next call to refresh the token (e.g. after a 401). */
    void invalidate();
}
