package dev.guardianai.personal.data.prefs;

import android.content.Context;
import android.content.SharedPreferences;

import dev.guardianai.personal.ui.model.ChildProfile;

/**
 * Manages persistent user preferences, onboarding completion, accessibility flags,
 * and active family safety profile using native Android SharedPreferences.
 */
public class PreferencesManager {

    public static final String PREF_NAME = "guardianai_personal_prefs";

    public static final String KEY_ONBOARDING_COMPLETED = "pref_onboarding_completed";
    public static final String KEY_SENIOR_MODE = "pref_senior_mode";
    public static final String KEY_LARGE_TEXT = "pref_large_text";
    public static final String KEY_HIGH_CONTRAST = "pref_high_contrast";
    public static final String KEY_HINDI = "pref_hindi";
    public static final String KEY_CURRENT_PROFILE = "pref_current_profile";

    private static volatile PreferencesManager instance;
    private final SharedPreferences preferences;

    public PreferencesManager(SharedPreferences preferences) {
        this.preferences = preferences;
    }

    public PreferencesManager(Context context) {
        this(context.getApplicationContext().getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE));
    }

    public static PreferencesManager getInstance(Context context) {
        if (instance == null) {
            synchronized (PreferencesManager.class) {
                if (instance == null) {
                    instance = new PreferencesManager(context);
                }
            }
        }
        return instance;
    }

    public boolean isOnboardingCompleted() {
        return preferences.getBoolean(KEY_ONBOARDING_COMPLETED, false);
    }

    public void setOnboardingCompleted(boolean completed) {
        preferences.edit().putBoolean(KEY_ONBOARDING_COMPLETED, completed).apply();
    }

    public boolean isSeniorMode() {
        return preferences.getBoolean(KEY_SENIOR_MODE, false);
    }

    public void setSeniorMode(boolean seniorMode) {
        preferences.edit().putBoolean(KEY_SENIOR_MODE, seniorMode).apply();
    }

    public boolean isLargeText() {
        return preferences.getBoolean(KEY_LARGE_TEXT, false);
    }

    public void setLargeText(boolean largeText) {
        preferences.edit().putBoolean(KEY_LARGE_TEXT, largeText).apply();
    }

    public boolean isHighContrast() {
        return preferences.getBoolean(KEY_HIGH_CONTRAST, false);
    }

    public void setHighContrast(boolean highContrast) {
        preferences.edit().putBoolean(KEY_HIGH_CONTRAST, highContrast).apply();
    }

    public boolean isHindi() {
        return preferences.getBoolean(KEY_HINDI, false);
    }

    public void setHindi(boolean hindi) {
        preferences.edit().putBoolean(KEY_HINDI, hindi).apply();
    }

    public ChildProfile getCurrentProfile() {
        String profileName = preferences.getString(KEY_CURRENT_PROFILE, ChildProfile.AARAV.name());
        try {
            return ChildProfile.valueOf(profileName);
        } catch (IllegalArgumentException e) {
            return ChildProfile.AARAV;
        }
    }

    public void setCurrentProfile(ChildProfile profile) {
        if (profile == null) return;
        preferences.edit().putString(KEY_CURRENT_PROFILE, profile.name()).apply();
    }

    public void clearAll() {
        preferences.edit().clear().apply();
    }
}
