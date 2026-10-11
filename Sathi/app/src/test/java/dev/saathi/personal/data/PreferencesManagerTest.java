package dev.saathi.personal.data;

import android.content.SharedPreferences;

import org.junit.Before;
import org.junit.Test;

import dev.saathi.personal.data.prefs.PreferencesManager;
import dev.saathi.personal.ui.model.ChildProfile;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.*;

public class PreferencesManagerTest {

    private InMemorySharedPreferences inMemoryPrefs;
    private PreferencesManager prefsManager;

    @Before
    public void setUp() {
        inMemoryPrefs = new InMemorySharedPreferences();
        prefsManager = new PreferencesManager(inMemoryPrefs);
    }

    @Test
    public void testDefaultPreferences() {
        assertFalse(prefsManager.isOnboardingCompleted());
        assertFalse(prefsManager.isSeniorMode());
        assertFalse(prefsManager.isLargeText());
        assertFalse(prefsManager.isHighContrast());
        assertFalse(prefsManager.isHindi());
        assertEquals(ChildProfile.AARAV, prefsManager.getCurrentProfile());
    }

    @Test
    public void testSetAndGetOnboarding() {
        prefsManager.setOnboardingCompleted(true);
        assertTrue(prefsManager.isOnboardingCompleted());
        prefsManager.setOnboardingCompleted(false);
        assertFalse(prefsManager.isOnboardingCompleted());
    }

    @Test
    public void testSetAndGetAccessibilityOptions() {
        prefsManager.setSeniorMode(true);
        assertTrue(prefsManager.isSeniorMode());

        prefsManager.setLargeText(true);
        assertTrue(prefsManager.isLargeText());

        prefsManager.setHighContrast(true);
        assertTrue(prefsManager.isHighContrast());

        prefsManager.setHindi(true);
        assertTrue(prefsManager.isHindi());
    }

    @Test
    public void testSetAndGetProfiles() {
        prefsManager.setCurrentProfile(ChildProfile.DADAJI);
        assertEquals(ChildProfile.DADAJI, prefsManager.getCurrentProfile());

        prefsManager.setCurrentProfile(ChildProfile.ANANYA);
        assertEquals(ChildProfile.ANANYA, prefsManager.getCurrentProfile());
    }

    @Test
    public void testClearAllPreferences() {
        prefsManager.setOnboardingCompleted(true);
        prefsManager.setSeniorMode(true);
        prefsManager.clearAll();

        assertFalse(prefsManager.isOnboardingCompleted());
        assertFalse(prefsManager.isSeniorMode());
    }

    /**
     * Minimal in-memory SharedPreferences implementation for fast JVM unit tests.
     */
    private static class InMemorySharedPreferences implements SharedPreferences {
        private final Map<String, Object> map = new HashMap<>();

        @Override
        public Map<String, ?> getAll() { return map; }

        @Override
        public String getString(String key, String defValue) {
            Object val = map.get(key);
            return val instanceof String ? (String) val : defValue;
        }

        @Override
        public Set<String> getStringSet(String key, Set<String> defValues) { return defValues; }

        @Override
        public int getInt(String key, int defValue) {
            Object val = map.get(key);
            return val instanceof Integer ? (Integer) val : defValue;
        }

        @Override
        public long getLong(String key, long defValue) {
            Object val = map.get(key);
            return val instanceof Long ? (Long) val : defValue;
        }

        @Override
        public float getFloat(String key, float defValue) {
            Object val = map.get(key);
            return val instanceof Float ? (Float) val : defValue;
        }

        @Override
        public boolean getBoolean(String key, boolean defValue) {
            Object val = map.get(key);
            return val instanceof Boolean ? (Boolean) val : defValue;
        }

        @Override
        public boolean contains(String key) { return map.containsKey(key); }

        @Override
        public Editor edit() { return new InMemoryEditor(map); }

        @Override
        public void registerOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener listener) {}

        @Override
        public void unregisterOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener listener) {}
    }

    private static class InMemoryEditor implements SharedPreferences.Editor {
        private final Map<String, Object> target;
        private final Map<String, Object> pending = new HashMap<>();
        private boolean clearRequested = false;

        InMemoryEditor(Map<String, Object> target) { this.target = target; }

        @Override
        public SharedPreferences.Editor putString(String key, String value) { pending.put(key, value); return this; }

        @Override
        public SharedPreferences.Editor putStringSet(String key, Set<String> values) { pending.put(key, values); return this; }

        @Override
        public SharedPreferences.Editor putInt(String key, int value) { pending.put(key, value); return this; }

        @Override
        public SharedPreferences.Editor putLong(String key, long value) { pending.put(key, value); return this; }

        @Override
        public SharedPreferences.Editor putFloat(String key, float value) { pending.put(key, value); return this; }

        @Override
        public SharedPreferences.Editor putBoolean(String key, boolean value) { pending.put(key, value); return this; }

        @Override
        public SharedPreferences.Editor remove(String key) { pending.put(key, this); return this; }

        @Override
        public SharedPreferences.Editor clear() { clearRequested = true; return this; }

        @Override
        public boolean commit() { apply(); return true; }

        @Override
        public void apply() {
            if (clearRequested) target.clear();
            for (Map.Entry<String, Object> entry : pending.entrySet()) {
                if (entry.getValue() == this) {
                    target.remove(entry.getKey());
                } else {
                    target.put(entry.getKey(), entry.getValue());
                }
            }
        }
    }
}
