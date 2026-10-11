package dev.guardianai.personal.data.apps;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.*;

/**
 * Unit tests for InstalledAppInfo permission categorization, high privilege detection,
 * and factual permission explanations.
 */
public class InstalledAppInfoTest {

    @Test
    public void testCleanAppMetadataAndPrivilege() {
        InstalledAppInfo cleanApp = new InstalledAppInfo(
                "org.guardianai.calculator",
                "GuardianAi Calculator",
                "2.1.0",
                210,
                34,
                false,
                null,
                1000L,
                2000L,
                Arrays.asList("android.permission.INTERNET", "android.permission.VIBRATE"),
                Collections.singletonList("android.permission.INTERNET")
        );

        assertEquals("org.guardianai.calculator", cleanApp.getPackageName());
        assertEquals("GuardianAi Calculator", cleanApp.getAppLabel());
        assertEquals("2.1.0", cleanApp.getVersionName());
        assertEquals(210, cleanApp.getVersionCode());
        assertEquals(34, cleanApp.getTargetSdk());
        assertFalse(cleanApp.isSystemApp());
        assertNull(cleanApp.getIcon());
        assertEquals(1000L, cleanApp.getFirstInstallTime());
        assertEquals(2000L, cleanApp.getLastUpdateTime());

        assertFalse("Clean calculator should not have accessibility service", cleanApp.hasAccessibilityService());
        assertFalse("Clean calculator should not have SMS permissions", cleanApp.hasSmsPermissions());
        assertFalse("Clean calculator should not have overlay permission", cleanApp.hasOverlayPermission());
        assertFalse("Clean calculator should not be high privilege", cleanApp.isHighPrivilege());

        assertTrue("Clean calculator should have 0 sensitive permissions", cleanApp.getSensitivePermissions().isEmpty());
        assertTrue(cleanApp.isPermissionGranted("android.permission.INTERNET"));
        assertFalse(cleanApp.isPermissionGranted("android.permission.VIBRATE"));
    }

    @Test
    public void testAccessibilityServiceDetection() {
        InstalledAppInfo accApp = new InstalledAppInfo(
                "com.assistive.screenreader",
                "Assistive Reader",
                "1.0",
                1,
                34,
                false,
                null,
                1000L,
                1000L,
                Collections.singletonList(InstalledAppInfo.PERM_ACCESSIBILITY),
                Collections.singletonList(InstalledAppInfo.PERM_ACCESSIBILITY)
        );

        assertTrue("Should detect accessibility service permission", accApp.hasAccessibilityService());
        assertTrue("Accessibility service makes app high privilege", accApp.isHighPrivilege());
        assertEquals(1, accApp.getSensitivePermissions().size());
        assertEquals(InstalledAppInfo.PERM_ACCESSIBILITY, accApp.getSensitivePermissions().get(0));
        assertTrue(accApp.isPermissionGranted(InstalledAppInfo.PERM_ACCESSIBILITY));
    }

    @Test
    public void testSmsPermissionsDetection() {
        InstalledAppInfo smsApp = new InstalledAppInfo(
                "com.messaging.client",
                "Messaging Client",
                "3.5",
                35,
                33,
                false,
                null,
                1000L,
                1000L,
                Arrays.asList(
                        InstalledAppInfo.PERM_RECEIVE_SMS,
                        InstalledAppInfo.PERM_READ_SMS,
                        "android.permission.INTERNET"
                ),
                Collections.singletonList(InstalledAppInfo.PERM_RECEIVE_SMS)
        );

        assertTrue("Should detect SMS permissions", smsApp.hasSmsPermissions());
        assertTrue("SMS permissions make app high privilege", smsApp.isHighPrivilege());
        assertEquals(2, smsApp.getSensitivePermissions().size());
        assertTrue(smsApp.isPermissionGranted(InstalledAppInfo.PERM_RECEIVE_SMS));
        assertFalse(smsApp.isPermissionGranted(InstalledAppInfo.PERM_READ_SMS));
    }

    @Test
    public void testOverlayPermissionDetection() {
        InstalledAppInfo overlayApp = new InstalledAppInfo(
                "com.floating.bubbles",
                "Floating Bubbles",
                "1.2",
                12,
                34,
                false,
                null,
                1000L,
                1000L,
                Collections.singletonList(InstalledAppInfo.PERM_OVERLAY),
                Collections.emptyList()
        );

        assertTrue("Should detect overlay permission", overlayApp.hasOverlayPermission());
        assertTrue("Overlay permission makes app high privilege", overlayApp.isHighPrivilege());
        assertFalse("Overlay permission was not granted", overlayApp.isPermissionGranted(InstalledAppInfo.PERM_OVERLAY));
    }

    @Test
    public void testSensitivePermissionClassification() {
        assertTrue(InstalledAppInfo.isSensitivePermission("android.permission.BIND_ACCESSIBILITY_SERVICE"));
        assertTrue(InstalledAppInfo.isSensitivePermission("android.permission.SYSTEM_ALERT_WINDOW"));
        assertTrue(InstalledAppInfo.isSensitivePermission("android.permission.RECEIVE_SMS"));
        assertTrue(InstalledAppInfo.isSensitivePermission("android.permission.READ_SMS"));
        assertTrue(InstalledAppInfo.isSensitivePermission("android.permission.SEND_SMS"));
        assertTrue(InstalledAppInfo.isSensitivePermission("android.permission.READ_CONTACTS"));
        assertTrue(InstalledAppInfo.isSensitivePermission("android.permission.RECORD_AUDIO"));
        assertTrue(InstalledAppInfo.isSensitivePermission("android.permission.CAMERA"));
        assertTrue(InstalledAppInfo.isSensitivePermission("android.permission.ACCESS_FINE_LOCATION"));

        // Benign / standard permissions
        assertFalse(InstalledAppInfo.isSensitivePermission("android.permission.INTERNET"));
        assertFalse(InstalledAppInfo.isSensitivePermission("android.permission.ACCESS_NETWORK_STATE"));
        assertFalse(InstalledAppInfo.isSensitivePermission("android.permission.VIBRATE"));
        assertFalse(InstalledAppInfo.isSensitivePermission("android.permission.WAKE_LOCK"));
        assertFalse(InstalledAppInfo.isSensitivePermission(null));
    }

    @Test
    public void testFactualPermissionExplanationsWithoutFearmongering() {
        String accExpl = InstalledAppInfo.getPermissionExplanation(InstalledAppInfo.PERM_ACCESSIBILITY);
        assertNotNull(accExpl);
        assertTrue("Should explain factual capability of reading screen and gestures",
                accExpl.contains("read text") || accExpl.contains("gestures") || accExpl.contains("assistive"));

        String smsExpl = InstalledAppInfo.getPermissionExplanation(InstalledAppInfo.PERM_RECEIVE_SMS);
        assertNotNull(smsExpl);
        assertTrue("Should mention OTP and incoming SMS verification factually",
                smsExpl.contains("OTP") || smsExpl.contains("SMS"));

        String overlayExpl = InstalledAppInfo.getPermissionExplanation(InstalledAppInfo.PERM_OVERLAY);
        assertNotNull(overlayExpl);
        assertTrue("Should mention floating windows factually",
                overlayExpl.contains("floating") || overlayExpl.contains("other app"));

        String label = InstalledAppInfo.getPermissionLabel(InstalledAppInfo.PERM_ACCESSIBILITY);
        assertEquals("Accessibility Service (Screen Control)", label);
    }

    @Test
    public void testSensitivePermissionDetailsExtraction() {
        InstalledAppInfo bankingApp = new InstalledAppInfo(
                "com.trusted.bank",
                "Trusted Mobile Banking",
                "5.0",
                500,
                34,
                false,
                null,
                1000L,
                1000L,
                Arrays.asList(
                        InstalledAppInfo.PERM_RECEIVE_SMS,
                        InstalledAppInfo.PERM_FINE_LOCATION,
                        "android.permission.INTERNET"
                ),
                Arrays.asList(
                        InstalledAppInfo.PERM_RECEIVE_SMS,
                        "android.permission.INTERNET"
                )
        );

        List<InstalledAppInfo.PermissionDetail> sensitiveDetails = bankingApp.getSensitivePermissionDetails();
        assertEquals(2, sensitiveDetails.size());

        InstalledAppInfo.PermissionDetail smsDetail = sensitiveDetails.get(0);
        assertEquals(InstalledAppInfo.PERM_RECEIVE_SMS, smsDetail.getPermission());
        assertEquals("Receive SMS Messages", smsDetail.getLabel());
        assertTrue(smsDetail.isGranted());
        assertTrue(smsDetail.isSensitive());

        InstalledAppInfo.PermissionDetail locDetail = sensitiveDetails.get(1);
        assertEquals(InstalledAppInfo.PERM_FINE_LOCATION, locDetail.getPermission());
        assertEquals("Precise GPS Location", locDetail.getLabel());
        assertFalse(locDetail.isGranted());
        assertTrue(locDetail.isSensitive());
    }

    @Test
    public void testSystemAppFlag() {
        InstalledAppInfo systemApp = new InstalledAppInfo(
                "com.android.settings",
                "Settings",
                "14",
                14,
                34,
                true,
                null,
                1000L,
                1000L,
                Collections.emptyList(),
                Collections.emptyList()
        );
        assertTrue(systemApp.isSystemApp());
    }
}
