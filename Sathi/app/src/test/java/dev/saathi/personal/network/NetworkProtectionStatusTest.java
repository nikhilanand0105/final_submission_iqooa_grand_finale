package dev.saathi.personal.network;

import org.junit.Test;

import static org.junit.Assert.*;

public class NetworkProtectionStatusTest {

    @Test
    public void testAllStatusesHaveValidBadgesAndDescriptions() {
        for (NetworkProtectionStatus status : NetworkProtectionStatus.values()) {
            assertNotNull("Badge text must not be null for " + status, status.getBadgeText());
            assertFalse("Badge text must not be empty for " + status, status.getBadgeText().trim().isEmpty());
            assertNotNull("Description must not be null for " + status, status.getDescription());
            assertFalse("Description must not be empty for " + status, status.getDescription().trim().isEmpty());
            assertTrue("Badge color must have full alpha for " + status, (status.getBadgeColor() & 0xFF000000) != 0);
        }
    }

    @Test
    public void testStatusSpecificSemantics() {
        // RUNNING must represent active protection
        assertEquals("PROTECTED", NetworkProtectionStatus.RUNNING.getBadgeText());
        assertTrue(NetworkProtectionStatus.RUNNING.getDescription().contains("Active on-device DNS firewall"));

        // STOPPED must be explicit about being inactive
        assertEquals("INACTIVE", NetworkProtectionStatus.STOPPED.getBadgeText());
        assertTrue(NetworkProtectionStatus.STOPPED.getDescription().contains("currently stopped"));

        // PERMISSION_NEEDED must state permission requirement
        assertEquals("PERMISSION NEEDED", NetworkProtectionStatus.PERMISSION_NEEDED.getBadgeText());
        assertTrue(NetworkProtectionStatus.PERMISSION_NEEDED.getDescription().contains("permission required"));

        // BLOCKED_BY_SYSTEM must note system restriction / VPN conflict
        assertEquals("BLOCKED BY SYSTEM", NetworkProtectionStatus.BLOCKED_BY_SYSTEM.getBadgeText());
        assertTrue(NetworkProtectionStatus.BLOCKED_BY_SYSTEM.getDescription().contains("Another VPN is active"));

        // FAILED must note error
        assertEquals("SERVICE ERROR", NetworkProtectionStatus.FAILED.getBadgeText());
        assertTrue(NetworkProtectionStatus.FAILED.getDescription().contains("Failed to bind"));
    }
}
