package dev.guardianai.personal.ui.model;

public class FamilyDevice {
    private final String id;
    private final String deviceName;
    private final String assignedMember;
    private final String status;
    private final String lastSync;
    private final boolean isSeniorMode;

    public FamilyDevice(String id, String deviceName, String assignedMember, String status, String lastSync, boolean isSeniorMode) {
        this.id = id;
        this.deviceName = deviceName;
        this.assignedMember = assignedMember;
        this.status = status;
        this.lastSync = lastSync;
        this.isSeniorMode = isSeniorMode;
    }

    public String getId() {
        return id;
    }

    public String getDeviceName() {
        return deviceName;
    }

    public String getAssignedMember() {
        return assignedMember;
    }

    public String getStatus() {
        return status;
    }

    public String getLastSync() {
        return lastSync;
    }

    public boolean isSeniorMode() {
        return isSeniorMode;
    }
}
