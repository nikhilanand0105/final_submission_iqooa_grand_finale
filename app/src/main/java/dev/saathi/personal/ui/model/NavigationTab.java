package dev.saathi.personal.ui.model;

public enum NavigationTab {
    HOME("Home"),
    SCAN("Scan"),
    ACTIVITY("Activity"),
    FAMILY("Family"),
    SETTINGS("Settings");

    private final String label;

    NavigationTab(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}
