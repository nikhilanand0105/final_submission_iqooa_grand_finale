package dev.saathi.model;

public enum ThreatSeverity {
    CRITICAL(4),
    HIGH(3),
    MEDIUM(2),
    LOW(1),
    INFO(0);

    private final int weight;

    ThreatSeverity(int weight) {
        this.weight = weight;
    }

    public int getWeight() {
        return weight;
    }
}
