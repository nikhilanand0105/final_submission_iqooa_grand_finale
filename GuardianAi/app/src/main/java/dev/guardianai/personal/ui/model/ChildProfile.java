package dev.guardianai.personal.ui.model;

public enum ChildProfile {
    AARAV("Aarav", 14, "Teen Protection", "Monitors APK sideloads, gaming chats, and phishing URLs.", 96),
    ANANYA("Ananya", 9, "Child Guardian", "Strict camera secrecy shield, grooming alerts, and safe search.", 100),
    DADAJI("Dadaji (Elderly)", 72, "Senior Mode", "High-contrast text, banking OTP theft protection, 1930 Helpline.", 92);

    private final String name;
    private final int age;
    private final String roleTitle;
    private final String description;
    private final int defaultSafetyScore;

    ChildProfile(String name, int age, String roleTitle, String description, int defaultSafetyScore) {
        this.name = name;
        this.age = age;
        this.roleTitle = roleTitle;
        this.description = description;
        this.defaultSafetyScore = defaultSafetyScore;
    }

    public String getName() {
        return name;
    }

    public int getAge() {
        return age;
    }

    public String getRoleTitle() {
        return roleTitle;
    }

    public String getDescription() {
        return description;
    }

    public int getDefaultSafetyScore() {
        return defaultSafetyScore;
    }
}
