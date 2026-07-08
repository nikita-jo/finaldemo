package com.enterprise.securitygate;

import java.util.List;
import java.util.Locale;

/**
 * Severity levels used across all scanners. The Security Gate maps each
 * scanner's native severity label (CodeQL "error"/"warning", Trivy
 * "CRITICAL"/"HIGH"/"MEDIUM"/"LOW", NVIDIA "CRITICAL"/"HIGH"/...) onto
 * this single enum so policies can be written in scanner-agnostic terms.
 */
public enum Severity {
    CRITICAL(4, "Critical"),
    HIGH(3, "High"),
    MEDIUM(2, "Medium"),
    LOW(1, "Low"),
    INFO(0, "Info");

    private final int weight;
    private final String display;

    Severity(int weight, String display) {
        this.weight = weight;
        this.display = display;
    }

    public int weight() {
        return weight;
    }

    public String display() {
        return display;
    }

    /** Best-effort mapping from arbitrary scanner labels. Unknown -> INFO. */
    public static Severity fromLabel(String label) {
        if (label == null) return INFO;
        String s = label.trim().toUpperCase(Locale.ROOT);
        return switch (s) {
            case "CRITICAL", "ERROR", "BLOCKER" -> CRITICAL;
            case "HIGH", "MAJOR" -> HIGH;
            case "MEDIUM", "MODERATE", "MINOR" -> MEDIUM;
            case "LOW", "INFO", "INFORMATIONAL", "NOTE" -> LOW;
            case "WARNING" -> MEDIUM;
            default -> INFO;
        };
    }
}
