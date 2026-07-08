package com.enterprise.securitygate;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Writes a compact machine-readable summary of the Security Gate run.
 * Mirrors the schema of {@code security-report.json} so downstream
 * tooling can treat the two as a small, predictable bundle.
 */
public final class JsonSummaryWriter {

    public static void write(Path out,
                             SecurityPolicy.Decision decision,
                             List<Finding> findings,
                             String commit) throws IOException {
        int c = 0, h = 0, m = 0, l = 0;
        List<String> blockers = new ArrayList<>(decision.reasons());
        for (Finding f : findings) {
            switch (f.severity()) {
                case CRITICAL -> c++;
                case HIGH -> h++;
                case MEDIUM -> m++;
                case LOW, INFO -> l++;
            }
        }
        int riskScore = Math.min(100, (int) Math.round(((c * 15) + (h * 7) + (m * 3) + l) * 100.0 / 126.0));

        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"status\": \"").append(decision.status()).append("\",\n");
        sb.append("  \"critical\": ").append(c).append(",\n");
        sb.append("  \"high\": ").append(h).append(",\n");
        sb.append("  \"medium\": ").append(m).append(",\n");
        sb.append("  \"low\": ").append(l).append(",\n");
        sb.append("  \"riskScore\": ").append(riskScore).append(",\n");
        sb.append("  \"commit\": \"").append(escape(commit == null ? "" : commit)).append("\",\n");
        sb.append("  \"generatedAt\": \"")
          .append(OffsetDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME))
          .append("\",\n");
        sb.append("  \"summary\": \"");
        sb.append(escape(decision.isPass()
                ? "No blocking vulnerabilities detected."
                : "Pipeline blocked: " + String.join("; ", decision.reasons())));
        sb.append("\",\n");
        sb.append("  \"recommendations\": [");
        List<String> recs = collectRecommendations(findings);
        for (int i = 0; i < recs.size(); i++) {
            sb.append(i == 0 ? "" : ", ").append("\"").append(escape(recs.get(i))).append("\"");
        }
        sb.append("],\n");
        sb.append("  \"blockingReasons\": [");
        for (int i = 0; i < blockers.size(); i++) {
            sb.append(i == 0 ? "" : ", ").append("\"").append(escape(blockers.get(i))).append("\"");
        }
        sb.append("]\n");
        sb.append("}\n");

        if (out.getParent() != null) {
            Files.createDirectories(out.getParent());
        }
        Files.writeString(out, sb.toString(), StandardCharsets.UTF_8);
    }

    private static List<String> collectRecommendations(List<Finding> findings) {
        List<String> out = new ArrayList<>();
        for (Finding f : findings) {
            if (f.severity() != Severity.CRITICAL && f.severity() != Severity.HIGH) continue;
            if (f.fix() != null && !f.fix().isBlank() && !f.packageName().isEmpty()) {
                out.add("Upgrade " + f.packageName() + " to " + f.fix()
                        + " (" + f.source() + " " + f.ruleId() + ")");
            }
            if (out.size() >= 10) break;
        }
        if (out.isEmpty()) out.add("No blocking vulnerabilities detected.");
        return out;
    }

    private static String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", " ").replace("\r", " ");
    }
}
