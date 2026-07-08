package com.enterprise.securitygate;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Reads the NVIDIA Security Agent's {@code security-report.json} and
 * converts its pre-aggregated counts into normalised findings so the
 * Security Gate can correlate them with CodeQL and Trivy.
 *
 * <p>The agent's findings are advisory; the Security Gate only enforces
 * the count-based thresholds defined in {@link SecurityPolicy}.
 */
public final class NvidiaJsonParser {

    private final ObjectMapper mapper = new ObjectMapper();

    public List<Finding> parse(Path nvidiaJson) throws IOException {
        List<Finding> findings = new ArrayList<>();
        if (nvidiaJson == null || !Files.exists(nvidiaJson)) {
            return findings;
        }
        JsonNode root = mapper.readTree(Files.readAllBytes(nvidiaJson));

        if (root.has("findings") && root.get("findings").isArray()) {
            for (JsonNode f : root.get("findings")) {
                String id = textOrEmpty(f, "id");
                String severity = textOrEmpty(f, "severity");
                String category = textOrEmpty(f, "category");
                if (category.isEmpty()) category = textOrEmpty(f, "source");
                String description = textOrEmpty(f, "description");
                String fix = textOrEmpty(f, "fixedVersion");
                if (fix.isEmpty()) fix = textOrEmpty(f, "fix");
                String pkg = textOrEmpty(f, "package");
                if (pkg.isEmpty()) pkg = textOrEmpty(f, "packageName");

                findings.add(new Finding(
                        Finding.Source.NVIDIA,
                        id,
                        Severity.fromLabel(severity),
                        category,
                        pkg,
                        fix.isEmpty() ? null : fix,
                        description));
            }
        } else {
            // Fall back to the pre-aggregated counts if the agent only
            // produced top-level numbers. Each "finding" we synthesise
            // is anonymous, but the Security Gate still blocks on counts.
            int crit = root.path("critical").asInt(0);
            int high = root.path("high").asInt(0);
            int med  = root.path("medium").asInt(0);
            int low  = root.path("low").asInt(0);
            for (int i = 0; i < crit; i++) {
                findings.add(new Finding(Finding.Source.NVIDIA, "nvidia-aggregated",
                        Severity.CRITICAL, "vuln", "", null, "Aggregated NVIDIA critical finding"));
            }
            for (int i = 0; i < high; i++) {
                findings.add(new Finding(Finding.Source.NVIDIA, "nvidia-aggregated",
                        Severity.HIGH, "vuln", "", null, "Aggregated NVIDIA high finding"));
            }
            for (int i = 0; i < med; i++) {
                findings.add(new Finding(Finding.Source.NVIDIA, "nvidia-aggregated",
                        Severity.MEDIUM, "vuln", "", null, "Aggregated NVIDIA medium finding"));
            }
            for (int i = 0; i < low; i++) {
                findings.add(new Finding(Finding.Source.NVIDIA, "nvidia-aggregated",
                        Severity.LOW, "vuln", "", null, "Aggregated NVIDIA low finding"));
            }
        }
        return findings;
    }

    private static String textOrEmpty(JsonNode node, String field) {
        if (node == null) return "";
        JsonNode v = node.get(field);
        return v == null || v.isNull() ? "" : v.asText("");
    }
}
