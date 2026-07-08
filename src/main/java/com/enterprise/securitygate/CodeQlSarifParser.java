package com.enterprise.securitygate;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Parses a CodeQL SARIF v2.1.0 file into normalised {@link Finding}s.
 *
 * <p>CodeQL categorises issues with rule IDs like {@code java/sql-injection}
 * and severity levels ({@code error}, {@code warning}, {@code note}). We map
 * them to the Security Gate's {@link Severity} and {@code category} fields
 * using the last path segment of the rule ID (e.g. {@code sql-injection}).
 */
public final class CodeQlSarifParser {

    private final ObjectMapper mapper = new ObjectMapper();

    public List<Finding> parse(Path sarifPath) throws IOException {
        List<Finding> findings = new ArrayList<>();
        if (sarifPath == null || !Files.exists(sarifPath)) {
            return findings;
        }
        JsonNode root = mapper.readTree(Files.readAllBytes(sarifPath));

        // Build ruleId -> security-severity / problem severity lookup.
        java.util.Map<String, Severity> ruleSeverity = new java.util.HashMap<>();
        java.util.Map<String, String> ruleCategory = new java.util.HashMap<>();
        for (JsonNode run : root.withArray("runs")) {
            for (JsonNode tool : run.withArray("tool")) {
                for (JsonNode driver : tool.withArray("driver")) {
                    for (JsonNode rule : driver.withArray("rules")) {
                        String id = textOrEmpty(rule, "id");
                        if (id.isEmpty()) continue;
                        ruleSeverity.put(id, mapRuleSeverity(rule));
                        ruleCategory.put(id, inferCategory(id));
                    }
                }
            }
        }

        for (JsonNode run : root.withArray("runs")) {
            for (JsonNode result : run.withArray("results")) {
                String ruleId = textOrEmpty(result, "ruleId");
                if (ruleId.isEmpty()) continue;

                Severity sev = ruleSeverity.getOrDefault(ruleId, Severity.MEDIUM);
                String category = ruleCategory.getOrDefault(ruleId, "codeql");
                String message = textOrEmpty(result.get("message"), "text");
                String location = primaryLocation(result);
                String description = message.isEmpty() ? location
                        : message + (location.isEmpty() ? "" : " (" + location + ")");

                findings.add(new Finding(
                        Finding.Source.CODEQL,
                        ruleId,
                        sev,
                        category,
                        "",
                        null,
                        description));
            }
        }
        return findings;
    }

    private static Severity mapRuleSeverity(JsonNode rule) {
        // Prefer the security-severity tag (CodeQL sets "9.0", "8.5" etc).
        for (JsonNode prop : rule.withArray("properties")) {
            for (JsonNode tag : prop.withArray("security-severity")) {
                String s = tag.asText("").trim();
                if (s.isEmpty()) continue;
                try {
                    double score = Double.parseDouble(s);
                    if (score >= 9.0) return Severity.CRITICAL;
                    if (score >= 7.0) return Severity.HIGH;
                    if (score >= 4.0) return Severity.MEDIUM;
                    return Severity.LOW;
                } catch (NumberFormatException ignored) { /* fall through */ }
            }
        }
        // Fall back to the problem.severity field.
        for (JsonNode prop : rule.withArray("properties")) {
            for (JsonNode ps : prop.withArray("problem-severity")) {
                return Severity.fromLabel(ps.asText(""));
            }
        }
        // Fall back to the level field on the result.
        return Severity.MEDIUM;
    }

    private static String inferCategory(String ruleId) {
        if (ruleId == null) return "codeql";
        int slash = ruleId.lastIndexOf('/');
        return (slash < 0 ? ruleId : ruleId.substring(slash + 1))
                .toLowerCase(Locale.ROOT);
    }

    private static String primaryLocation(JsonNode result) {
        for (JsonNode loc : result.withArray("locations")) {
            for (JsonNode pl : loc.withArray("physicalLocation")) {
                String artifact = textOrEmpty(pl.get("artifactLocation"), "uri");
                for (JsonNode reg : pl.withArray("region")) {
                    int line = reg.path("startLine").asInt(0);
                    if (!artifact.isEmpty() && line > 0) {
                        return artifact + ":" + line;
                    }
                    if (!artifact.isEmpty()) return artifact;
                }
                if (!artifact.isEmpty()) return artifact;
            }
        }
        return "";
    }

    private static String textOrEmpty(JsonNode node, String field) {
        if (node == null) return "";
        JsonNode v = node.get(field);
        return v == null || v.isNull() ? "" : v.asText("");
    }
}
