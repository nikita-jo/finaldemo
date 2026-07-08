package com.enterprise.securitygate;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;

/**
 * Parses the JSON returned by SonarQube's
 * <code>api/measures/component?component=…&amp;metricKeys=…</code> endpoint
 * and emits one synthetic {@link Finding} per Quality Gate condition.
 *
 * <p>Each finding encodes a single rule from the task brief (blocker &gt; 0,
 * critical &gt; 0, security rating &lt; A, …). The actual threshold
 * evaluation is performed by {@link SecurityPolicy}, so this parser stays
 * pure: it only translates server output into findings, it does not make
 * pass/fail decisions.
 *
 * <p>Example input (truncated):
 * <pre>
 * {
 *   "component": {
 *     "key": "com.enterprise:employee-management",
 *     "name": "Employee Management Service",
 *     "qualifier": "TRK",
 *     "measures": [
 *       { "metric": "blocker_violations",     "value": "0",   "period": { "index": 1, "value": "0" } },
 *       { "metric": "critical_violations",    "value": "0",   "period": { "index": 1, "value": "0" } },
 *       { "metric": "security_rating",        "value": "1" },
 *       { "metric": "reliability_rating",     "value": "1" },
 *       { "metric": "new_coverage",           "value": "82.3" },
 *       { "metric": "duplicated_lines_density","value": "2.1" },
 *       { "metric": "new_bugs",               "value": "0" }
 *     ]
 *   }
 * }
 * </pre>
 *
 * <p>Measures include both a global {@code value} and, when "new code"
 * is enabled, a {@code periods[0].value}. New-code metrics are preferred
 * when both are present.
 */
public final class SonarQubeMeasuresParser {

    /**
     * Metric keys the parser is interested in. Additional keys present
     * in the response are ignored — the brief enumerates exactly these.
     */
    public static final List<String> TRACKED_METRICS = List.of(
            "blocker_violations",
            "critical_violations",
            "new_bugs",
            "new_vulnerabilities",
            "security_rating",
            "reliability_rating",
            "new_security_rating",
            "new_reliability_rating",
            "coverage",
            "new_coverage",
            "duplicated_lines_density",
            "quality_gate_details");

    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * Parse a SonarQube measures/component response.
     *
     * @param measuresJson path to the JSON file, or {@code null} if missing
     * @return the list of synthetic findings, one per Quality Gate condition
     * @throws IOException if the file exists but cannot be read
     */
    public List<Finding> parse(Path measuresJson) throws IOException {
        List<Finding> out = new ArrayList<>();
        if (measuresJson == null || !Files.exists(measuresJson)) {
            return out;
        }
        JsonNode root = mapper.readTree(Files.readAllBytes(measuresJson));

        JsonNode component = root.path("component");
        if (component.isMissingNode() || component.isNull()) {
            return out;
        }

        // Pre-index measures for O(1) lookup. Each metric in the response
        // is a separate object; the values of interest live in `value`
        // and (for "new_*" metrics) `periods[0].value`.
        java.util.Map<String, JsonNode> byMetric = new java.util.HashMap<>();
        for (JsonNode m : component.withArray("measures")) {
            String key = m.path("metric").asText("");
            if (!key.isEmpty()) byMetric.put(key, m);
        }

        // ---------------- Issue counts ----------------
        emitCount(out, byMetric, "blocker_violations", "blocker-issues");
        emitCount(out, byMetric, "critical_violations", "critical-issues");
        emitCount(out, byMetric, "new_bugs", "new-bugs");
        emitCount(out, byMetric, "new_vulnerabilities", "new-vulnerabilities");

        // ---------------- Ratings (1 = A, 2 = B, …) ----------------
        emitRating(out, byMetric, "security_rating", "security-rating");
        emitRating(out, byMetric, "reliability_rating", "reliability-rating");
        emitRating(out, byMetric, "new_security_rating", "new-security-rating");
        emitRating(out, byMetric, "new_reliability_rating", "new-reliability-rating");

        // ---------------- Coverage (%) ----------------
        emitPercent(out, byMetric, "coverage", "coverage");
        emitPercent(out, byMetric, "new_coverage", "new-coverage");

        // ---------------- Duplications (%) ----------------
        emitPercent(out, byMetric, "duplicated_lines_density", "duplications");

        return out;
    }

    // ------------------------------------------------------------------
    // Emitters
    // ------------------------------------------------------------------

    private static void emitCount(List<Finding> out,
                                  java.util.Map<String, JsonNode> byMetric,
                                  String metricKey,
                                  String category) {
        JsonNode m = byMetric.get(metricKey);
        if (m == null) return;
        int value = readInt(m);
        out.add(new Finding(
                Finding.Source.SONAR,
                "sonar:" + metricKey,
                Severity.CRITICAL,
                category,
                "",
                null,
                metricKey + " = " + value));
    }

    private static void emitRating(List<Finding> out,
                                   java.util.Map<String, JsonNode> byMetric,
                                   String metricKey,
                                   String category) {
        JsonNode m = byMetric.get(metricKey);
        if (m == null) return;
        // A rating in the response is the letter itself when
        // `&ratingMode=letter` is set, or a number 1..5 otherwise.
        // We normalise both to a numeric 1..5 scale.
        String raw = m.path("value").asText("");
        int numeric = parseRating(raw);
        if (numeric <= 0) {
            // Fallback: treat the letter string as informational only.
            out.add(new Finding(
                    Finding.Source.SONAR,
                    "sonar:" + metricKey,
                    Severity.HIGH,
                    category,
                    "",
                    null,
                    metricKey + " = " + (raw.isEmpty() ? "?" : raw)));
            return;
        }
        out.add(new Finding(
                Finding.Source.SONAR,
                "sonar:" + metricKey,
                Severity.CRITICAL,
                category,
                "",
                null,
                metricKey + " = " + numeric + " (" + ratingLetter(numeric) + ")"));
    }

    private static void emitPercent(List<Finding> out,
                                    java.util.Map<String, JsonNode> byMetric,
                                    String metricKey,
                                    String category) {
        JsonNode m = byMetric.get(metricKey);
        if (m == null) return;
        double value = readDouble(m);
        if (Double.isNaN(value)) return;
        out.add(new Finding(
                Finding.Source.SONAR,
                "sonar:" + metricKey,
                Severity.CRITICAL,
                category,
                "",
                null,
                metricKey + " = " + formatPercent(value) + "%"));
    }

    // ------------------------------------------------------------------
    // Value extraction helpers
    // ------------------------------------------------------------------

    /**
     * Read the best available value for a measure. Prefers the
     * first period's value (new-code slice) when present, otherwise
     * falls back to the global value.
     */
    private static String readValueText(JsonNode measure) {
        JsonNode periods = measure.path("periods");
        if (periods.isArray() && periods.size() > 0) {
            String v = periods.get(0).path("value").asText("");
            if (!v.isEmpty()) return v;
        }
        String v = measure.path("value").asText("");
        return v;
    }

    private static int readInt(JsonNode measure) {
        try {
            return Integer.parseInt(readValueText(measure).trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static double readDouble(JsonNode measure) {
        try {
            return Double.parseDouble(readValueText(measure).trim());
        } catch (NumberFormatException e) {
            return Double.NaN;
        }
    }

    /**
     * SonarQube's rating format is either a letter (A..E) or a number
     * 1..5. Convert either into a numeric value, or 0 if unparseable.
     */
    static int parseRating(String raw) {
        if (raw == null) return 0;
        String s = raw.trim();
        if (s.isEmpty()) return 0;
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException ignored) {
            // Fall through to letter parsing.
        }
        switch (s.toUpperCase(Locale.ROOT)) {
            case "A": return 1;
            case "B": return 2;
            case "C": return 3;
            case "D": return 4;
            case "E": return 5;
            default:  return 0;
        }
    }

    static String ratingLetter(int numeric) {
        return switch (numeric) {
            case 1 -> "A";
            case 2 -> "B";
            case 3 -> "C";
            case 4 -> "D";
            case 5 -> "E";
            default -> "?";
        };
    }

    private static String formatPercent(double v) {
        if (v == Math.floor(v) && !Double.isInfinite(v)) {
            return String.format(Locale.ROOT, "%.1f", v);
        }
        return String.format(Locale.ROOT, "%.2f", v);
    }

    /**
     * Expose the list of metric keys the workflow should request.
     * Kept in sync with {@link #TRACKED_METRICS} for use in
     * <code>metricKeys=…</code> query strings.
     */
    public static String metricKeysQueryParam() {
        StringBuilder sb = new StringBuilder();
        Iterator<String> it = TRACKED_METRICS.iterator();
        while (it.hasNext()) {
            sb.append(it.next());
            if (it.hasNext()) sb.append(',');
        }
        return sb.toString();
    }
}
