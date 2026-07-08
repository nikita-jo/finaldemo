package com.enterprise.securitygate;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Evaluates a list of normalised {@link Finding}s against a configured
 * security policy and produces a {@link Decision}.
 *
 * <p>Policies are intentionally explicit and scanner-agnostic:
 * <ul>
 *   <li>Count-based thresholds: e.g. "no more than 5 HIGH per source".</li>
 *   <li>Category-based blocking: e.g. "any SQL injection finding fails".</li>
 *   <li>Severity-floor blocking: e.g. "any CRITICAL fails".</li>
 * </ul>
 *
 * <p>To add a new scanner, write a {@link Finding.Source#CODEQL}-style
 * producer and reuse these rules — there is no scanner-specific code in
 * this class.
 */
public final class SecurityPolicy {

    /** Per-source caps on a given severity. */
    public static final class SeverityThresholds {
        public final int criticalMax;
        public final int highMax;
        public final int mediumMax;
        public final int lowMax;

        public SeverityThresholds(int criticalMax, int highMax, int mediumMax, int lowMax) {
            this.criticalMax = criticalMax;
            this.highMax = highMax;
            this.mediumMax = mediumMax;
            this.lowMax = lowMax;
        }

        public static SeverityThresholds of(int crit, int high, int med, int low) {
            return new SeverityThresholds(crit, high, med, low);
        }

        public static SeverityThresholds lenient() {
            return new SeverityThresholds(Integer.MAX_VALUE, Integer.MAX_VALUE,
                                          Integer.MAX_VALUE, Integer.MAX_VALUE);
        }
    }

    /**
     * Quality Gate thresholds evaluated from SonarQube's
     * <code>api/measures/component</code> response. The defaults match the
     * task brief exactly.
     *
     * <p>Ratings are numeric: 1 = A, 2 = B, 3 = C, 4 = D, 5 = E. A
     * "Security Rating is below A" check is therefore expressed as
     * <code>securityRating &gt; securityRatingMax (=1)</code>.
     */
    public static final class SonarGate {
        public final int blockerMax;             // 0 by default
        public final int criticalMax;            // 0 by default
        public final int newBugsMax;             // 0 by default
        public final int newVulnerabilitiesMax;  // 0 by default
        public final int securityRatingMax;      // 1 = "must be A"
        public final int reliabilityRatingMax;   // 1 = "must be A"
        public final int newSecurityRatingMax;   // 1 = "new code security must be A"
        public final int newReliabilityRatingMax;// 1 = "new code reliability must be A"
        public final double coverageMin;         // 80.0 by default
        public final double newCoverageMin;      // 80.0 by default
        public final double duplicationsMax;     // 3.0 by default

        public SonarGate(int blockerMax,
                         int criticalMax,
                         int newBugsMax,
                         int newVulnerabilitiesMax,
                         int securityRatingMax,
                         int reliabilityRatingMax,
                         int newSecurityRatingMax,
                         int newReliabilityRatingMax,
                         double coverageMin,
                         double newCoverageMin,
                         double duplicationsMax) {
            this.blockerMax = blockerMax;
            this.criticalMax = criticalMax;
            this.newBugsMax = newBugsMax;
            this.newVulnerabilitiesMax = newVulnerabilitiesMax;
            this.securityRatingMax = securityRatingMax;
            this.reliabilityRatingMax = reliabilityRatingMax;
            this.newSecurityRatingMax = newSecurityRatingMax;
            this.newReliabilityRatingMax = newReliabilityRatingMax;
            this.coverageMin = coverageMin;
            this.newCoverageMin = newCoverageMin;
            this.duplicationsMax = duplicationsMax;
        }

        /** The values from the task brief. */
        public static SonarGate defaults() {
            return new SonarGate(
                    0,  // blockerMax
                    0,  // criticalMax
                    0,  // newBugsMax
                    0,  // newVulnerabilitiesMax
                    1,  // securityRatingMax     (1 == A)
                    1,  // reliabilityRatingMax  (1 == A)
                    1,  // newSecurityRatingMax
                    1,  // newReliabilityRatingMax
                    80.0, // coverageMin
                    80.0, // newCoverageMin
                    3.0); // duplicationsMax
        }
    }

    private final SeverityThresholds trivy;
    private final SeverityThresholds nvidia;
    private final boolean codeqlBlockOnCritical;
    private final boolean codeqlBlockOnHighRce;
    private final List<String> codeqlBlockedCategories;   // lower-cased
    private final boolean trivyBlockOnFixableCritical;
    private final boolean trivyBlockOnMalware;
    private final boolean trivyBlockOnSecret;
    private final List<String> ignoredRules;             // lower-cased rule IDs
    private final SonarGate sonarGate;

    private SecurityPolicy(Builder b) {
        this.trivy = Objects.requireNonNull(b.trivy, "trivy thresholds");
        this.nvidia = Objects.requireNonNull(b.nvidia, "nvidia thresholds");
        this.codeqlBlockOnCritical = b.codeqlBlockOnCritical;
        this.codeqlBlockOnHighRce = b.codeqlBlockOnHighRce;
        this.codeqlBlockedCategories = lower(b.codeqlBlockedCategories);
        this.trivyBlockOnFixableCritical = b.trivyBlockOnFixableCritical;
        this.trivyBlockOnMalware = b.trivyBlockOnMalware;
        this.trivyBlockOnSecret = b.trivyBlockOnSecret;
        this.ignoredRules = lower(b.ignoredRules);
        this.sonarGate = Objects.requireNonNull(b.sonarGate, "sonar gate");
    }

    public SeverityThresholds trivyThresholds()   { return trivy; }
    public SeverityThresholds nvidiaThresholds()  { return nvidia; }
    public SonarGate sonarGate()                  { return sonarGate; }

    /**
     * Run the policy. Findings whose ruleId is in {@code ignoredRules} are
     * dropped before evaluation.
     */
    public Decision evaluate(List<Finding> findings) {
        Objects.requireNonNull(findings, "findings");
        List<Finding> active = findings.stream()
                .filter(f -> !ignoredRules.contains(f.ruleId().toLowerCase(java.util.Locale.ROOT)))
                .toList();

        List<String> reasons = new ArrayList<>();
        Map<Finding.Source, int[]> counts = new LinkedHashMap<>();
        for (Finding.Source s : Finding.Source.values()) {
            counts.put(s, new int[Severity.values().length]);
        }
        for (Finding f : active) {
            counts.get(f.source())[f.severity().weight()]++;
        }

        // ----- CodeQL -----
        if (codeqlBlockOnCritical) {
            int c = counts.get(Finding.Source.CODEQL)[Severity.CRITICAL.weight()];
            if (c > 0) reasons.add("CodeQL: %d critical issue(s) detected".formatted(c));
        }
        if (codeqlBlockOnHighRce) {
            for (Finding f : active) {
                if (f.source() == Finding.Source.CODEQL
                        && f.severity() == Severity.HIGH
                        && containsAny(f.category(),
                                "rce", "remote-code-execution", "code-execution", "command-injection")) {
                    reasons.add("CodeQL: high-severity RCE / command-injection detected (%s)"
                            .formatted(f.ruleId()));
                    break;
                }
            }
        }
        for (String blocked : codeqlBlockedCategories) {
            for (Finding f : active) {
                if (f.source() == Finding.Source.CODEQL && f.category().contains(blocked)) {
                    reasons.add("CodeQL: blocked category '%s' detected (%s)"
                            .formatted(blocked, f.ruleId()));
                    break;
                }
            }
        }

        // ----- Trivy -----
        int trivyCrit = counts.get(Finding.Source.TRIVY)[Severity.CRITICAL.weight()];
        int trivyHigh = counts.get(Finding.Source.TRIVY)[Severity.HIGH.weight()];
        if (trivyCrit > trivy.criticalMax) {
            reasons.add("Trivy: %d critical vulnerabilities exceed threshold (%d)"
                    .formatted(trivyCrit, trivy.criticalMax));
        }
        if (trivyHigh > trivy.highMax) {
            reasons.add("Trivy: %d high vulnerabilities exceed threshold (%d)"
                    .formatted(trivyHigh, trivy.highMax));
        }
        if (trivyBlockOnFixableCritical) {
            long fixableCrit = active.stream()
                    .filter(f -> f.source() == Finding.Source.TRIVY
                              && f.severity() == Severity.CRITICAL
                              && f.fix() != null && !f.fix().isBlank()
                              && !f.fix().equalsIgnoreCase("n/a"))
                    .count();
            if (fixableCrit > 0) {
                reasons.add("Trivy: %d fixable critical vulnerabilities present".formatted(fixableCrit));
            }
        }
        if (trivyBlockOnMalware) {
            for (Finding f : active) {
                if (f.source() == Finding.Source.TRIVY
                        && (f.category().contains("malware") || f.category().contains("virus"))) {
                    reasons.add("Trivy: malware finding %s".formatted(f.ruleId()));
                    break;
                }
            }
        }
        if (trivyBlockOnSecret) {
            for (Finding f : active) {
                if (f.source() == Finding.Source.TRIVY && f.category().contains("secret")) {
                    reasons.add("Trivy: secret finding %s".formatted(f.ruleId()));
                    break;
                }
            }
        }

        // ----- NVIDIA -----
        int nvidiaCrit = counts.get(Finding.Source.NVIDIA)[Severity.CRITICAL.weight()];
        int nvidiaHigh = counts.get(Finding.Source.NVIDIA)[Severity.HIGH.weight()];
        if (nvidiaCrit > nvidia.criticalMax) {
            reasons.add("NVIDIA: %d critical issues exceed threshold (%d)"
                    .formatted(nvidiaCrit, nvidia.criticalMax));
        }
        if (nvidiaHigh > nvidia.highMax) {
            reasons.add("NVIDIA: %d high issues exceed threshold (%d)"
                    .formatted(nvidiaHigh, nvidia.highMax));
        }

        // ----- SonarQube Quality Gate (defense in depth) -----
        // SonarQube already enforced these conditions server-side via
        // its built-in Quality Gate, and the `sonarqube-quality-gate-action`
        // step will have failed the job if the server said "FAILED".
        // We re-evaluate the same conditions here so a mis-configured
        // server, a disabled gate, or a missing endpoint cannot let a
        // bad build pass.
        evaluateSonar(reasons, active);

        return new Decision(reasons.isEmpty() ? "PASS" : "FAIL", reasons, counts);
    }

    /** A policy decision. {@code reasons} is empty when the policy passes. */
    public record Decision(String status, List<String> reasons,
                           Map<Finding.Source, int[]> counts) {
        public Decision {
            reasons = Collections.unmodifiableList(new ArrayList<>(reasons));
        }
        public boolean isPass() { return "PASS".equals(status); }
    }

    // ------------------------------------------------------------------
    // SonarQube evaluation
    // ------------------------------------------------------------------

    /**
     * Inspect every {@link Finding.Source#SONAR} finding (produced by
     * {@link SonarQubeMeasuresParser}) and add a reason for each Quality
     * Gate rule that failed. Each rule mirrors the condition from the
     * task brief.
     */
    private void evaluateSonar(List<String> reasons, List<Finding> active) {
        SonarGate g = sonarGate;

        // Issue counts. The parser emits one finding per metric key, so
        // we look up the value from the description (e.g. "blocker_violations = 0").
        Integer blocker = sonarIntMetric(active, "blocker_violations");
        if (blocker != null && blocker > g.blockerMax) {
            reasons.add("SonarQube: %d blocker issue(s) exceed threshold (%d)"
                    .formatted(blocker, g.blockerMax));
        }

        Integer critical = sonarIntMetric(active, "critical_violations");
        if (critical != null && critical > g.criticalMax) {
            reasons.add("SonarQube: %d critical issue(s) exceed threshold (%d)"
                    .formatted(critical, g.criticalMax));
        }

        Integer newBugs = sonarIntMetric(active, "new_bugs");
        if (newBugs != null && newBugs > g.newBugsMax) {
            reasons.add("SonarQube: %d new bug(s) detected (threshold %d)"
                    .formatted(newBugs, g.newBugsMax));
        }

        Integer newVulns = sonarIntMetric(active, "new_vulnerabilities");
        if (newVulns != null && newVulns > g.newVulnerabilitiesMax) {
            reasons.add("SonarQube: %d new vulnerabilit(ies) detected (threshold %d)"
                    .formatted(newVulns, g.newVulnerabilitiesMax));
        }

        // Ratings — 1 == A. Anything > 1 is below A.
        Integer sec = sonarRating(active, "security_rating");
        if (sec != null && sec > g.securityRatingMax) {
            reasons.add("SonarQube: security rating is below A (observed %d, threshold 1)"
                    .formatted(sec));
        }
        Integer rel = sonarRating(active, "reliability_rating");
        if (rel != null && rel > g.reliabilityRatingMax) {
            reasons.add("SonarQube: reliability rating is below A (observed %d, threshold 1)"
                    .formatted(rel));
        }
        Integer newSec = sonarRating(active, "new_security_rating");
        if (newSec != null && newSec > g.newSecurityRatingMax) {
            reasons.add("SonarQube: new-code security rating is below A (observed %d, threshold 1)"
                    .formatted(newSec));
        }
        Integer newRel = sonarRating(active, "new_reliability_rating");
        if (newRel != null && newRel > g.newReliabilityRatingMax) {
            reasons.add("SonarQube: new-code reliability rating is below A (observed %d, threshold 1)"
                    .formatted(newRel));
        }

        // Coverage — strictly less than the minimum is a fail. We treat
        // a missing coverage value as "unknown" and do not block.
        Double cov = sonarDoubleMetric(active, "new_coverage");
        if (cov == null) cov = sonarDoubleMetric(active, "coverage");
        if (cov != null && cov < g.newCoverageMin) {
            reasons.add("SonarQube: coverage %.1f%% is below threshold %.1f%%"
                    .formatted(cov, g.newCoverageMin));
        }

        Double dup = sonarDoubleMetric(active, "duplicated_lines_density");
        if (dup != null && dup > g.duplicationsMax) {
            reasons.add("SonarQube: duplicated code %.1f%% exceeds threshold %.1f%%"
                    .formatted(dup, g.duplicationsMax));
        }
    }

    /**
     * Parse the integer stored in a SonarQube finding's description
     * (e.g. <code>"blocker_violations = 3"</code> → 3). Returns
     * {@code null} if the metric is absent in the input.
     */
    private static Integer sonarIntMetric(List<Finding> active, String metricKey) {
        for (Finding f : active) {
            if (f.source() != Finding.Source.SONAR) continue;
            if (!f.ruleId().equals("sonar:" + metricKey)) continue;
            String desc = f.description();
            int eq = desc.lastIndexOf('=');
            if (eq < 0) continue;
            try {
                return Integer.parseInt(desc.substring(eq + 1).trim());
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private static Integer sonarRating(List<Finding> active, String metricKey) {
        for (Finding f : active) {
            if (f.source() != Finding.Source.SONAR) continue;
            if (!f.ruleId().equals("sonar:" + metricKey)) continue;
            String desc = f.description();
            int eq = desc.lastIndexOf('=');
            if (eq < 0) continue;
            String tail = desc.substring(eq + 1).trim();
            // The parser formats ratings as "1 (A)".
            int sp = tail.indexOf(' ');
            String num = sp > 0 ? tail.substring(0, sp) : tail;
            try {
                return Integer.parseInt(num);
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private static Double sonarDoubleMetric(List<Finding> active, String metricKey) {
        for (Finding f : active) {
            if (f.source() != Finding.Source.SONAR) continue;
            if (!f.ruleId().equals("sonar:" + metricKey)) continue;
            String desc = f.description();
            int eq = desc.lastIndexOf('=');
            if (eq < 0) continue;
            String tail = desc.substring(eq + 1).trim();
            // Strip the trailing "%" if present.
            if (tail.endsWith("%")) tail = tail.substring(0, tail.length() - 1);
            try {
                return Double.parseDouble(tail);
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    // ------------------------------------------------------------------
    // Builder
    // ------------------------------------------------------------------

    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        private SeverityThresholds trivy = new SeverityThresholds(0, 5, Integer.MAX_VALUE, Integer.MAX_VALUE);
        private SeverityThresholds nvidia = new SeverityThresholds(0, 5, Integer.MAX_VALUE, Integer.MAX_VALUE);
        private boolean codeqlBlockOnCritical = true;
        private boolean codeqlBlockOnHighRce = true;
        private List<String> codeqlBlockedCategories = List.of(
                "sql-injection", "command-injection", "path-traversal",
                "auth-bypass", "hardcoded-credentials", "hardcoded-credential");
        private boolean trivyBlockOnFixableCritical = true;
        private boolean trivyBlockOnMalware = true;
        private boolean trivyBlockOnSecret = true;
        private List<String> ignoredRules = List.of();
        private SonarGate sonarGate = SonarGate.defaults();

        public Builder trivyThresholds(SeverityThresholds t) { this.trivy = t; return this; }
        public Builder nvidiaThresholds(SeverityThresholds t) { this.nvidia = t; return this; }
        public Builder codeqlBlockOnCritical(boolean v) { this.codeqlBlockOnCritical = v; return this; }
        public Builder codeqlBlockOnHighRce(boolean v) { this.codeqlBlockOnHighRce = v; return this; }
        public Builder codeqlBlockedCategories(List<String> v) { this.codeqlBlockedCategories = v; return this; }
        public Builder trivyBlockOnFixableCritical(boolean v) { this.trivyBlockOnFixableCritical = v; return this; }
        public Builder trivyBlockOnMalware(boolean v) { this.trivyBlockOnMalware = v; return this; }
        public Builder trivyBlockOnSecret(boolean v) { this.trivyBlockOnSecret = v; return this; }
        public Builder ignoredRules(List<String> v) { this.ignoredRules = v; return this; }
        public Builder sonarGate(SonarGate g) { this.sonarGate = g == null ? SonarGate.defaults() : g; return this; }

        public SecurityPolicy build() { return new SecurityPolicy(this); }
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    private static List<String> lower(List<String> in) {
        List<String> out = new ArrayList<>(in.size());
        for (String s : in) {
            out.add(s.toLowerCase(java.util.Locale.ROOT));
        }
        return Collections.unmodifiableList(out);
    }

    private static boolean containsAny(String haystack, String... needles) {
        for (String n : needles) {
            if (haystack.contains(n)) return true;
        }
        return false;
    }
}
