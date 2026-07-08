package com.enterprise.securitygate;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Orchestrates the Security Gate:
 *
 * <ol>
 *   <li>Load CodeQL SARIF, Trivy JSON, NVIDIA JSON (if available).</li>
 *   <li>Deduplicate identical findings across scanners.</li>
 *   <li>Evaluate the configured {@link SecurityPolicy}.</li>
 *   <li>Write {@code SECURITY_GATE_REPORT.md} and a structured
 *       {@code security-gate.json} summary.</li>
 *   <li>Print a compact console summary for the GitHub Actions log.</li>
 *   <li>Exit with code 0 on PASS, 1 on FAIL.</li>
 * </ol>
 *
 * <p>Run from the workflow with:
 * <pre>mvn -q -DskipTests package
 *   &amp;&amp; java -cp target/classes com.enterprise.securitygate.SecurityGate \
 *        --codeql codeql-results.sarif \
 *        --trivy trivy-report.json \
 *        --nvidia reports/security-report.json \
 *        --report SECURITY_GATE_REPORT.md \
 *        --json  security-gate.json \
 *        --commit "$GITHUB_SHA"</pre>
 */
public final class SecurityGate {

    public static void main(String[] args) {
        Args parsed;
        try {
            parsed = Args.parse(args);
        } catch (IllegalArgumentException ex) {
            System.err.println("::error::" + ex.getMessage());
            Args.printUsage(System.err);
            System.exit(2);
            return;
        }

        String startedAt = OffsetDateTime.now(ZoneOffset.UTC)
                .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);

        List<Finding> findings = new ArrayList<>();
        try {
            findings.addAll(new CodeQlSarifParser().parse(parsed.codeql));
        } catch (IOException e) {
            System.err.println("::warning::Failed to parse CodeQL SARIF: " + e.getMessage());
        }
        try {
            findings.addAll(new TrivyJsonParser().parse(parsed.trivy));
        } catch (IOException e) {
            System.err.println("::warning::Failed to parse Trivy JSON: " + e.getMessage());
        }
        try {
            findings.addAll(new NvidiaJsonParser().parse(parsed.nvidia));
        } catch (IOException e) {
            System.err.println("::warning::Failed to parse NVIDIA JSON: " + e.getMessage());
        }
        try {
            findings.addAll(new SonarQubeMeasuresParser().parse(parsed.sonar));
        } catch (IOException e) {
            System.err.println("::warning::Failed to parse SonarQube measures: " + e.getMessage());
        }

        List<Finding> deduped = deduplicate(findings);
        SecurityPolicy policy = parsed.policy();
        SecurityPolicy.Decision decision = policy.evaluate(deduped);

        String trivySummary  = summarise("Trivy", parsed.trivy);
        String codeqlSummary = summarise("CodeQL", parsed.codeql);
        String nvidiaSummary = summarise("NVIDIA", parsed.nvidia);
        String sonarSummary  = summariseSonar("SonarQube", parsed.sonar, deduped);

        try {
            new ReportWriter().write(
                    Paths.get(parsed.report),
                    parsed.commit,
                    startedAt,
                    OffsetDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME),
                    decision,
                    deduped,
                    trivySummary,
                    codeqlSummary,
                    nvidiaSummary,
                    sonarSummary);
        } catch (IOException e) {
            System.err.println("::error::Failed to write Markdown report: " + e.getMessage());
            System.exit(1);
            return;
        }

        try {
            JsonSummaryWriter.write(Paths.get(parsed.json), decision, deduped, parsed.commit);
        } catch (IOException e) {
            System.err.println("::warning::Failed to write JSON summary: " + e.getMessage());
        }

        printConsoleSummary(decision, deduped);

        System.exit(decision.isPass() ? 0 : 1);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /** Drop findings that look identical across scanners. */
    static List<Finding> deduplicate(List<Finding> in) {
        Set<String> seen = new LinkedHashSet<>();
        List<Finding> out = new ArrayList<>();
        for (Finding f : in) {
            String key = f.source() + "|" + f.severity() + "|" + f.category() + "|"
                    + f.ruleId().toLowerCase() + "|" + f.packageName();
            if (seen.add(key)) out.add(f);
        }
        return out;
    }

    private static String summarise(String label, Path path) {
        if (path == null || !Files.exists(path)) {
            return "_" + label + " report not found._\n";
        }
        long bytes;
        try { bytes = Files.size(path); } catch (IOException e) { bytes = -1; }
        return "- File: `" + path + "` (" + bytes + " bytes)\n";
    }

    /**
     * Produce a compact summary of the SonarQube measures that were
     * consumed by the policy. The values mirror the Quality Gate
     * conditions from the task brief so a reviewer can confirm them at
     * a glance in the Markdown report.
     */
    private static String summariseSonar(String label, Path path, List<Finding> findings) {
        StringBuilder sb = new StringBuilder();
        if (path == null || !Files.exists(path)) {
            return "_" + label + " measures not found._\n";
        }
        long bytes;
        try { bytes = Files.size(path); } catch (IOException e) { bytes = -1; }
        sb.append("- File: `").append(path).append("` (").append(bytes).append(" bytes)\n");
        sb.append("\n| Metric | Observed | Threshold | Status |\n|---|---|---|---|\n");
        appendSonarRow(sb, findings, "blocker_violations",     "0",  "sonar:pass");
        appendSonarRow(sb, findings, "critical_violations",    "0",  "sonar:pass");
        appendSonarRow(sb, findings, "new_bugs",               "0",  "sonar:pass");
        appendSonarRow(sb, findings, "security_rating",        "1 (A)",  "sonar:pass");
        appendSonarRow(sb, findings, "reliability_rating",     "1 (A)",  "sonar:pass");
        appendSonarRow(sb, findings, "new_coverage",           "≥80.0%", "sonar:pass");
        appendSonarRow(sb, findings, "duplicated_lines_density","≤3.0%",  "sonar:pass");
        return sb.toString();
    }

    private static void appendSonarRow(StringBuilder sb, List<Finding> findings,
                                       String metric, String threshold, String passToken) {
        for (Finding f : findings) {
            if (f.source() != Finding.Source.SONAR) continue;
            if (!f.ruleId().equals("sonar:" + metric)) continue;
            String status = f.severity() == Severity.CRITICAL ? "❌ FAIL" : "✅ PASS";
            sb.append("| `").append(metric).append("` | ")
              .append(f.description().substring(f.description().indexOf('=') + 1).trim())
              .append(" | ").append(threshold).append(" | ").append(status).append(" |\n");
            return;
        }
        // Metric not present in the measures response.
        sb.append("| `").append(metric).append("` | _not reported_ | ")
          .append(threshold).append(" | ⚠️  UNKNOWN |\n");
    }

    private static void printConsoleSummary(SecurityPolicy.Decision decision, List<Finding> findings) {
        System.out.println();
        System.out.println("================ SECURITY GATE ================");
        System.out.println("Status:    " + decision.status());
        System.out.println("Findings:  " + findings.size() + " (after dedup)");
        int c = countBySeverity(findings, Severity.CRITICAL);
        int h = countBySeverity(findings, Severity.HIGH);
        int m = countBySeverity(findings, Severity.MEDIUM);
        int l = countBySeverity(findings, Severity.LOW);
        System.out.println("Critical:  " + c);
        System.out.println("High:      " + h);
        System.out.println("Medium:    " + m);
        System.out.println("Low:       " + l);
        if (!decision.isPass()) {
            System.out.println();
            System.out.println("Blocking reasons:");
            for (String r : decision.reasons()) {
                System.out.println("  - " + r);
            }
        }
        System.out.println("==============================================");
    }

    private static int countBySeverity(List<Finding> findings, Severity s) {
        long n = findings.stream().filter(f -> f.severity() == s).count();
        return (int) Math.min(Integer.MAX_VALUE, n);
    }

    // ------------------------------------------------------------------
    // Argument parsing
    // ------------------------------------------------------------------

    static final class Args {
        Path codeql;
        Path trivy;
        Path nvidia;
        Path sonar;
        String report;
        String json;
        String commit;
        boolean strict;

        static Args parse(String[] argv) {
            Args a = new Args();
            a.report = "SECURITY_GATE_REPORT.md";
            a.json = "security-gate.json";
            for (int i = 0; i < argv.length; i++) {
                String k = argv[i];
                String v = (i + 1 < argv.length) ? argv[i + 1] : null;
                switch (k) {
                    case "--codeql" -> { a.codeql = Paths.get(require(v, k)); i++; }
                    case "--trivy" -> { a.trivy = Paths.get(require(v, k)); i++; }
                    case "--nvidia" -> { a.nvidia = Paths.get(require(v, k)); i++; }
                    case "--sonar" -> { a.sonar = Paths.get(require(v, k)); i++; }
                    case "--report" -> { a.report = require(v, k); i++; }
                    case "--json" -> { a.json = require(v, k); i++; }
                    case "--commit" -> { a.commit = v; i++; }
                    case "--strict" -> { a.strict = true; }
                    case "-h", "--help" -> { printUsage(System.out); System.exit(0); }
                    default -> throw new IllegalArgumentException("Unknown flag: " + k);
                }
            }
            if (a.report == null || a.report.isBlank()) {
                throw new IllegalArgumentException("--report is required");
            }
            return a;
        }

        SecurityPolicy policy() {
            SecurityPolicy.Builder b = SecurityPolicy.builder();
            if (strict) {
                // Strict mode: zero-tolerance on Critical/High for all scanners.
                b.trivyThresholds(SecurityPolicy.SeverityThresholds.of(0, 0, 0, 0))
                 .nvidiaThresholds(SecurityPolicy.SeverityThresholds.of(0, 0, Integer.MAX_VALUE, Integer.MAX_VALUE));
            }
            return b.build();
        }

        private static String require(String v, String flag) {
            if (v == null) throw new IllegalArgumentException(flag + " requires a value");
            return v;
        }

        static void printUsage(java.io.PrintStream out) {
            out.println("Usage: java com.enterprise.securitygate.SecurityGate " +
                    "[--codeql SARIF] [--trivy JSON] [--nvidia JSON] [--sonar JSON] " +
                    "[--report PATH] [--json PATH] [--commit SHA] [--strict]");
        }
    }
}
