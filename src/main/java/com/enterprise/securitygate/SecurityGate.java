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

        List<Finding> deduped = deduplicate(findings);
        SecurityPolicy policy = parsed.policy();
        SecurityPolicy.Decision decision = policy.evaluate(deduped);

        String trivySummary  = summarise("Trivy", parsed.trivy);
        String codeqlSummary = summarise("CodeQL", parsed.codeql);
        String nvidiaSummary = summarise("NVIDIA", parsed.nvidia);

        try {
            Files.createDirectories(Paths.get(parsed.report).toAbsolutePath().getParent() == null
                    ? "." : Paths.get(parsed.report).toAbsolutePath().getParent().toString());
        } catch (IOException ignored) { /* best effort */ }

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
                    nvidiaSummary);
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

    private static long countBySeverity(List<Finding> findings, Severity s) {
        return findings.stream().filter(f -> f.severity() == s).count();
    }

    // ------------------------------------------------------------------
    // Argument parsing
    // ------------------------------------------------------------------

    static final class Args {
        Path codeql;
        Path trivy;
        Path nvidia;
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
                    "[--codeql SARIF] [--trivy JSON] [--nvidia JSON] " +
                    "[--report PATH] [--json PATH] [--commit SHA] [--strict]");
        }
    }
}
