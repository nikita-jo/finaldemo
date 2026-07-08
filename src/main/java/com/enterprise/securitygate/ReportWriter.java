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
import java.util.Map;

/**
 * Renders the final {@code SECURITY_GATE_REPORT.md} that the workflow
 * uploads as an artifact. The format is intentionally simple Markdown
 * tables so the report renders cleanly in the GitHub Actions summary
 * and on the workflow run page.
 */
public final class ReportWriter {

    public void write(Path out,
                      String commit,
                      String startedAt,
                      String finishedAt,
                      SecurityPolicy.Decision decision,
                      List<Finding> allFindings,
                      String trivySummary,
                      String codeqlSummary,
                      String nvidiaSummary) throws IOException {

        if (out.getParent() != null) {
            Files.createDirectories(out.getParent());
        }

        int[] codeqlCounts = decision.counts().getOrDefault(Finding.Source.CODEQL, zero());
        int[] trivyCounts  = decision.counts().getOrDefault(Finding.Source.TRIVY,  zero());
        int[] nvidiaCounts = decision.counts().getOrDefault(Finding.Source.NVIDIA, zero());

        int critical = sum(codeqlCounts, Severity.CRITICAL) + sum(trivyCounts, Severity.CRITICAL) + sum(nvidiaCounts, Severity.CRITICAL);
        int high     = sum(codeqlCounts, Severity.HIGH)     + sum(trivyCounts, Severity.HIGH)     + sum(nvidiaCounts, Severity.HIGH);
        int medium   = sum(codeqlCounts, Severity.MEDIUM)   + sum(trivyCounts, Severity.MEDIUM)   + sum(nvidiaCounts, Severity.MEDIUM);
        int low      = sum(codeqlCounts, Severity.LOW)      + sum(trivyCounts, Severity.LOW)      + sum(nvidiaCounts, Severity.LOW);

        int riskScore = computeRiskScore(codeqlCounts, trivyCounts, nvidiaCounts);

        StringBuilder md = new StringBuilder();
        md.append("# Security Gate Report\n\n");
        md.append("| Field | Value |\n|---|---|\n");
        md.append("| **Status** | **").append(decision.status()).append("** |\n");
        md.append("| **Risk Score** | ").append(riskScore).append(" / 100 |\n");
        md.append("| **Commit SHA** | `").append(nullToDash(commit)).append("` |\n");
        md.append("| **Pipeline Started** | ").append(nullToDash(startedAt)).append(" |\n");
        md.append("| **Pipeline Finished** | ").append(nullToDash(finishedAt)).append(" |\n");
        md.append("| **Report Generated** | ")
          .append(OffsetDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME))
          .append(" |\n");
        md.append("| **Total Findings** | ").append(allFindings.size()).append(" |\n\n");

        md.append("## Aggregate Counts\n\n");
        md.append("| Source | Critical | High | Medium | Low |\n|---|---|---|---|---|\n");
        md.append("| CodeQL | ")
          .append(codeqlCounts[Severity.CRITICAL.weight()]).append(" | ")
          .append(codeqlCounts[Severity.HIGH.weight()]).append(" | ")
          .append(codeqlCounts[Severity.MEDIUM.weight()]).append(" | ")
          .append(codeqlCounts[Severity.LOW.weight()]).append(" |\n");
        md.append("| Trivy | ")
          .append(trivyCounts[Severity.CRITICAL.weight()]).append(" | ")
          .append(trivyCounts[Severity.HIGH.weight()]).append(" | ")
          .append(trivyCounts[Severity.MEDIUM.weight()]).append(" | ")
          .append(trivyCounts[Severity.LOW.weight()]).append(" |\n");
        md.append("| NVIDIA | ")
          .append(nvidiaCounts[Severity.CRITICAL.weight()]).append(" | ")
          .append(nvidiaCounts[Severity.HIGH.weight()]).append(" | ")
          .append(nvidiaCounts[Severity.MEDIUM.weight()]).append(" | ")
          .append(nvidiaCounts[Severity.LOW.weight()]).append(" |\n");
        md.append("| **Total** | **").append(critical).append("** | **")
          .append(high).append("** | **").append(medium).append("** | **").append(low).append("** |\n\n");

        md.append("## Scanners Summary\n\n");
        md.append("### CodeQL\n").append(codeqlSummary).append("\n\n");
        md.append("### Trivy\n").append(trivySummary).append("\n\n");
        md.append("### NVIDIA Security Agent\n").append(nvidiaSummary).append("\n\n");

        if (decision.isPass()) {
            md.append("## Blocking Issues\n\n_None — the Security Gate **PASSED**._\n\n");
        } else {
            md.append("## Blocking Issues\n\n");
            for (String reason : decision.reasons()) {
                md.append("- ❌ ").append(reason).append("\n");
            }
            md.append('\n');
        }

        md.append("## Recommendations\n\n");
        List<String> recs = collectRecommendations(allFindings);
        if (recs.isEmpty()) {
            md.append("- No remediation actions required.\n");
        } else {
            for (String r : recs) md.append("- ").append(r).append('\n');
        }
        md.append('\n');

        md.append("## Top Findings (max 25)\n\n");
        md.append("| Source | Severity | Rule | Category | Description |\n|---|---|---|---|---|\n");
        List<Finding> top = new ArrayList<>(allFindings);
        top.sort((a, b) -> Integer.compare(b.severity().weight(), a.severity().weight()));
        int shown = 0;
        for (Finding f : top) {
            if (shown++ >= 25) break;
            md.append("| ").append(f.source())
              .append(" | ").append(f.severity().display())
              .append(" | `").append(escape(f.ruleId())).append("`")
              .append(" | ").append(escape(f.category()))
              .append(" | ").append(escape(truncate(f.description(), 160)))
              .append(" |\n");
        }
        if (shown == 0) md.append("| - | - | - | - | _no findings_ |\n");

        Files.writeString(out, md.toString(), StandardCharsets.UTF_8);
    }

    private static List<String> collectRecommendations(List<Finding> findings) {
        List<String> recs = new ArrayList<>();
        for (Finding f : findings) {
            if (f.severity() != Severity.CRITICAL && f.severity() != Severity.HIGH) continue;
            if (f.fix() != null && !f.fix().isBlank() && !f.packageName().isEmpty()) {
                recs.add("Upgrade " + f.packageName() + " to " + f.fix()
                        + " (" + f.source() + " " + f.ruleId() + ")");
            } else if (f.fix() != null && !f.fix().isBlank()) {
                recs.add(f.fix() + " (" + f.source() + " " + f.ruleId() + ")");
            }
            if (recs.size() >= 10) break;
        }
        return recs;
    }

    private static int computeRiskScore(int[] c, int[] t, int[] n) {
        int raw = (c[Severity.CRITICAL.weight()] + t[Severity.CRITICAL.weight()] + n[Severity.CRITICAL.weight()]) * 15
                + (c[Severity.HIGH.weight()]     + t[Severity.HIGH.weight()]     + n[Severity.HIGH.weight()])     * 7
                + (c[Severity.MEDIUM.weight()]   + t[Severity.MEDIUM.weight()]   + n[Severity.MEDIUM.weight()])   * 3
                + (c[Severity.LOW.weight()]      + t[Severity.LOW.weight()]      + n[Severity.LOW.weight()])      * 1;
        return Math.min(100, (int) Math.round((raw / 126.0) * 100));
    }

    private static int sum(int[] counts, Severity s) {
        return counts[s.weight()];
    }

    private static int[] zero() { return new int[Severity.values().length]; }

    private static String nullToDash(String s) { return s == null || s.isEmpty() ? "-" : s; }

    private static String truncate(String s, int n) {
        if (s == null) return "";
        return s.length() <= n ? s : s.substring(0, n - 1) + "…";
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("|", "\\|").replace("\n", " ").replace("\r", " ");
    }
}
