package com.enterprise.securitygate;

import java.util.Locale;
import java.util.Objects;

/**
 * A single normalised finding produced by any scanner. The Security Gate
 * uses {@link #category()} together with {@link #severity()} to evaluate
 * the policy, and prints the other fields in the Markdown report.
 */
public final class Finding {
    public enum Source { CODEQL, TRIVY, NVIDIA, SONAR }

    private final Source source;
    private final String ruleId;       // e.g. CWE-89, CVE-2024-..., java/sql-injection
    private final Severity severity;
    private final String category;     // e.g. "sql-injection", "rce", "secret", "vuln"
    private final String packageName;  // Trivy: pkg@version ; null for CodeQL
    private final String fix;          // Suggested fix, may be null
    private final String description;  // Human-readable summary

    public Finding(Source source,
                   String ruleId,
                   Severity severity,
                   String category,
                   String packageName,
                   String fix,
                   String description) {
        this.source = Objects.requireNonNull(source, "source");
        this.ruleId = ruleId == null ? "" : ruleId;
        this.severity = Objects.requireNonNull(severity, "severity");
        this.category = category == null ? "" : category.toLowerCase(Locale.ROOT);
        this.packageName = packageName == null ? "" : packageName;
        this.fix = fix;
        this.description = description == null ? "" : description;
    }

    public Source source()              { return source; }
    public String ruleId()              { return ruleId; }
    public Severity severity()          { return severity; }
    public String category()            { return category; }
    public String packageName()         { return packageName; }
    public String fix()                 { return fix; }
    public String description()         { return description; }

    @Override
    public String toString() {
        return source + "/" + severity + "/" + category + "/" + ruleId;
    }
}
