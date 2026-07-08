package com.enterprise.securitygate;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Parses a Trivy JSON report into normalised {@link Finding}s.
 *
 * <p>Trivy produces a {@code Results[]} array with sub-objects for
 * {@code Vulnerabilities}, {@code Secrets} and {@code Misconfigurations}.
 * We currently cover vulnerabilities and secrets — misconfigurations are
 * rarely part of an enterprise blocking policy and the Security Gate
 * forwards them as INFO if encountered.
 */
public final class TrivyJsonParser {

    private final ObjectMapper mapper = new ObjectMapper();

    public List<Finding> parse(Path trivyJson) throws IOException {
        List<Finding> findings = new ArrayList<>();
        if (trivyJson == null || !Files.exists(trivyJson)) {
            return findings;
        }
        JsonNode root = mapper.readTree(Files.readAllBytes(trivyJson));

        for (JsonNode result : root.withArray("Results")) {
            String target = textOrEmpty(result, "Target");

            for (JsonNode v : result.withArray("Vulnerabilities")) {
                String id = textOrEmpty(v, "VulnerabilityID");
                String severity = textOrEmpty(v, "Severity");
                String pkg = textOrEmpty(v, "PkgName");
                String installed = textOrEmpty(v, "InstalledVersion");
                String fixed = textOrEmpty(v, "FixedVersion");
                String title = textOrEmpty(v, "Title");

                findings.add(new Finding(
                        Finding.Source.TRIVY,
                        id,
                        Severity.fromLabel(severity),
                        "vuln",
                        pkg + (installed.isEmpty() ? "" : "@" + installed),
                        fixed.isEmpty() ? null : fixed,
                        title + " (target=" + target + ")"));
            }

            for (JsonNode s : result.withArray("Secrets")) {
                String rule = textOrEmpty(s, "RuleID");
                String title = textOrEmpty(s, "Title");
                findings.add(new Finding(
                        Finding.Source.TRIVY,
                        rule.isEmpty() ? "secret" : rule,
                        Severity.CRITICAL,
                        "secret",
                        "",
                        null,
                        title + " (target=" + target + ")"));
            }

            for (JsonNode m : result.withArray("Misconfigurations")) {
                String id = textOrEmpty(m, "ID");
                String severity = textOrEmpty(m, "Severity");
                String title = textOrEmpty(m, "Title");
                findings.add(new Finding(
                        Finding.Source.TRIVY,
                        id.isEmpty() ? "misconfig" : id,
                        Severity.fromLabel(severity),
                        "misconfig",
                        "",
                        textOrEmpty(m, "Resolution"),
                        title + " (target=" + target + ")"));
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
