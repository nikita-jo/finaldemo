package com.enterprise.securitygate;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for the Security Gate policy. The gate is a pure function of
 * its inputs so we can fully cover it without standing up an HTTP layer
 * or scanner mocks.
 */
class SecurityPolicyTest {

    @Test
    void passesWhenNoFindings() {
        SecurityPolicy p = SecurityPolicy.builder().build();
        SecurityPolicy.Decision d = p.evaluate(List.of());
        assertTrue(d.isPass(), "Empty findings should pass");
    }

    @Test
    void failsOnAnyCodeQlCritical() {
        SecurityPolicy p = SecurityPolicy.builder().build();
        SecurityPolicy.Decision d = p.evaluate(List.of(
                new Finding(Finding.Source.CODEQL, "java/sql-injection",
                        Severity.CRITICAL, "sql-injection", "", null, "x")));
        assertFalse(d.isPass());
        assertTrue(d.reasons().stream().anyMatch(r -> r.contains("CodeQL") && r.contains("critical")));
    }

    @Test
    void failsOnHighRceFromCodeQl() {
        SecurityPolicy p = SecurityPolicy.builder().build();
        SecurityPolicy.Decision d = p.evaluate(List.of(
                new Finding(Finding.Source.CODEQL, "java/command-line-injection",
                        Severity.HIGH, "command-injection", "", null, "x")));
        assertFalse(d.isPass());
    }

    @Test
    void failsOnTrivyCritical() {
        SecurityPolicy p = SecurityPolicy.builder().build();
        SecurityPolicy.Decision d = p.evaluate(List.of(
                new Finding(Finding.Source.TRIVY, "CVE-2024-9999",
                        Severity.CRITICAL, "vuln", "log4j@1.0", "2.24.0", "x")));
        assertFalse(d.isPass());
        assertTrue(d.reasons().stream().anyMatch(r -> r.contains("Trivy") && r.contains("critical")));
    }

    @Test
    void failsWhenTrivyHighExceedsThreshold() {
        SecurityPolicy p = SecurityPolicy.builder()
                .trivyThresholds(SecurityPolicy.SeverityThresholds.of(0, 5, Integer.MAX_VALUE, Integer.MAX_VALUE))
                .build();
        // 6 highs -> over the threshold of 5
        List<Finding> six = List.of(
                finding("CVE-1"), finding("CVE-2"), finding("CVE-3"),
                finding("CVE-4"), finding("CVE-5"), finding("CVE-6"));
        SecurityPolicy.Decision d = p.evaluate(six);
        assertFalse(d.isPass());
    }

    @Test
    void passesWhenTrivyHighAtThreshold() {
        SecurityPolicy p = SecurityPolicy.builder()
                .trivyThresholds(SecurityPolicy.SeverityThresholds.of(0, 5, Integer.MAX_VALUE, Integer.MAX_VALUE))
                .build();
        // 5 highs -> exactly at the threshold, should pass
        List<Finding> five = List.of(
                finding("CVE-1"), finding("CVE-2"), finding("CVE-3"),
                finding("CVE-4"), finding("CVE-5"));
        SecurityPolicy.Decision d = p.evaluate(five);
        assertTrue(d.isPass());
    }

    @Test
    void failsOnTrivySecret() {
        SecurityPolicy p = SecurityPolicy.builder().build();
        SecurityPolicy.Decision d = p.evaluate(List.of(
                new Finding(Finding.Source.TRIVY, "AWS-Access-Key",
                        Severity.CRITICAL, "secret", "", null, "x")));
        assertFalse(d.isPass());
        assertTrue(d.reasons().stream().anyMatch(r -> r.contains("secret")));
    }

    @Test
    void ignoredRulesAreNotCounted() {
        SecurityPolicy p = SecurityPolicy.builder()
                .ignoredRules(List.of("CVE-2024-9999"))
                .build();
        SecurityPolicy.Decision d = p.evaluate(List.of(
                new Finding(Finding.Source.TRIVY, "CVE-2024-9999",
                        Severity.CRITICAL, "vuln", "x@1.0", "2.0", "x")));
        assertTrue(d.isPass(), "Ignored rules must be filtered before evaluation");
    }

    @Test
    void strictModeBlocksAllHigh() {
        SecurityPolicy p = SecurityPolicy.builder()
                .trivyThresholds(SecurityPolicy.SeverityThresholds.of(0, 0, 0, 0))
                .build();
        SecurityPolicy.Decision d = p.evaluate(List.of(
                new Finding(Finding.Source.TRIVY, "CVE-1",
                        Severity.HIGH, "vuln", "x@1.0", "2.0", "x")));
        assertFalse(d.isPass());
    }

    private static Finding finding(String id) {
        return new Finding(Finding.Source.TRIVY, id, Severity.HIGH, "vuln", "pkg@1.0", "1.1", "x");
    }
}
