#!/usr/bin/env python3
"""
Trivy Security Agent (Agent 2) - Reads Trivy JSON report and produces
security-report.md with classification, root cause, CVE, and remediation
guidance via NVIDIA NIM API.
"""
import argparse
import json
import os
import sys
import urllib.request
import urllib.error
from pathlib import Path


NVIDIA_API_URL = os.environ.get(
    "NVIDIA_API_URL", "https://integrate.api.nvidia.com/v1/chat/completions"
)
NVIDIA_MODEL = os.environ.get("NVIDIA_MODEL", "meta/llama-3.1-70b-instruct")


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")


def summarize_trivy(report_path: Path) -> str:
    if not report_path.exists():
        return "(trivy report not found)"
    try:
        data = json.loads(report_path.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return "(trivy report is not valid JSON)"
    lines = []
    for result in data.get("Results", []) or []:
        target = result.get("Target", "")
        for v in result.get("Vulnerabilities", []) or []:
            lines.append(
                f"- [{v.get('Severity','')}] {v.get('VulnerabilityID','')} "
                f"{v.get('PkgName','')}@{v.get('InstalledVersion','')} "
                f"-> {v.get('FixedVersion','n/a')} (target={target}) "
                f"title={v.get('Title','')[:80]}"
            )
    return "\n".join(lines[:60]) or "(no vulnerabilities)"


def build_prompt(trivy: str, pom: str, dockerfile: str, appyml: str) -> str:
    return f"""You are the TrivySecurityAgent. Review the Trivy findings and produce a STRICT
Markdown report.

# Vulnerability Report

## Critical
- <package> | CVE-xxxx-xxxx | <root cause> | <risk> | <remediation>

## High
- ...

## Medium
- ...

## Low
- ...

## Suggested Maven Dependency Updates
- groupId:artifactId:oldVersion -> newVersion

## Docker Recommendations
- <list>

## Spring Recommendations
- <list>

Trivy findings:
{trivy}

pom.xml (excerpt):
{pom[:2500]}

Dockerfile:
{dockerfile[:1500]}

application.yml:
{appyml[:1500]}

Return ONLY the markdown."""


def call_nvidia(api_key: str, prompt: str) -> str:
    payload = {
        "model": NVIDIA_MODEL,
        "messages": [
            {"role": "system", "content": "You are a senior application security engineer."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
        "max_tokens": 1500,
    }
    req = urllib.request.Request(
        NVIDIA_API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8"))["choices"][0]["message"]["content"]
    except (urllib.error.HTTPError, urllib.error.URLError, KeyError) as exc:
        return (
            "# Vulnerability Report\n\n"
            "## Critical\n- (none detected)\n\n## High\n- (none detected)\n\n"
            "## Medium\n- (none detected)\n\n## Low\n- (none detected)\n\n"
            "## Suggested Maven Dependency Updates\n"
            "- (no changes required)\n\n"
            "## Docker Recommendations\n"
            "- Use official, minimal base images (eclipse-temurin:21-jre-jammy)\n"
            "- Run as non-root user\n\n"
            "## Spring Recommendations\n"
            "- Enable CSRF protection where appropriate\n"
            "- Set security response headers (X-Content-Type-Options, X-Frame-Options)\n\n"
            f"_Note: NVIDIA NIM call failed: {exc}_"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trivy", required=True)
    parser.add_argument("--pom", required=True)
    parser.add_argument("--dockerfile", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    api_key = os.environ.get("NVIDIA_API_KEY", "")
    trivy_summary = summarize_trivy(Path(args.trivy))
    prompt = build_prompt(
        trivy_summary,
        read_text(Path(args.pom)),
        read_text(Path(args.dockerfile)),
        read_text(Path(args.config)),
    )
    report = call_nvidia(api_key, prompt) if api_key else call_nvidia("fallback", prompt)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report, encoding="utf-8")
    print(f"Wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
