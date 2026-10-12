"""Configuration, IaC, and container definition security analysis rules."""

from __future__ import annotations

import re

from .models import ConfigSecurityFinding

SECRET_KEY_REGEX = re.compile(
    r"^(?:AWS_SECRET_ACCESS_KEY|SECRET_KEY|API_KEY|PRIVATE_KEY|DATABASE_PASSWORD|PASSWORD|TOKEN)\s*=\s*['\"]?([^'\"\s]{8,})['\"]?",
    re.IGNORECASE,
)
FROM_LATEST_REGEX = re.compile(r"^FROM\s+([A-Za-z0-9_.\-\/]+)(?::latest)?\s*(?:AS\s+\w+)?$", re.IGNORECASE)


def evaluate_dockerfile(content: str, file_path: str) -> list[ConfigSecurityFinding]:
    """Scan Dockerfile for container hardening and image tagging issues."""
    findings: list[ConfigSecurityFinding] = []
    has_user_directive = False
    lines = content.splitlines()

    for lineno, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # Check FROM :latest
        if line.upper().startswith("FROM "):
            # Check if tag is missing or explicitly :latest
            match = FROM_LATEST_REGEX.match(line)
            if match:
                img = match.group(1)
                # If FROM line specifies :latest or has no tag (no colon)
                if ":latest" in line.lower() or ":" not in line.split()[1]:
                    findings.append(
                        ConfigSecurityFinding(
                            rule_id="cfg.docker-latest-tag",
                            severity="medium",
                            file=file_path,
                            lineno=lineno,
                            title="Unpinned Docker base image using ':latest' or floating tag",
                            message=f"Base image '{img}' does not pin a specific immutable version tag or digest.",
                            remediation="Pin base image to an exact semantic version tag or SHA256 digest.",
                            cwe=("CWE-1188",),
                            details={"image": img, "line": line},
                        )
                    )

        # Check USER directive
        if line.upper().startswith("USER "):
            user_arg = line.split(None, 1)[1].strip()
            if user_arg.lower() not in ("root", "0"):
                has_user_directive = True

        # Check sudo without password
        if "NOPASSWD" in line.upper() and "sudo" in line.lower():
            findings.append(
                ConfigSecurityFinding(
                    rule_id="cfg.docker-sudo-nopasswd",
                    severity="high",
                    file=file_path,
                    lineno=lineno,
                    title="Container config grants passwordless sudo",
                    message="Passwordless sudo escalation is configured in container image.",
                    remediation="Remove sudo passwordless grants in production container images.",
                    cwe=("CWE-250",),
                    details={"line": line},
                )
            )

    if not has_user_directive:
        findings.append(
            ConfigSecurityFinding(
                rule_id="cfg.docker-root-user",
                severity="medium",
                file=file_path,
                lineno=len(lines) or 1,
                title="Container execution defaults to root user",
                message="Dockerfile lacks a non-root 'USER' directive, executing application processes as root.",
                remediation="Add 'USER <non-root-user>' before container entrypoint.",
                cwe=("CWE-250",),
            )
        )

    return findings


def evaluate_env_file(content: str, file_path: str) -> list[ConfigSecurityFinding]:
    """Scan committed environment or config files for plaintext secrets."""
    findings: list[ConfigSecurityFinding] = []

    for lineno, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        match = SECRET_KEY_REGEX.match(line)
        if match:
            secret_val = match.group(1)
            # Mask secret
            masked = secret_val[:3] + "..." + secret_val[-2:] if len(secret_val) > 5 else "***"
            findings.append(
                ConfigSecurityFinding(
                    rule_id="cfg.plaintext-secret",
                    severity="critical",
                    file=file_path,
                    lineno=lineno,
                    title="Plaintext secret or credential in checked-in configuration",
                    message=f"Credential variable assigned plaintext value ({masked}) in repository configuration.",
                    remediation="Move secrets to an environment manager, secrets vault, or gitignore file.",
                    cwe=("CWE-798", "CWE-312"),
                    details={"line": line.split("=")[0]},
                )
            )

    return findings


def evaluate_tls_code(content: str, file_path: str) -> list[ConfigSecurityFinding]:
    """Scan source code for insecure TLS/SSL disabling configurations."""
    findings: list[ConfigSecurityFinding] = []

    for lineno, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if "verify=False" in line or "verify=false" in line:
            findings.append(
                ConfigSecurityFinding(
                    rule_id="cfg.insecure-tls",
                    severity="high",
                    file=file_path,
                    lineno=lineno,
                    title="Disabled TLS certificate validation ('verify=False')",
                    message="TLS certificate verification is disabled, exposing network traffic to man-in-the-middle attacks.",
                    remediation="Enable TLS validation with verify=True and supply valid CA trust bundles.",
                    cwe=("CWE-295",),
                    details={"line": line},
                )
            )
        elif "CERT_NONE" in line or "check_hostname = False" in line:
            findings.append(
                ConfigSecurityFinding(
                    rule_id="cfg.insecure-tls",
                    severity="high",
                    file=file_path,
                    lineno=lineno,
                    title="Insecure SSLContext configuration disabling certificate check",
                    message="SSLContext disables hostname validation or certificate requirements.",
                    remediation="Use ssl.CERT_REQUIRED and check_hostname = True.",
                    cwe=("CWE-295",),
                    details={"line": line},
                )
            )

    return findings
