"""Test suite for pure-Python package archive structural inspector (ZIP, JAR, APK, Wheel)."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest

from plex.cli import main
from plex.inspect import InspectEngine, parse_archive
from tests.test_native_inspect import build_synthetic_elf64


def _create_zip(files: dict[str, bytes | str]) -> bytes:
    """Helper creating an in-memory zip archive with specified file map."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for fname, content in files.items():
            if isinstance(content, str):
                zf.writestr(fname, content.encode("utf-8"))
            else:
                zf.writestr(fname, content)
    return buf.getvalue()


def test_parse_standard_zip():
    data = _create_zip({
        "data/config.json": '{"app": "demo"}',
        "README.md": "# Demo Application",
    })
    desc = parse_archive(data, "demo.zip", "sha256:test")

    assert desc.format == "archive"
    assert desc.metadata["archive_type"] == "zip"
    assert desc.metadata["entry_count"] == 2
    assert len(desc.sections) == 2


def test_parse_python_wheel():
    data = _create_zip({
        "demo_pkg-1.2.0.dist-info/METADATA": (
            "Metadata-Version: 2.1\n"
            "Name: demo-pkg\n"
            "Version: 1.2.0\n"
            "Summary: A secure test package\n"
            "License: Apache-2.0\n"
        ),
        "demo_pkg-1.2.0.dist-info/entry_points.txt": (
            "[console_scripts]\n"
            "demo-cli = demo_pkg.cli:main\n"
        ),
        "demo_pkg/__init__.py": "# init",
    })
    desc = parse_archive(data, "demo_pkg-1.2.0-py3-none-any.whl", "sha256:test")

    assert desc.format == "archive"
    assert desc.metadata["archive_type"] == "wheel"
    assert desc.metadata["manifest_info"]["name"] == "demo-pkg"
    assert desc.metadata["manifest_info"]["version"] == "1.2.0"
    assert desc.metadata["manifest_info"]["license"] == "Apache-2.0"
    assert "demo-cli" in desc.exported_symbols


def test_parse_java_jar():
    data = _create_zip({
        "META-INF/MANIFEST.MF": (
            "Manifest-Version: 1.0\n"
            "Main-Class: com.example.service.Application\n"
            "Implementation-Version: 3.4.1\n"
        ),
        "com/example/service/Application.class": b"\xca\xfe\xba\xbe\x00\x00",
    })
    desc = parse_archive(data, "service.jar", "sha256:test")

    assert desc.format == "archive"
    assert desc.metadata["archive_type"] == "jar"
    assert desc.metadata["manifest_info"]["Main-Class"] == "com.example.service.Application"
    assert "com.example.service.Application" in desc.exported_symbols


def test_parse_android_apk():
    # AndroidManifest binary/text containing permission tokens
    manifest_bytes = (
        b"<?xml version='1.0' encoding='utf-8'?>\n"
        b"<manifest package='com.example.app'>\n"
        b"  <uses-permission android:name='android.permission.INTERNET' />\n"
        b"  <uses-permission android:name='android.permission.CAMERA' />\n"
        b"  <uses-permission android:name='android.permission.RECORD_AUDIO' />\n"
        b"</manifest>\n"
    )
    data = _create_zip({
        "AndroidManifest.xml": manifest_bytes,
        "classes.dex": b"dex\n035\x00",
        "res/layout/activity_main.xml": b"<layout/>",
    })
    desc = parse_archive(data, "app.apk", "sha256:test")

    assert desc.format == "archive"
    assert desc.metadata["archive_type"] == "apk"
    perms = desc.metadata["permissions"]
    assert "INTERNET" in perms
    assert "CAMERA" in perms
    assert "RECORD_AUDIO" in perms

    dangerous = desc.metadata["dangerous_permissions"]
    assert "CAMERA" in dangerous
    assert "RECORD_AUDIO" in dangerous
    assert "INTERNET" not in dangerous


def test_archive_zip_slip_detection(tmp_path: Path):
    data = _create_zip({
        "../../etc/passwd": "root:x:0:0:root:/root:/bin/bash",
        "valid/file.txt": "hello",
    })
    p = tmp_path / "slip.zip"
    p.write_bytes(data)

    engine = InspectEngine()
    report = engine.inspect(p)

    assert report.scan_status == "complete"
    slip_findings = [f for f in report.findings_unified if f.rule_id == "bin.archive.zip-slip"]
    assert len(slip_findings) == 1
    assert slip_findings[0].severity == "critical"
    assert "CWE-22" in slip_findings[0].cwe


def test_archive_sensitive_files_detection(tmp_path: Path):
    data = _create_zip({
        "certs/production_keystore.jks": b"\xfe\xed\xfe\xedkeystore",
        "secrets/service-account.json": '{"private_key_id": "123"}',
        "data/app.txt": "normal file",
    })
    p = tmp_path / "leaks.jar"
    p.write_bytes(data)

    engine = InspectEngine()
    report = engine.inspect(p)

    sensitive_findings = [f for f in report.findings_unified if f.rule_id == "bin.archive.sensitive-file"]
    assert len(sensitive_findings) == 2
    rule_ids = {f.rule_id for f in sensitive_findings}
    assert "bin.archive.sensitive-file" in rule_ids
    assert all(f.severity == "high" for f in sensitive_findings)


def test_archive_embedded_elf_binary_recursion(tmp_path: Path):
    # Create synthetic ELF with banned API 'gets' and weak hardening (no NX)
    elf_bytes = build_synthetic_elf64(
        is_pie=False,
        nx=False,
        imported_symbols=["gets"],
    )

    data = _create_zip({
        "lib/arm64-v8a/libvuln.so": elf_bytes,
        "classes.dex": b"dex\n035\x00",
        "AndroidManifest.xml": b"<manifest package='test'/>",
    })
    p = tmp_path / "native_app.apk"
    p.write_bytes(data)

    desc = parse_archive(data, str(p), "sha256:test")
    assert len(desc.metadata["embedded_binaries"]) == 1
    bin_info = desc.metadata["embedded_binaries"][0]
    assert bin_info["format"] == "elf"
    assert bin_info["hardening"]["nx"] is False
    assert "gets" in desc.imported_symbols

    # Verify InspectEngine emits banned API finding for embedded binary
    engine = InspectEngine()
    report = engine.inspect(p)

    banned_finds = [f for f in report.findings_unified if f.rule_id == "bin.banned-api"]
    assert len(banned_finds) == 1
    assert banned_finds[0].engine_meta["symbol"] == "gets"

    nx_finds = [f for f in report.findings_unified if f.rule_id == "bin.weak-hardening" and f.engine_meta.get("mitigation") == "nx"]
    assert len(nx_finds) == 1


def test_archive_hardcoded_secrets_detection(tmp_path: Path):
    data = _create_zip({
        "config/credentials.properties": "aws.access.key=AKIAIOSFODNN7EXAMPLE\n",
    })
    p = tmp_path / "secrets.zip"
    p.write_bytes(data)

    engine = InspectEngine()
    report = engine.inspect(p)

    secret_finds = [f for f in report.findings_unified if f.rule_id == "bin.hardcoded-secret"]
    assert len(secret_finds) == 1
    assert secret_finds[0].severity == "critical"
    assert secret_finds[0].engine_meta.get("aws_key_id") == "AKIAIOSFODNN7EXAMPLE"


def test_inspect_cli_archive(tmp_path: Path, capsys):
    data = _create_zip({
        "../../bad.txt": "traversal",
    })
    p = tmp_path / "test.zip"
    p.write_bytes(data)

    code = main(["inspect", str(p), "--format", "json"])
    assert code == 0
    captured = capsys.readouterr().out
    out = json.loads(captured)
    assert out["scan_status"] == "complete"
    rule_ids = {f["rule_id"] for f in out["findings_unified"]}
    assert "bin.archive.zip-slip" in rule_ids


def test_invalid_archive_bytes():
    with pytest.raises(ValueError, match="missing PK zip header magic"):
        parse_archive(b"NOT_A_ZIP", "bad.zip", "sha256:x")
