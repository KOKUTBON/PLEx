"""Pure-Python ZIP, JAR, APK, and Python Wheel package archive inspector."""

from __future__ import annotations

import hashlib
import io
import re
import zipfile
from typing import Any

from .elf import parse_elf
from .macho import parse_macho
from .models import (
    Architecture,
    ArtifactDescriptor,
    BinarySection,
    HardeningProperties,
    RelroMode,
)
from .pe import parse_pe

MAX_EMBEDDED_BINARY_SIZE = 50 * 1024 * 1024  # 50 MB budget per embedded binary
MAX_TEXT_SCAN_SIZE = 2 * 1024 * 1024  # 2 MB budget for text secret scanning

ZIP_LOCAL_MAGIC = b"PK\x03\x04"

# Android high-privilege dangerous permissions
DANGEROUS_ANDROID_PERMISSIONS = {
    "SEND_SMS",
    "RECEIVE_SMS",
    "READ_SMS",
    "RECORD_AUDIO",
    "CAMERA",
    "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION",
    "READ_CONTACTS",
    "WRITE_CONTACTS",
    "READ_CALL_LOG",
    "WRITE_CALL_LOG",
    "READ_EXTERNAL_STORAGE",
    "WRITE_EXTERNAL_STORAGE",
    "INSTALL_PACKAGES",
    "REQUEST_INSTALL_PACKAGES",
    "SYSTEM_ALERT_WINDOW",
}

AWS_KEY_REGEX = re.compile(r"(?:^|[^A-Z0-9])(AKIA[0-9A-Z]{16})(?:[^A-Z0-9]|$)")
PRIVATE_KEY_MARKERS = [
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
]


def _is_zip_slip(name: str) -> bool:
    """Detect if an archive entry attempts directory traversal escaping."""
    if name.startswith(("/", "\\", "../")) or "/../" in name or "\\..\\" in name or "/..\\" in name or "\\../" in name:
        return True
    if re.match(r"^[A-Za-z]:[\\/]", name):
        return True
    return False


def _is_sensitive_file(name: str) -> bool:
    """Detect bundled keystores, credentials, or private keys."""
    n = name.lower()
    if any(
        n.endswith(ext)
        for ext in (
            ".jks",
            ".keystore",
            ".p12",
            ".pfx",
            ".pem",
            ".key",
            ".pk8",
            ".id_rsa",
            ".env",
        )
    ):
        return True
    if any(
        n.endswith(f"/{f}") or n == f
        for f in (
            "credentials.json",
            "secrets.json",
            "service-account.json",
            ".htpasswd",
        )
    ):
        return True
    return False


def _is_native_binary_candidate(name: str) -> bool:
    """Check if entry name indicates a compiled native library or executable."""
    n = name.lower()
    return any(
        n.endswith(ext)
        for ext in (
            ".so",
            ".dylib",
            ".dll",
            ".exe",
            ".pyd",
            ".elf",
            ".node",
        )
    )


def parse_archive(data: bytes, path: str, sha256: str) -> ArtifactDescriptor:
    """Parse ZIP, JAR, APK, or Python Wheel archive structure, manifests, and embedded binaries."""
    if not data.startswith(ZIP_LOCAL_MAGIC):
        raise ValueError("Invalid archive binary: missing PK zip header magic")

    try:
        zf = zipfile.ZipFile(io.BytesIO(data), "r")
    except Exception as exc:
        raise ValueError(f"Corrupt or invalid ZIP archive: {exc}") from exc

    namelist = zf.namelist()
    infolist = zf.infolist()

    # 1. Structural security checks: Zip Slip, sensitive keystores, scripts
    zip_slip_entries: list[str] = []
    sensitive_files: list[str] = []
    embedded_scripts: list[str] = []

    for name in namelist:
        if _is_zip_slip(name):
            zip_slip_entries.append(name)
        if _is_sensitive_file(name):
            sensitive_files.append(name)
        name_lower = name.lower()
        if any(name_lower.endswith(ext) for ext in (".sh", ".bat", ".cmd", ".ps1", ".vbs")):
            embedded_scripts.append(name)

    # 2. Archive Subtype Classification
    archive_type = "zip"
    if "AndroidManifest.xml" in namelist or any(re.match(r"^classes\d*\.dex$", n) for n in namelist):
        archive_type = "apk"
    elif any(n.endswith(".dist-info/METADATA") or n.endswith(".dist-info/WHEEL") for n in namelist):
        archive_type = "wheel"
    elif "META-INF/MANIFEST.MF" in namelist or any(n.endswith(".class") for n in namelist):
        archive_type = "jar"

    manifest_info: dict[str, Any] = {}
    exported_symbols: list[str] = []
    extracted_strings: list[str] = []
    permissions: list[str] = []
    dangerous_permissions: list[str] = []

    # 3. Subtype Manifest & Metadata Extraction
    if archive_type == "wheel":
        for n in namelist:
            if n.endswith(".dist-info/METADATA"):
                try:
                    meta_text = zf.read(n).decode("utf-8", errors="replace")
                    for line in meta_text.splitlines():
                        if ":" in line:
                            k, v = line.split(":", 1)
                            k_clean = k.strip().lower()
                            if k_clean in ("name", "version", "summary", "license", "author"):
                                manifest_info[k_clean] = v.strip()
                except Exception:
                    pass
            elif n.endswith(".dist-info/entry_points.txt"):
                try:
                    ep_text = zf.read(n).decode("utf-8", errors="replace")
                    for line in ep_text.splitlines():
                        line_s = line.strip()
                        if "=" in line_s and not line_s.startswith("["):
                            ep_name = line_s.split("=", 1)[0].strip()
                            exported_symbols.append(ep_name)
                except Exception:
                    pass

    elif archive_type == "jar":
        if "META-INF/MANIFEST.MF" in namelist:
            try:
                mf_text = zf.read("META-INF/MANIFEST.MF").decode("utf-8", errors="replace")
                for line in mf_text.splitlines():
                    if ":" in line:
                        k, v = line.split(":", 1)
                        manifest_info[k.strip()] = v.strip()
                        if k.strip().lower() == "main-class":
                            exported_symbols.append(v.strip())
            except Exception:
                pass

    elif archive_type == "apk":
        if "AndroidManifest.xml" in namelist:
            try:
                axml_bytes = zf.read("AndroidManifest.xml")
                # Extract permission tokens from binary XML or plaintext
                # Tokens appear as ASCII or UTF-16 strings: android.permission.<NAME>
                matches = re.findall(rb"android\.permission\.([A-Za-z0-9_]+)", axml_bytes)
                found_perms = sorted(set(m.decode("ascii", errors="replace") for m in matches))
                for perm in found_perms:
                    permissions.append(perm)
                    if perm.upper() in DANGEROUS_ANDROID_PERMISSIONS:
                        dangerous_permissions.append(perm)
            except Exception:
                pass

    # 4. Embedded Native Binaries Recursive Inspection
    embedded_binaries: list[dict[str, Any]] = []
    imported_symbols: list[str] = []
    detected_architectures: list[Architecture] = []
    embedded_hardening_list: list[HardeningProperties] = []

    for info in infolist:
        if info.is_dir() or info.file_size == 0 or info.file_size > MAX_EMBEDDED_BINARY_SIZE:
            continue

        is_cand = _is_native_binary_candidate(info.filename)
        # Read header bytes to check if native binary magic is present
        try:
            with zf.open(info.filename) as f:
                head = f.read(16)
        except Exception:
            continue

        sub_desc: ArtifactDescriptor | None = None
        sub_data: bytes | None = None

        if head.startswith(b"\x7fELF"):
            try:
                sub_data = zf.read(info.filename)
                sub_desc = parse_elf(sub_data, f"{path}!{info.filename}", hashlib.sha256(sub_data).hexdigest())
            except Exception:
                pass
        elif head.startswith(b"MZ"):
            try:
                sub_data = zf.read(info.filename)
                sub_desc = parse_pe(sub_data, f"{path}!{info.filename}", hashlib.sha256(sub_data).hexdigest())
            except Exception:
                pass
        elif head.startswith((b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca")):
            try:
                sub_data = zf.read(info.filename)
                sub_desc = parse_macho(sub_data, f"{path}!{info.filename}", hashlib.sha256(sub_data).hexdigest())
            except Exception:
                pass
        elif is_cand:
            # Candidate extension without standard magic - ignore or skip
            pass

        if sub_desc:
            detected_architectures.append(sub_desc.architecture)
            embedded_hardening_list.append(sub_desc.hardening)
            imported_symbols.extend(sub_desc.imported_symbols)
            exported_symbols.extend(sub_desc.exported_symbols)
            extracted_strings.extend(sub_desc.extracted_strings)

            embedded_binaries.append(
                {
                    "filename": info.filename,
                    "format": sub_desc.format,
                    "architecture": sub_desc.architecture,
                    "size": info.file_size,
                    "is_stripped": sub_desc.is_stripped,
                    "hardening": {
                        "nx": sub_desc.hardening.nx,
                        "pie": sub_desc.hardening.pie,
                        "relro": sub_desc.hardening.relro,
                        "canary": sub_desc.hardening.canary,
                    },
                    "imported_symbols_count": len(sub_desc.imported_symbols),
                }
            )

    # 5. Text Files Secret Scanning
    for info in infolist:
        if info.is_dir() or info.file_size == 0 or info.file_size > MAX_TEXT_SCAN_SIZE:
            continue
        fname_lower = info.filename.lower()
        if any(
            fname_lower.endswith(ext)
            for ext in (".txt", ".json", ".xml", ".properties", ".yml", ".yaml", ".ini", ".conf", ".py", ".java")
        ):
            try:
                content = zf.read(info.filename).decode("utf-8", errors="replace")
                for marker in PRIVATE_KEY_MARKERS:
                    if marker in content:
                        extracted_strings.append(marker)
                aws_match = AWS_KEY_REGEX.search(content)
                if aws_match:
                    extracted_strings.append(aws_match.group(1))
            except Exception:
                pass

    # 6. Synthesize Sections & Hardening Properties
    sections: list[BinarySection] = []
    for info in infolist[:100]:
        sections.append(
            BinarySection(
                name=info.filename,
                type_name="compressed_entry",
                flags="r",
                virtual_address=0,
                offset=info.header_offset,
                size=info.file_size,
            )
        )

    # Aggregate hardening
    primary_arch: Architecture = "unknown"
    if detected_architectures:
        primary_arch = detected_architectures[0]

    # If embedded binaries exist, aggregate hardening; otherwise default to safe
    if embedded_hardening_list:
        all_nx = all(h.nx for h in embedded_hardening_list)
        all_pie = all(h.pie for h in embedded_hardening_list)
        all_canary = all(h.canary for h in embedded_hardening_list)
        relro_modes = [h.relro for h in embedded_hardening_list]
        relro_agg: RelroMode = "full" if all(r == "full" for r in relro_modes) else (
            "partial" if any(r in ("partial", "full") for r in relro_modes) else "none"
        )
        hardening = HardeningProperties(
            nx=all_nx,
            pie=all_pie,
            canary=all_canary,
            relro=relro_agg,
        )
    else:
        # Pure non-native package: compiler hardening flags are not applicable
        hardening = HardeningProperties(
            nx=True,
            pie=True,
            canary=True,
            relro="full",
        )

    metadata: dict[str, Any] = {
        "archive_type": archive_type,
        "entry_count": len(namelist),
        "total_compressed_size": sum(i.compress_size for i in infolist),
        "total_uncompressed_size": sum(i.file_size for i in infolist),
        "manifest_info": manifest_info,
        "permissions": permissions,
        "dangerous_permissions": dangerous_permissions,
        "zip_slip_entries": zip_slip_entries,
        "sensitive_files": sensitive_files,
        "embedded_scripts": embedded_scripts,
        "embedded_binaries": embedded_binaries,
    }

    return ArtifactDescriptor(
        path=path,
        sha256=sha256,
        size=len(data),
        format="archive",
        architecture=primary_arch,
        endianness="little",
        is_64bit=any(b.get("format") in ("elf", "macho", "pe") for b in embedded_binaries),
        entry_point=0,
        sections=tuple(sections),
        imported_symbols=tuple(sorted(set(imported_symbols))),
        exported_symbols=tuple(sorted(set(exported_symbols))),
        extracted_strings=tuple(sorted(set(extracted_strings))),
        hardening=hardening,
        is_stripped=all(b.get("is_stripped", False) for b in embedded_binaries) if embedded_binaries else False,
        metadata=metadata,
    )
