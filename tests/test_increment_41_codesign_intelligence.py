"""Comprehensive behavioral test suite for Increment 41:
Native Mach-O Code Signature & Entitlements Analysis, Apple Hardened Runtime verification,
PE Authenticode digest extraction, and Code Signing capabilities.
"""

from __future__ import annotations

import json
import plistlib
import struct
from pathlib import Path

from plex.evidence import EvidenceStore
from plex.inspect.capabilities import detect_capabilities
from plex.inspect.engine import InspectEngine
from plex.inspect.macho import (
    CPU_TYPE_ARM64,
    LC_CODE_SIGNATURE,
    LC_MAIN,
    LC_SEGMENT_64,
    MH_EXECUTE,
    MH_MAGIC_64,
    MH_PIE,
    MH_TWOLEVEL,
    parse_macho,
)
from plex.inspect.macho_cs import (
    CS_ADHOC,
    CS_RUNTIME,
    CS_VALID,
    CSMAGIC_CODEDIRECTORY,
    CSMAGIC_EMBEDDED_SIGNATURE,
    CSMAGIC_ENTITLEMENTS,
    CSSLOT_CODEDIRECTORY,
    CSSLOT_ENTITLEMENTS,
    parse_code_directory,
    parse_entitlements,
    parse_macho_code_signature,
)
from plex.inspect.models import (
    ArtifactDescriptor,
    HardeningProperties,
)
from plex.inspect.pe import (
    WIN_CERT_TYPE_PKCS_SIGNED_DATA,
    parse_authenticode,
    parse_pe,
)
from plex.inspect.rules import evaluate_artifact_rules
from plex.report.unified import EvidenceRef

# ==============================================================================
# Helpers for Synthetic Binary Generation
# ==============================================================================


def build_synthetic_code_directory(
    *,
    ident: str = "com.example.app",
    team_id: str = "TEAM12345",
    flags: int = CS_VALID | CS_RUNTIME,
    hash_type: int = 2,  # SHA-256
) -> bytes:
    """Build a valid binary CS_CodeDirectory blob."""
    ident_bytes = ident.encode("utf-8") + b"\x00"
    team_bytes = team_id.encode("utf-8") + b"\x00" if team_id else b""

    # Base header size: 44 bytes + version 0x20200 fields (scatterOffset 4, teamIDOffset 4) = 52 bytes
    header_size = 52
    ident_offset = header_size
    team_offset = ident_offset + len(ident_bytes) if team_id else 0
    total_len = header_size + len(ident_bytes) + len(team_bytes)

    buf = bytearray(total_len)
    struct.pack_into(
        ">IIIIIIIIIBBBBI",
        buf,
        0,
        CSMAGIC_CODEDIRECTORY,
        total_len,
        0x20200,  # version
        flags,
        total_len,  # hashOffset
        ident_offset,
        0,  # nSpecialSlots
        1,  # nCodeSlots
        0x1000,  # codeLimit
        32 if hash_type == 2 else 20,  # hashSize
        hash_type,
        26,  # platform
        12,  # pageSize (4096)
        0,  # spare2
    )
    # scatterOffset = 0, teamIDOffset
    struct.pack_into(">II", buf, 44, 0, team_offset)

    buf[ident_offset : ident_offset + len(ident_bytes)] = ident_bytes
    if team_id:
        buf[team_offset : team_offset + len(team_bytes)] = team_bytes

    return bytes(buf)


def build_synthetic_entitlements(entitlements: dict[str, bool | str]) -> bytes:
    """Build a binary CSMAGIC_ENTITLEMENTS blob with XML plist."""
    xml_data = plistlib.dumps(entitlements, fmt=plistlib.FMT_XML)
    total_len = 8 + len(xml_data)
    buf = bytearray(total_len)
    struct.pack_into(">II", buf, 0, CSMAGIC_ENTITLEMENTS, total_len)
    buf[8:total_len] = xml_data
    return bytes(buf)


def build_synthetic_superblob(blobs: list[tuple[int, bytes]]) -> bytes:
    """Build a CS_SuperBlob holding multiple slot blobs."""
    count = len(blobs)
    header_len = 12 + count * 8

    # Calculate offsets for each slot
    cur_offset = header_len
    offsets: list[int] = []
    for _, blob_data in blobs:
        offsets.append(cur_offset)
        cur_offset += len(blob_data)

    total_len = cur_offset
    buf = bytearray(total_len)
    struct.pack_into(">III", buf, 0, CSMAGIC_EMBEDDED_SIGNATURE, total_len, count)

    for i, ((slot_type, blob_data), offset) in enumerate(zip(blobs, offsets, strict=True)):
        struct.pack_into(">II", buf, 12 + i * 8, slot_type, offset)
        buf[offset : offset + len(blob_data)] = blob_data

    return bytes(buf)


def build_synthetic_macho_with_codesign(superblob_bytes: bytes) -> bytes:
    """Construct a minimal valid 64-bit Mach-O binary containing LC_CODE_SIGNATURE."""
    order = "<"
    cs_offset = 0x1000
    cs_size = len(superblob_bytes)

    # Load commands: LC_SEGMENT_64 (__TEXT), LC_MAIN, LC_CODE_SIGNATURE
    cmds = bytearray()

    # 1. __TEXT Segment (72 bytes)
    cmds.extend(
        struct.pack(
            f"{order}II16sQQQQiiII",
            LC_SEGMENT_64,
            72,
            b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            0x100000000,
            0x1000,
            0,
            0x1000,
            7,
            5,
            0,
            0,
        )
    )

    # 2. LC_MAIN (24 bytes)
    cmds.extend(struct.pack(f"{order}IIQQ", LC_MAIN, 24, 0x1000, 0x800000))

    # 3. LC_CODE_SIGNATURE (16 bytes)
    cmds.extend(struct.pack(f"{order}IIII", LC_CODE_SIGNATURE, 16, cs_offset, cs_size))

    ncmds = 3
    header = struct.pack(
        f"{order}IIIIIIII",
        MH_MAGIC_64,
        CPU_TYPE_ARM64,
        3,
        MH_EXECUTE,
        ncmds,
        len(cmds),
        MH_PIE | MH_TWOLEVEL,
        0,
    )

    data = bytearray(header + cmds)
    if len(data) < cs_offset:
        data.extend(b"\x00" * (cs_offset - len(data)))
    data.extend(superblob_bytes)
    return bytes(data)


# ==============================================================================
# 1. Mach-O Code Signature & Entitlements Structural Parser Tests
# ==============================================================================


def test_parse_code_directory_sha256() -> None:
    cd_bytes = build_synthetic_code_directory(
        ident="com.security.testapp",
        team_id="MYTEAMID99",
        flags=CS_VALID | CS_RUNTIME,
        hash_type=2,
    )
    info = parse_code_directory(cd_bytes)
    assert info is not None
    assert info["signing_id"] == "com.security.testapp"
    assert info["team_id"] == "MYTEAMID99"
    assert info["cdhash_type"] == "sha256"
    assert len(info["cdhash"]) == 40  # Standard 20-byte / 40-char cdhash
    assert len(info["cdhash_full"]) == 64
    assert info["has_hardened_runtime"] is True
    assert "CS_RUNTIME" in info["code_sign_flags_names"]
    assert "CS_VALID" in info["code_sign_flags_names"]


def test_parse_code_directory_sha1() -> None:
    cd_bytes = build_synthetic_code_directory(
        ident="legacy.tool",
        team_id="",
        flags=CS_ADHOC,
        hash_type=1,
    )
    info = parse_code_directory(cd_bytes)
    assert info is not None
    assert info["signing_id"] == "legacy.tool"
    assert info["cdhash_type"] == "sha1"
    assert len(info["cdhash"]) == 40
    assert info["has_hardened_runtime"] is False
    assert "CS_ADHOC" in info["code_sign_flags_names"]


def test_parse_entitlements_xml() -> None:
    ents_dict = {
        "com.apple.security.get-task-allow": True,
        "com.apple.security.cs.disable-library-validation": True,
        "com.apple.security.app-sandbox": False,
        "application-identifier": "MYTEAM.com.app",
    }
    ent_bytes = build_synthetic_entitlements(ents_dict)
    parsed, raw_xml = parse_entitlements(ent_bytes)

    assert parsed["com.apple.security.get-task-allow"] is True
    assert parsed["com.apple.security.cs.disable-library-validation"] is True
    assert parsed["application-identifier"] == "MYTEAM.com.app"
    assert "<?xml" in raw_xml


def test_parse_macho_code_signature_superblob() -> None:
    cd_bytes = build_synthetic_code_directory(
        ident="com.corp.agent",
        team_id="APPLETEAM1",
        flags=CS_RUNTIME,
    )
    ent_bytes = build_synthetic_entitlements({"com.apple.security.cs.allow-jit": True})
    superblob = build_synthetic_superblob([
        (CSSLOT_CODEDIRECTORY, cd_bytes),
        (CSSLOT_ENTITLEMENTS, ent_bytes),
    ])

    result = parse_macho_code_signature(superblob)
    assert result["signing_id"] == "com.corp.agent"
    assert result["team_id"] == "APPLETEAM1"
    assert result["has_hardened_runtime"] is True
    assert "cdhash" in result
    assert result["entitlements"].get("com.apple.security.cs.allow-jit") is True


# ==============================================================================
# 2. Mach-O Integration Tests
# ==============================================================================


def test_macho_binary_with_embedded_signature() -> None:
    cd_bytes = build_synthetic_code_directory(
        ident="com.demo.service",
        team_id="DEVTEAM100",
        flags=CS_RUNTIME | CS_VALID,
    )
    ent_bytes = build_synthetic_entitlements({
        "com.apple.security.get-task-allow": True,
        "com.apple.security.cs.disable-library-validation": True,
    })
    superblob = build_synthetic_superblob([
        (CSSLOT_CODEDIRECTORY, cd_bytes),
        (CSSLOT_ENTITLEMENTS, ent_bytes),
    ])

    macho_data = build_synthetic_macho_with_codesign(superblob)
    desc = parse_macho(macho_data, "/tmp/demo_service", "sha256_mock")

    assert desc.metadata.get("has_code_signature") is True
    assert desc.metadata.get("signing_id") == "com.demo.service"
    assert desc.metadata.get("team_id") == "DEVTEAM100"
    assert desc.metadata.get("has_hardened_runtime") is True
    assert "cdhash" in desc.metadata

    ents = desc.metadata.get("entitlements", {})
    assert ents.get("com.apple.security.get-task-allow") is True
    assert ents.get("com.apple.security.cs.disable-library-validation") is True


def test_real_macos_system_binaries() -> None:
    # Test real host Mach-O binary parsing if running on macOS
    ls_path = Path("/bin/ls")
    if ls_path.exists():
        desc = parse_macho(ls_path.read_bytes(), "/bin/ls", "sha256_mock")
        assert desc.format == "macho"
        assert desc.metadata.get("has_code_signature") is True
        assert desc.metadata.get("signing_id") == "com.apple.ls"
        assert "cdhash" in desc.metadata
        assert len(desc.metadata["cdhash"]) == 40


# ==============================================================================
# 3. PE Authenticode Digest & Structure Tests
# ==============================================================================


def test_parse_authenticode_sha256() -> None:
    # Build synthetic WIN_CERTIFICATE with SHA-256 OID
    # OID 2.16.840.1.101.3.4.2.1 is encoded as tag 0x06, len 9, bytes
    sha256_oid = b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01"
    cert_payload = b"\x30\x82\x01\x00" + sha256_oid + b"\x00" * 32
    dwLength = 8 + len(cert_payload)

    win_cert = struct.pack("<IIH", dwLength, 0x0200, WIN_CERT_TYPE_PKCS_SIGNED_DATA) + cert_payload
    data = b"\x00" * 0x1000 + win_cert

    info = parse_authenticode(data, 0x1000, dwLength)
    assert info is not None
    assert info["cert_type"] == "PKCS_SIGNED_DATA"
    assert info["digest_algorithm"] == "sha256"
    assert info["certificates_detected"] >= 1
    assert info["cert_length"] == dwLength


def test_parse_authenticode_sha1() -> None:
    # Build synthetic WIN_CERTIFICATE with SHA-1 OID
    # OID 1.3.14.3.2.26 is encoded as tag 0x06, len 5, bytes
    sha1_oid = b"\x06\x05\x2b\x0e\x03\x02\x1a"
    cert_payload = b"\x30\x82\x00\x80" + sha1_oid + b"\x00" * 16
    dwLength = 8 + len(cert_payload)

    win_cert = struct.pack("<IIH", dwLength, 0x0200, WIN_CERT_TYPE_PKCS_SIGNED_DATA) + cert_payload
    data = b"\x00" * 0x2000 + win_cert

    info = parse_authenticode(data, 0x2000, dwLength)
    assert info is not None
    assert info["digest_algorithm"] == "sha1"


def test_pe_binary_with_authenticode_metadata() -> None:
    # Construct minimal PE binary with Security Directory
    sha256_oid = b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01"
    cert_payload = b"\x30\x82\x01\x00" + sha256_oid + b"\x00" * 64
    dwLength = 8 + len(cert_payload)
    win_cert = struct.pack("<IIH", dwLength, 0x0200, WIN_CERT_TYPE_PKCS_SIGNED_DATA) + cert_payload

    # Minimal DOS header
    dos_header = bytearray(0x80)
    struct.pack_into("<H", dos_header, 0, 0x5A4D)  # 'MZ'
    struct.pack_into("<I", dos_header, 0x3C, 0x80)  # e_lfanew

    pe_headers = bytearray(0x400)
    struct.pack_into("<I", pe_headers, 0, 0x00004550)  # 'PE\0\0'
    struct.pack_into("<HHIIIHH", pe_headers, 4, 0x8664, 1, 0, 0, 0, 240, 0x0022)
    # Optional header
    struct.pack_into("<H", pe_headers, 24, 0x020B)  # PE32+
    struct.pack_into("<I", pe_headers, 24 + 16, 0x1000)  # AddressOfEntryPoint
    struct.pack_into("<I", pe_headers, 24 + 108, 16)  # NumberOfRvaAndSizes

    # Security directory entry (index 4) at offset 24 + 112 + 4 * 8 = 168
    cert_file_offset = 0x480
    struct.pack_into("<II", pe_headers, 24 + 112 + 4 * 8, cert_file_offset, dwLength)

    # Section header: .text
    struct.pack_into("<8sIIIIIIHHI", pe_headers, 24 + 240, b".text\x00\x00\x00", 0x100, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)

    raw_binary = bytearray(dos_header + pe_headers)
    if len(raw_binary) < cert_file_offset:
        raw_binary.extend(b"\x00" * (cert_file_offset - len(raw_binary)))
    raw_binary.extend(win_cert)

    desc = parse_pe(bytes(raw_binary), "/tmp/signed.exe", "mock_pe_sha")
    assert desc.metadata.get("has_authenticode") is True
    assert "authenticode" in desc.metadata
    assert desc.metadata["authenticode"]["digest_algorithm"] == "sha256"


# ==============================================================================
# 4. Security Rules Tests (Rules 12, 13, 14)
# ==============================================================================


def test_rule_macho_dangerous_entitlement_detected() -> None:
    desc = ArtifactDescriptor(
        path="/app/vulnerable_app",
        sha256="mock_hash",
        size=1000,
        format="macho",
        architecture="aarch64",
        endianness="little",
        is_64bit=True,
        entry_point=0x1000,
        hardening=HardeningProperties(pie=True, nx=True),
        metadata={
            "entitlements": {
                "com.apple.security.get-task-allow": True,
                "com.apple.security.cs.disable-library-validation": True,
                "com.apple.security.cs.allow-dyld-environment-variables": True,
            }
        },
    )
    ev_ref = EvidenceRef(engine="inspect", kind="artifact_structure", ref="dummy_ref")
    findings = evaluate_artifact_rules(desc, ev_ref)
    rule_ids = [f.rule_id for f in findings]

    assert "bin.macho.dangerous-entitlement" in rule_ids
    ent_findings = [f for f in findings if f.rule_id == "bin.macho.dangerous-entitlement"]
    assert len(ent_findings) == 3

    # get-task-allow must have severity 'high'
    gta = next(f for f in ent_findings if f.engine_meta.get("entitlement") == "com.apple.security.get-task-allow")
    assert gta.severity == "high"
    assert "CWE-250" in gta.cwe


def test_rule_macho_unhardened_runtime_detected() -> None:
    desc = ArtifactDescriptor(
        path="/app/unhardened_app",
        sha256="mock_hash",
        size=1000,
        format="macho",
        architecture="aarch64",
        endianness="little",
        is_64bit=True,
        entry_point=0x1000,
        hardening=HardeningProperties(pie=True, nx=True),
        metadata={
            "has_code_signature": True,
            "has_hardened_runtime": False,
            "filetype": 2,  # MH_EXECUTE
        },
    )
    ev_ref = EvidenceRef(engine="inspect", kind="artifact_structure", ref="dummy_ref")
    findings = evaluate_artifact_rules(desc, ev_ref)
    rule_ids = [f.rule_id for f in findings]
    assert "bin.macho.unhardened-runtime" in rule_ids

    # When Hardened Runtime is present, no finding should be emitted
    desc_hardened = ArtifactDescriptor(
        path="/app/hardened_app",
        sha256="mock_hash",
        size=1000,
        format="macho",
        architecture="aarch64",
        endianness="little",
        is_64bit=True,
        entry_point=0x1000,
        hardening=HardeningProperties(pie=True, nx=True),
        metadata={
            "has_code_signature": True,
            "has_hardened_runtime": True,
            "filetype": 2,
        },
    )
    findings_hardened = evaluate_artifact_rules(desc_hardened, ev_ref)
    assert "bin.macho.unhardened-runtime" not in [f.rule_id for f in findings_hardened]


def test_rule_weak_signature_digest_detected() -> None:
    # Test PE with SHA-1 signature
    desc_pe = ArtifactDescriptor(
        path="/app/legacy_signed.exe",
        sha256="mock_hash",
        size=1000,
        format="pe",
        architecture="x86_64",
        endianness="little",
        is_64bit=True,
        entry_point=0x1000,
        hardening=HardeningProperties(pie=True, nx=True),
        metadata={
            "authenticode": {"digest_algorithm": "sha1"}
        },
    )
    ev_ref = EvidenceRef(engine="inspect", kind="artifact_structure", ref="dummy_ref")
    findings_pe = evaluate_artifact_rules(desc_pe, ev_ref)
    assert "bin.hardening.weak-signature-digest" in [f.rule_id for f in findings_pe]

    # Test Mach-O with SHA-1 cdhash
    desc_macho = ArtifactDescriptor(
        path="/app/legacy_signed_macho",
        sha256="mock_hash",
        size=1000,
        format="macho",
        architecture="aarch64",
        endianness="little",
        is_64bit=True,
        entry_point=0x1000,
        hardening=HardeningProperties(pie=True, nx=True),
        metadata={
            "cdhash_type": "sha1"
        },
    )
    findings_macho = evaluate_artifact_rules(desc_macho, ev_ref)
    assert "bin.hardening.weak-signature-digest" in [f.rule_id for f in findings_macho]


# ==============================================================================
# 5. Capabilities Hypothesis Tests (bin.capability.codesign)
# ==============================================================================


def test_capability_codesign_detected() -> None:
    desc = ArtifactDescriptor(
        path="/app/signed_app",
        sha256="mock_hash",
        size=1000,
        format="macho",
        architecture="aarch64",
        endianness="little",
        is_64bit=True,
        entry_point=0x1000,
        hardening=HardeningProperties(pie=True, nx=True),
        metadata={
            "cdhash": "45d1613a435c6cb05794cbb585587a5245989943",
            "signing_id": "com.company.agent",
            "team_id": "MYTEAM77",
        },
    )
    ev_ref = EvidenceRef(engine="inspect", kind="artifact_structure", ref="dummy_ref")
    caps = detect_capabilities(desc, ev_ref)
    codesign_caps = [c for c in caps if c.rule_id == "bin.capability.codesign"]
    assert len(codesign_caps) == 1
    c = codesign_caps[0]
    assert c.engine_meta["cdhash"] == "45d1613a435c6cb05794cbb585587a5245989943"
    assert c.engine_meta["signing_id"] == "com.company.agent"
    assert c.engine_meta["team_id"] == "MYTEAM77"


# ==============================================================================
# 6. InspectEngine & EvidenceStore End-to-End Tests
# ==============================================================================


def test_inspect_engine_evidence_store_codesign(tmp_path: Path) -> None:
    store_dir = tmp_path / "store"
    store = EvidenceStore(store_dir)
    engine = InspectEngine(evidence_store=store)

    cd_bytes = build_synthetic_code_directory(
        ident="com.audit.tool",
        team_id="AUDIT123",
        flags=CS_RUNTIME,
    )
    superblob = build_synthetic_superblob([(CSSLOT_CODEDIRECTORY, cd_bytes)])
    binary_bytes = build_synthetic_macho_with_codesign(superblob)

    bin_path = tmp_path / "signed_test_bin"
    bin_path.write_bytes(binary_bytes)

    report = engine.inspect(bin_path)
    assert report.scan_status == "complete"

    # Verify findings include capability codesign
    rule_ids = [f.rule_id for f in report.findings_unified]
    assert "bin.capability.codesign" in rule_ids

    # Verify evidence artifact stored in evidence store
    codesign_finding = next(f for f in report.findings_unified if f.rule_id == "bin.capability.codesign")
    assert codesign_finding.evidence
    ev_ref = codesign_finding.evidence[0]
    assert ev_ref.digest is not None
    stored_art = store.get(ev_ref.digest)
    assert stored_art is not None
    assert stored_art.kind == "artifact_structure"
    content = json.loads(stored_art.payload)
    assert content["signing_id"] == "com.audit.tool"
    assert content["team_id"] == "AUDIT123"
    assert "cdhash" in content
