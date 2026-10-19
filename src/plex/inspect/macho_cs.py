"""Pure-Python Mach-O Code Signature and Entitlements structural parser."""

from __future__ import annotations

import hashlib
import plistlib
import struct
from typing import Any

CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_ENTITLEMENTS = 0xFADE7171
CSMAGIC_DER_ENTITLEMENTS = 0xFADE7172

CSSLOT_CODEDIRECTORY = 0
CSSLOT_ENTITLEMENTS = 5

CS_RUNTIME = 0x00010000  # Apple Hardened Runtime flag
CS_ADHOC = 0x00000002
CS_VALID = 0x00000001
CS_KILL = 0x00000200
CS_HARD = 0x00000100
CS_ENFORCEMENT = 0x00001000

CS_FLAG_NAMES: dict[int, str] = {
    CS_VALID: "CS_VALID",
    CS_ADHOC: "CS_ADHOC",
    CS_HARD: "CS_HARD",
    CS_KILL: "CS_KILL",
    CS_ENFORCEMENT: "CS_ENFORCEMENT",
    CS_RUNTIME: "CS_RUNTIME",
}


def parse_code_directory(cd_bytes: bytes) -> dict[str, Any] | None:
    """Parse a Mach-O CodeDirectory blob and extract CDHash, signing ID, Team ID, and flags."""
    if len(cd_bytes) < 44:
        return None

    magic, cd_len = struct.unpack_from(">II", cd_bytes, 0)
    if magic != CSMAGIC_CODEDIRECTORY:
        return None

    if cd_len > len(cd_bytes):
        cd_len = len(cd_bytes)

    (
        _,
        _,
        version,
        flags,
        hash_offset,
        ident_offset,
        n_special_slots,
        n_code_slots,
        code_limit,
        hash_size,
        hash_type,
        platform,
        page_size,
        _,
    ) = struct.unpack_from(">IIIIIIIIIBBBBI", cd_bytes, 0)

    # Compute standard CDHash
    # Standard macOS cdhash is the SHA-256 (or SHA-1) digest of the entire CodeDirectory blob
    if hash_type == 2:
        cdhash_full = hashlib.sha256(cd_bytes[:cd_len]).hexdigest()
        cdhash = cdhash_full[:40]  # Standard 20-byte / 40-hex-char CDHash
        hash_name = "sha256"
    elif hash_type == 1:
        cdhash_full = hashlib.sha1(cd_bytes[:cd_len]).hexdigest()
        cdhash = cdhash_full
        hash_name = "sha1"
    else:
        cdhash_full = hashlib.sha256(cd_bytes[:cd_len]).hexdigest()
        cdhash = cdhash_full[:40]
        hash_name = f"type_{hash_type}"

    ident = ""
    if 0 < ident_offset < cd_len:
        ident_raw = cd_bytes[ident_offset:cd_len].split(b"\x00")[0]
        ident = ident_raw.decode("utf-8", errors="replace")

    team_id = ""
    if version >= 0x20200 and cd_len >= 52:
        team_id_offset = struct.unpack_from(">I", cd_bytes, 48)[0]
        if 0 < team_id_offset < cd_len:
            team_raw = cd_bytes[team_id_offset:cd_len].split(b"\x00")[0]
            team_id = team_raw.decode("utf-8", errors="replace")

    active_flags = [name for flag_bit, name in CS_FLAG_NAMES.items() if bool(flags & flag_bit)]

    return {
        "cdhash": cdhash,
        "cdhash_full": cdhash_full,
        "cdhash_type": hash_name,
        "signing_id": ident,
        "team_id": team_id,
        "code_sign_flags": flags,
        "code_sign_flags_names": active_flags,
        "has_hardened_runtime": bool(flags & CS_RUNTIME),
        "code_limit": code_limit,
        "code_directory_version": hex(version),
        "platform_identifier": platform,
    }


def parse_entitlements(ent_bytes: bytes) -> tuple[dict[str, Any], str]:
    """Parse Mach-O entitlements slot blob into a dictionary and raw XML string."""
    if len(ent_bytes) < 8:
        return {}, ""

    magic, length = struct.unpack_from(">II", ent_bytes, 0)
    if magic not in (CSMAGIC_ENTITLEMENTS, CSMAGIC_DER_ENTITLEMENTS):
        return {}, ""

    if length > len(ent_bytes):
        length = len(ent_bytes)

    raw_payload = ent_bytes[8:length]
    raw_xml = ""
    entitlements: dict[str, Any] = {}

    if magic == CSMAGIC_ENTITLEMENTS:
        try:
            raw_xml = raw_payload.decode("utf-8", errors="replace")
            parsed = plistlib.loads(raw_payload)
            if isinstance(parsed, dict):
                entitlements = parsed
        except Exception:
            pass

    return entitlements, raw_xml


def parse_macho_code_signature(cs_data: bytes) -> dict[str, Any]:
    """Parse Mach-O code signature SuperBlob or standalone CodeDirectory."""
    if len(cs_data) < 12:
        return {}

    magic = struct.unpack_from(">I", cs_data, 0)[0]

    # Standalone CodeDirectory
    if magic == CSMAGIC_CODEDIRECTORY:
        cd_info = parse_code_directory(cs_data)
        return cd_info or {}

    if magic != CSMAGIC_EMBEDDED_SIGNATURE:
        return {}

    _, length, count = struct.unpack_from(">III", cs_data, 0)
    if count > 100:  # Sanity bound
        count = 100

    result: dict[str, Any] = {}

    for i in range(count):
        entry_off = 12 + i * 8
        if entry_off + 8 > len(cs_data):
            break
        slot_type, slot_offset = struct.unpack_from(">II", cs_data, entry_off)
        if slot_offset >= len(cs_data):
            continue

        blob_bytes = cs_data[slot_offset:]
        if len(blob_bytes) < 4:
            continue

        blob_magic = struct.unpack_from(">I", blob_bytes, 0)[0]

        if slot_type == CSSLOT_CODEDIRECTORY or blob_magic == CSMAGIC_CODEDIRECTORY:
            cd_info = parse_code_directory(blob_bytes)
            if cd_info and "cdhash" not in result:
                result.update(cd_info)

        elif slot_type == CSSLOT_ENTITLEMENTS or blob_magic in (CSMAGIC_ENTITLEMENTS, CSMAGIC_DER_ENTITLEMENTS):
            ents, raw_xml = parse_entitlements(blob_bytes)
            if ents:
                result["entitlements"] = ents
                result["raw_entitlements_xml"] = raw_xml

    return result
