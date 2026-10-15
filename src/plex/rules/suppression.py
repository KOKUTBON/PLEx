"""Rule suppression comment parsing and matching subsystem for PLEx.

Supports fine-grained suppression comments:
- Line-level inline: `val = d[k]  # plex: ignore[plex.try-except-dict-get]`
- Next-line: `# plex: disable-next[plex.db-in-loop]` or `# plex: ignore[rule]` before stmt
- Block-level: `# plex: disable=rule` ... `# plex: enable=rule`
- File-level: `# plex: disable-file[rule]` or `# plex: disable-all`
- Multi-rule: `# plex: ignore[rule1, rule2]` or `# plex: disable=rule1,rule2`
- Metadata: `reason="...", ticket="..."`
- Unused suppression detection
"""

from __future__ import annotations

import io
import re
import tokenize
from dataclasses import dataclass, field

from plex.report.models import Suppression

_META_RE = re.compile(r"\b(reason|ticket)\s*=\s*(['\"])(.*?)\2", re.IGNORECASE)

# File-level directives:
# # plex: disable-file[rule1, rule2]
# # plex: file-ignore[rule1]
# # plex: disable-all
_FILE_DIRECTIVE_RE = re.compile(
    r"\bplex:\s*(?:disable-file|file-ignore)(?:\[([^\]]*)\])?|\bplex:\s*disable-all",
    re.IGNORECASE,
)

# Next-line explicit directives:
# # plex: disable-next[rule]
# # plex: disable-next-line[rule]
# # plex: ignore-next[rule]
# # plex: ignore-next-line[rule]
_NEXT_LINE_DIRECTIVE_RE = re.compile(
    r"\bplex:\s*(?:disable-next(?:-line)?|ignore-next(?:-line)?)(?:\[([^\]]*)\])?",
    re.IGNORECASE,
)

# Block disable / enable directives:
# # plex: disable=rule1,rule2
# # plex: disable
_BLOCK_DISABLE_RE = re.compile(
    r"\bplex:\s*disable(?![-])(?:=([^\s,;]+(?:,[^\s,;]+)*))?",
    re.IGNORECASE,
)
_BLOCK_ENABLE_RE = re.compile(
    r"\bplex:\s*enable(?![-])(?:=([^\s,;]+(?:,[^\s,;]+)*))?",
    re.IGNORECASE,
)

# General ignore directive:
# # plex: ignore[rule1, rule2]
# # plex: ignore
_IGNORE_DIRECTIVE_RE = re.compile(
    r"\bplex:\s*ignore(?:\[([^\]]*)\])?",
    re.IGNORECASE,
)

# Compatibility directive for alternative comment syntax (e.g. "noqa: plex.rule-id")
_NOQA_DIRECTIVE_RE = re.compile(
    r"\bnoqa:\s*((?:plex)(?:\.[\w-]+)?(?:,\s*(?:plex)(?:\.[\w-]+)?)*)",
    re.IGNORECASE,
)


def _parse_rules_spec(raw: str | None) -> set[str]:
    """Parse comma-separated rule list into normalized set of rule IDs."""
    if raw is None or not raw.strip():
        return {"*"}
    rules: set[str] = set()
    for item in raw.split(","):
        rule_id = item.strip()
        if not rule_id:
            continue
        if rule_id in {"*", "all"}:
            rules.add("*")
        else:
            base = rule_id.removeprefix("plex.")
            rules.add(base)
            rules.add(f"plex.{base}")
    return rules or {"*"}


def _parse_metadata(comment_text: str) -> tuple[str, str]:
    """Extract reason and ticket metadata from comment string."""
    reason = ""
    ticket = ""
    for match in _META_RE.finditer(comment_text):
        key = match.group(1).lower()
        val = match.group(3)
        if key == "reason":
            reason = val
        elif key == "ticket":
            ticket = val
    return reason, ticket


@dataclass
class RuleSuppressionDirective:
    file: str
    comment_line: int
    start_line: int
    end_line: int | float  # inclusive; float('inf') for EOF
    rules: set[str]  # e.g. {"plex.db-in-loop", "db-in-loop"} or {"*"}
    scope: str  # "line", "next-line", "block", "file"
    reason: str = ""
    ticket: str = ""
    comment: str = ""
    hit_count: int = 0

    def matches_rule(self, rule_id: str) -> bool:
        """Check if directive covers the given rule_id."""
        if "*" in self.rules:
            return True
        if rule_id in self.rules:
            return True
        base = rule_id.removeprefix("plex.")
        if base in self.rules or f"plex.{base}" in self.rules:
            return True
        return False

    def matches_line(self, lineno: int) -> bool:
        """Check if line is within the suppression line range."""
        return self.start_line <= lineno <= self.end_line


@dataclass
class FileRuleSuppressions:
    file_path: str
    directives: list[RuleSuppressionDirective] = field(default_factory=list)

    def is_suppressed(
        self, lineno: int, rule_id: str
    ) -> tuple[bool, RuleSuppressionDirective | None]:
        for d in self.directives:
            if d.matches_line(lineno) and d.matches_rule(rule_id):
                d.hit_count += 1
                return True, d
        return False, None

    def unused_suppressions(self) -> list[RuleSuppressionDirective]:
        return [d for d in self.directives if d.hit_count == 0]


def _find_next_code_line(lines: list[str], start_lineno: int) -> int:
    """Find the 1-indexed line number of the next non-empty, non-comment line."""
    for idx in range(start_lineno, len(lines)):
        stripped = lines[idx].strip()
        if stripped and not stripped.startswith("#"):
            return idx + 1
    return len(lines)


def _find_block_end(lines: list[str], start_lineno: int) -> int:
    """If line is a compound statement ending with ':', return the end line of its indented block."""
    if start_lineno < 1 or start_lineno > len(lines):
        return start_lineno

    target_line = lines[start_lineno - 1]
    stripped = target_line.split("#", 1)[0].rstrip()
    if not stripped.endswith(":"):
        return start_lineno

    base_indent = len(target_line) - len(target_line.lstrip())
    end_lineno = start_lineno
    for idx in range(start_lineno, len(lines)):
        line = lines[idx]
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        if indent > base_indent:
            end_lineno = idx + 1
        else:
            break
    return end_lineno


def parse_file_rule_suppressions(file_path: str, source: str) -> FileRuleSuppressions:
    """Parse all PLEx rule suppression directives from Python source code."""
    lines = source.splitlines()
    directives: list[RuleSuppressionDirective] = []

    # Open block suppressions: list of (start_line, comment_line, rules_set, reason, ticket, comment_str)
    open_blocks: list[tuple[int, int, set[str], str, str, str]] = []

    # Extract comment tokens using tokenize
    comment_tokens: list[tuple[str, int, int, bool]] = []
    try:
        tokens = tokenize.tokenize(io.BytesIO(source.encode("utf-8")).readline)
        for tok in tokens:
            if tok.type == tokenize.COMMENT:
                lineno = tok.start[0]
                col = tok.start[1]
                line_str = lines[lineno - 1] if 1 <= lineno <= len(lines) else ""
                is_standalone = line_str[:col].strip() == ""
                comment_tokens.append((tok.string, lineno, col, is_standalone))
    except Exception:
        # Fallback to line scanning if tokenize fails
        for idx, line in enumerate(lines, start=1):
            if "#" in line:
                col = line.index("#")
                comment_text = line[col:]
                is_standalone = line[:col].strip() == ""
                comment_tokens.append((comment_text, idx, col, is_standalone))

    for comment_text, lineno, _col, is_standalone in comment_tokens:
        reason, ticket = _parse_metadata(comment_text)

        # 1. File-level directive
        m_file = _FILE_DIRECTIVE_RE.search(comment_text)
        if m_file:
            rules_spec = m_file.group(1) if m_file.lastindex and m_file.group(1) else None
            rules = _parse_rules_spec(rules_spec)
            directives.append(
                RuleSuppressionDirective(
                    file=file_path,
                    comment_line=lineno,
                    start_line=1,
                    end_line=float("inf"),
                    rules=rules,
                    scope="file",
                    reason=reason,
                    ticket=ticket,
                    comment=comment_text.strip(),
                )
            )
            continue

        # 2. Block enable directive
        m_enable = _BLOCK_ENABLE_RE.search(comment_text)
        if m_enable and is_standalone:
            rules_spec = m_enable.group(1)
            enabled_rules = _parse_rules_spec(rules_spec)
            remained_blocks = []
            for (
                blk_start,
                blk_comment,
                blk_rules,
                blk_reason,
                blk_ticket,
                blk_comment_str,
            ) in open_blocks:
                if "*" in enabled_rules or (blk_rules & enabled_rules):
                    directives.append(
                        RuleSuppressionDirective(
                            file=file_path,
                            comment_line=blk_comment,
                            start_line=blk_start,
                            end_line=lineno,
                            rules=blk_rules,
                            scope="block",
                            reason=blk_reason,
                            ticket=blk_ticket,
                            comment=blk_comment_str,
                        )
                    )
                else:
                    remained_blocks.append(
                        (blk_start, blk_comment, blk_rules, blk_reason, blk_ticket, blk_comment_str)
                    )
            open_blocks = remained_blocks
            continue

        # 3. Explicit next-line directive
        m_next = _NEXT_LINE_DIRECTIVE_RE.search(comment_text)
        if m_next:
            rules_spec = m_next.group(1)
            rules = _parse_rules_spec(rules_spec)
            target_line = _find_next_code_line(lines, lineno)
            end_line = _find_block_end(lines, target_line)
            directives.append(
                RuleSuppressionDirective(
                    file=file_path,
                    comment_line=lineno,
                    start_line=target_line,
                    end_line=end_line,
                    rules=rules,
                    scope="next-line",
                    reason=reason,
                    ticket=ticket,
                    comment=comment_text.strip(),
                )
            )
            continue

        # 4. Block disable directive (only when standalone comment)
        m_disable = _BLOCK_DISABLE_RE.search(comment_text)
        if m_disable and is_standalone:
            rules_spec = m_disable.group(1)
            disabled_rules = _parse_rules_spec(rules_spec)
            open_blocks.append(
                (lineno, lineno, disabled_rules, reason, ticket, comment_text.strip())
            )
            continue

        # 5. General ignore directive
        m_ignore = _IGNORE_DIRECTIVE_RE.search(comment_text)
        if m_ignore:
            rules_spec = m_ignore.group(1)
            rules = _parse_rules_spec(rules_spec)
            if is_standalone:
                target_line = _find_next_code_line(lines, lineno)
                end_line = _find_block_end(lines, target_line)
                directives.append(
                    RuleSuppressionDirective(
                        file=file_path,
                        comment_line=lineno,
                        start_line=lineno,
                        end_line=end_line,
                        rules=rules,
                        scope="next-line",
                        reason=reason,
                        ticket=ticket,
                        comment=comment_text.strip(),
                    )
                )
            else:
                end_line = _find_block_end(lines, lineno)
                directives.append(
                    RuleSuppressionDirective(
                        file=file_path,
                        comment_line=lineno,
                        start_line=lineno,
                        end_line=end_line,
                        rules=rules,
                        scope="line",
                        reason=reason,
                        ticket=ticket,
                        comment=comment_text.strip(),
                    )
                )
            continue

        # 6. Inline disable directive on same line as code
        if m_disable and not is_standalone:
            rules_spec = m_disable.group(1)
            rules = _parse_rules_spec(rules_spec)
            end_line = _find_block_end(lines, lineno)
            directives.append(
                RuleSuppressionDirective(
                    file=file_path,
                    comment_line=lineno,
                    start_line=lineno,
                    end_line=end_line,
                    rules=rules,
                    scope="line",
                    reason=reason,
                    ticket=ticket,
                    comment=comment_text.strip(),
                )
            )
            continue

        # 7. Noqa plex directive
        m_noqa = _NOQA_DIRECTIVE_RE.search(comment_text)
        if m_noqa:
            raw_specs = m_noqa.group(1)
            rules = _parse_rules_spec(raw_specs)
            target_line = lineno if not is_standalone else _find_next_code_line(lines, lineno)
            end_line = _find_block_end(lines, target_line)
            directives.append(
                RuleSuppressionDirective(
                    file=file_path,
                    comment_line=lineno,
                    start_line=lineno if is_standalone else target_line,
                    end_line=end_line,
                    rules=rules,
                    scope="line" if not is_standalone else "next-line",
                    reason=reason,
                    ticket=ticket,
                    comment=comment_text.strip(),
                )
            )

    # Close any unclosed open blocks to EOF
    for blk_start, blk_comment, blk_rules, blk_reason, blk_ticket, blk_comment_str in open_blocks:
        directives.append(
            RuleSuppressionDirective(
                file=file_path,
                comment_line=blk_comment,
                start_line=blk_start,
                end_line=float("inf"),
                rules=blk_rules,
                scope="block",
                reason=blk_reason,
                ticket=blk_ticket,
                comment=blk_comment_str,
            )
        )

    return FileRuleSuppressions(file_path=file_path, directives=directives)


class RuleSuppressionContext:
    """Manages rule suppressions across multiple files."""

    def __init__(self, sources: dict[str, str] | None = None) -> None:
        self._file_suppressions: dict[str, FileRuleSuppressions] = {}
        if sources:
            for file_path, src in sources.items():
                self._file_suppressions[file_path] = parse_file_rule_suppressions(file_path, src)

    def is_suppressed(
        self, file_path: str, lineno: int, rule_id: str
    ) -> tuple[bool, RuleSuppressionDirective | None]:
        file_map = self._file_suppressions.get(file_path)
        if not file_map:
            return False, None
        return file_map.is_suppressed(lineno, rule_id)

    def add_source(self, file_path: str, source: str) -> None:
        self._file_suppressions[file_path] = parse_file_rule_suppressions(file_path, source)

    def get_all_directives(self) -> list[RuleSuppressionDirective]:
        all_d: list[RuleSuppressionDirective] = []
        for file_map in self._file_suppressions.values():
            all_d.extend(file_map.directives)
        return all_d

    def get_unused_suppressions(self) -> list[RuleSuppressionDirective]:
        unused: list[RuleSuppressionDirective] = []
        for file_map in self._file_suppressions.values():
            unused.extend(file_map.unused_suppressions())
        return unused

    def to_report_suppressions(self) -> list[Suppression]:
        """Convert used and active suppressions to report models."""
        out: list[Suppression] = []
        for d in self.get_all_directives():
            rule_spec = ",".join(sorted(d.rules)) if d.rules != {"*"} else "*"
            out.append(
                Suppression(
                    file=d.file,
                    qualname="",
                    function_id=f"rule:{rule_spec}",
                    lineno=int(d.start_line) if d.start_line != float("inf") else d.comment_line,
                    end_lineno=int(d.end_line) if d.end_line != float("inf") else d.comment_line,
                    comment_line=d.comment_line,
                    reason=d.reason,
                    ticket=d.ticket,
                    comment=d.comment,
                    rule_id=rule_spec,
                )
            )
        return out
