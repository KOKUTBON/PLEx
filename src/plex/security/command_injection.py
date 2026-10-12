"""Experimental command-injection rule."""

from .injection import DataflowInjectionRule

COMMAND_LIMITATIONS = (
    "Command rule models shell interpretation, not general argument or executable injection",
    "No universal shell quoting sanitizer; SQL policy sinks/sanitizers apply only to SQL",
    "Windows implicit batch-file shells and indirect shell argv construction are outside the model",
)

__all__ = ["COMMAND_LIMITATIONS", "CommandInjectionRule"]


class CommandInjectionRule(DataflowInjectionRule):
    id = "xbnd.command-injection"
    name = "Untrusted input in shell command"
    description = "Untrusted input reaches a command interpreted by a shell."
    kind = "command"
    limitations = COMMAND_LIMITATIONS
    cwe = "CWE-78"
    tags = ["security", "injection", "CWE-78", "A05:2025"]
    message = "Untrusted input reaches shell command text. Use a fixed executable and separate argument values with shell=False."
    remediation = "Avoid shell interpretation; pass a fixed executable and an argument list. Validate arguments for the called program."
