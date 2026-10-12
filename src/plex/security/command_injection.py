"""Experimental Command-injection rule."""

from .injection import DataflowInjectionRule

COMMAND_LIMITATIONS = [
    "Command analysis models shell interpretation and vector argument construction",
    "Dynamic subprocess keywords and non-literal shell flags yield incomplete coverage",
]

__all__ = ["COMMAND_LIMITATIONS", "CommandInjectionRule"]


class CommandInjectionRule(DataflowInjectionRule):
    id = "xbnd.command-injection"
    name = "Untrusted input in command execution"
    description = "Untrusted input reaches shell or OS command execution without safe argument vector passing."
    message = "Untrusted input reaches command execution. Pass arguments as a vector without shell interpolation, or use shlex.quote()."
    remediation = "Pass arguments as a sequence without shell=True, or sanitize with shlex.quote()."
    kind = "command"
    cwe = "CWE-78"
    tags = ["security", "injection", "CWE-78", "A05:2025"]
