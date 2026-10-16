# Changelog

- Repair supported unsafe PyYAML loaders without changing loader argument positions or rewriting incompatible serialization formats; abstain on custom schemas and ambiguous bindings. (#65)

- Declare experimental coverage and document repair limitations. (#63)

- Validate redirect targets once and reject browser URL bypasses. (#61)

- Escape untrusted HTML values in supported rendering contexts. (#59)

- Separate Flask template input from template code. (#57)

- Reject nested MongoDB operators without changing legitimate query types. (#55)

- Resolve eval safely and retain manual review for literal evaluation. (#53)

- Confine filesystem repairs to a known base directory. (#51)

- Preserve command arguments and block shell and option injection. (#49)

- Require behavioral evidence before applying repair candidates. (#47)

## Initial release

Project source, documentation, and development tools.
