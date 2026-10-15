# Release checklist

Maintainers complete these checks for each source, package or deployment release.

- Run the project tests, lint checks and build instructions in README and CONTRIBUTING. Require successful checks on the exact revision being released.
- Review the complete distribution for credentials, personal data, customer exports, internal documents and generated files. Include only documented synthetic fixtures or data with verified redistribution rights.
- Verify LICENSE, THIRD_PARTY_NOTICES and dependency licenses. Preserve required copyright notices and attribution.
- Check installation from a clean environment, supported runtime versions, configuration defaults and upgrade instructions. Document remaining operational limitations accurately.
- Review dependency vulnerability reports; resolve exploitable findings before releasing affected components.
- Verify SECURITY, CODE_OF_CONDUCT and SUPPORT reporting channels. Private reports go to kokutbon@gmail.com.
- Confirm release notes, version identifiers, package names and artifact contents. Publish only through reviewed workflows with least-privilege credentials.
- Verify branch protection, required checks, private vulnerability reporting and secret-scanning push protection where the GitHub plan supports them.
- Check Sponsors links and the funding policy in SPONSORSHIP. Payments depend on GitHub approval and account eligibility.
- Keep real user records, operational registers and deployment secrets outside version control. Run backups, restore rehearsals and integration acceptance checks in the deployment owner's environment before operating with real data.

Repository visibility, package publishing and production deployment are separate maintainer decisions. A passing source build does not establish production suitability for every environment.

Dependency alerts remain enabled. Automated dependency and release pull requests are paused for the initial source distribution. Maintainers can raise `open-pull-requests-limit` in `.github/dependabot.yml` and enable automated security fixes when ready to receive bot contributions.
