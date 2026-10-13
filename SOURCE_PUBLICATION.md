# Source publication status

This is the initial open-source source distribution maintained by KOKUTBON.
The source license is in LICENSE; third-party components retain their own terms.
See README.md for installation, supported components and validation commands.

Source publication, demo hosting, package distribution and production deployment
are separate steps. A static synthetic demo does not validate a backend or a real
integration. No production certification or supported production release is
implied by this source distribution.

## Before changing visibility

- Run the documented build, test and security checks on the candidate commit.
- Review distribution contents and dependencies for privacy and redistribution rights.
- Confirm the private reporting contact in SECURITY.md and CODE_OF_CONDUCT.md.
- Review the local validation record in PUBLICATION_VALIDATION.md; unresolved checks
  remain explicit and must not be described as passing.

## At publication

- Enable private vulnerability reporting, secret scanning and push protection where supported.
- Protect the default branch with the actual successful check names and review policy.
- Follow the repository publication procedure and review checklist before applying.
- Publish demos only through reviewed manual workflows; verify the URL before calling it live.
- Prepare release notes and tags separately if distributing packages or binaries.

Prepared GitHub Pages URLs are planned until a successful deployment is verified.
Never upload production credentials, customer records, private datasets or signing material.

Container publication requires a manual Docker workflow dispatch with `publish=true`. PyPI publication remains separately gated by PUBLISH_PYPI.
