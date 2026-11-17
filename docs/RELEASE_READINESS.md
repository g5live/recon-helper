# Release readiness — recon-helper

Updated: 17 November 2026. Release preparation remains pending.

## Checks completed for the current local build

- Built the 0.2.0 wheel and installed it with its dependencies into a fresh virtual environment on Linux with Python 3.15.2.
- Ran the installed `recon-helper --help` from outside the source tree and confirmed the UDP and SMTP STARTTLS options.
- Added [contribution notes](../CONTRIBUTING.md) and an [Unreleased changelog](../CHANGELOG.md).

This check covers one platform and Python version. See the [roadmap](ROADMAP.md) for feature work.

## Before a first public release

- Run CI on Linux for the minimum declared Python version (3.11) and a newer supported version. Include mocked tests and a wheel installation and CLI smoke check.
- Document network requests, redirects, timeouts, scope limits, output schema and exit codes. Keep HTTP enrichment opt-in.
- Expand mocked tests for interruptions, malformed targets and future protocol probes; CI must not scan arbitrary external targets.
- Provide versioned source/package releases and example outputs based on documentation addresses. Investigate PyPI distribution only after clean packaging and dependency checks.

## Shared release preparation

Before publishing a tagged release, choose a project licence after reviewing tutorial and asset provenance; document installation, supported versions, examples and known limits; review the changelog and contribution notes, and add issue/PR templates and a vulnerability-reporting policy; run CI on the claimed platforms and test a clean installation. Add dependency updates and appropriate repository security checks where supported. Provide tagged release notes and usable download assets where relevant. These are readiness recommendations, not GitHub certification or features already delivered.

GitHub references: [community health files](https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/creating-a-default-community-health-file) and [releases](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases).
