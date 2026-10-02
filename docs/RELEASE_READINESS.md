# Release readiness — recon-helper

Review date: 2 October 2026. Proposed work, not an implementation or release announcement.

## Appropriate next functionality

- Add target-file ingestion and named port presets with clear host/port bounds.
- Validate protocols rather than relying on port-number service hints; add bounded TLS/certificate inspection.
- Add rate controls separate from concurrency, partial findings after interruption and direct structured exports.
- Develop UDP as a separate engine with distinct result semantics, rather than treating it as TCP.

## Before a first public release

- Build/install the existing package in a clean environment, test CLI entry points and declare supported Python/OS combinations.
- Document network requests, redirects, timeouts, scope limits, output schema and exit codes. Keep HTTP enrichment opt-in.
- Expand mocked tests for interruptions, malformed targets and future protocol probes; CI must not scan arbitrary external targets.
- Provide versioned source/package releases and example outputs based on documentation addresses. Investigate PyPI distribution only after clean packaging and dependency checks.

## Shared release preparation

Before publishing a tagged release, choose a project licence after reviewing tutorial and asset provenance; document installation, supported versions, examples and known limits; add a changelog, issue/PR templates, contribution guidance and a vulnerability-reporting policy; run CI on the claimed platforms and test a clean installation. Add dependency updates and appropriate repository security checks where supported. Provide tagged release notes and usable download assets where relevant. These are readiness recommendations, not GitHub certification or features already delivered.

GitHub references: [community health files](https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/creating-a-default-community-health-file) and [releases](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases).
