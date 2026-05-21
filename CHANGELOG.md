<!--
SPDX-FileCopyrightText: 2026 PNED G.I.E.

SPDX-License-Identifier: CC-BY-4.0
-->

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
## [v1.0.3] - 2026-05-21

### Added
- feat: Enhance GA4GH visa issuance by implementing dynamic role and terms handling by @Kacem Bechka in c524cd9


### Changed
- chore(deps): update maven docker tag to v3.9.16 by @Renovate Bot in 5ada58c
- chore(deps): update dependency org.testcontainers:junit-jupiter to v1.19.8 by @Renovate Bot in b94c6fd
- chore(deps): update dependency org.projectlombok:lombok to v1.18.46 by @Renovate Bot in d8cce60
- chore(deps): update dependency org.junit.jupiter:junit-jupiter to v5.10.5 by @Renovate Bot in bfce891
- chore(deps): update dependency org.jboss.resteasy:resteasy-jackson2-provider to v6.2.16.final by @Renovate Bot in 5223298
- chore(deps): update dependency org.jboss.resteasy:resteasy-core to v6.2.16.final by @Renovate Bot in 9de56ae
- chore(deps): update dependency org.apache.maven.plugins:maven-surefire-plugin to v3.2.5 by @Renovate Bot in 80a85d8
- chore(deps): update dependency org.apache.maven.plugins:maven-failsafe-plugin to v3.2.5 by @Renovate Bot in 6837358
- chore(deps): update actions/checkout action to v6.0.2 by @Renovate Bot in b49859e
- update gdi-realm.json by @Kacem Bechka in bb6d5ad
- changing from attribute gdi to RESEARCHER by @Kacem Bechka in f5f0b2a
- Enhance GA4GH visa issuance logic and documentation by @Kacem Bechka in f6b19c8
- Update Trivy action to version 0.35.0 by @Bruno Pacheco in 76ac454
- Revert "Revert "Revert "chore: remove api jwk""" by @Bruno Pacheco in d4680e6
- chore: add jwk API by @Bruno Pacheco in ea91237
- Revert "Revert "chore: remove api jwk"" by @Bruno Pacheco in 5932976
- doc: update CHANGELOG.md for v1.0.2 by @LNDS-Sysadmins in 7c0ff70


### Fixed
- fix: get terms and conditions timestamp from terms_and_conditions by @Bruno Pacheco in 4c6c8bf


### Security
- Upgrade Trivy vulnerability scanner version by @Bruno Pacheco in ff2bcde


## [v1.0.2] - 2026-02-12

### Changed
- chore by @Bruno Pacheco in 70c2109
- Revert "chore: remove api jwk" by @Bruno Pacheco in a21b886
- chore: remove api jwk by @Bruno Pacheco in fe44fda
- chore: remove authorisation from api jwk by @Bruno Pacheco in dfe0705
- doc: update CHANGELOG.md for v1.0.1 by @LNDS-Sysadmins in 9a988e9


## [v1.0.1] - 2026-02-11

### Changed
- chore: add jku to jwt header by @Bruno Pacheco in 39b07f4
- doc: update CHANGELOG.md for v1.0.0 by @LNDS-Sysadmins in 97829f7


## [v1.0.0] - 2026-02-10

### Added
- feat: implement authorization in the custom endpoints by @Bruno Pacheco in 0d38faa
- feat: add 409 and 500 for corner cases, like multiple users with the same elixir_id, or unexpected exception when signing visas. by @Bruno Pacheco in 3c8630f
- feat: expose permissions API endpoint with mocked values by @Bruno Pacheco in cfc611f


### Changed
- chore: remove postgres from compose by @Bruno Pacheco in 544fea0
- chore: add license headers by @Bruno Pacheco in bb51e2f
- chore: add integration tests by @Bruno Pacheco in cc5e328


### Fixed
- doc: fix formatter issue by @Bruno Pacheco in b2a85b1
- chore: fix release workflow by @Bruno Pacheco in 3ca5f8c
- chore: fix problems highlighted by Sonar by @Bruno Pacheco in ab69a1f
- chore: fix nullpointer exception when header is missing by @Bruno Pacheco in 34f5eaa
- chore: fix sonar warning by @Bruno Pacheco in 438b8ca
- fix: add missing slash by @Bruno Pacheco in cb408c4
- fix: ignore files from sonar by @Bruno Pacheco in 58ddc0b
- fix: remove boilerplate code from sonar analysis by @Bruno Pacheco in ac051ea
- fix: generate jacoco report and remove formatter from docker build by @Bruno Pacheco in 4370a89
- fix: add license headers to not covered files. by @Bruno Pacheco in 6ce5a62



### Added

### Changed

### Deprecated

### Removed

### Fixed

### Security
