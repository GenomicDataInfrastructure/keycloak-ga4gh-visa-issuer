<!--
SPDX-FileCopyrightText: 2026 PNED G.I.E.

SPDX-License-Identifier: CC-BY-4.0
-->

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
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
