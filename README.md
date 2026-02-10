<!--
SPDX-FileCopyrightText: 2026 PNED G.I.E.

SPDX-License-Identifier: CC-BY-4.0
-->

[![REUSE status](https://api.reuse.software/badge/github.com/GenomicDataInfrastructure/keycloak-ga4gh-visa-issuer)](https://api.reuse.software/info/github.com/GenomicDataInfrastructure/keycloak-ga4gh-visa-issuer)
![example workflow](https://github.com/GenomicDataInfrastructure/keycloak-ga4gh-visa-issuer/actions/workflows/main.yml/badge.svg)
![example workflow](https://github.com/GenomicDataInfrastructure/keycloak-ga4gh-visa-issuer/actions/workflows/test.yml/badge.svg)
![example workflow](https://github.com/GenomicDataInfrastructure/keycloak-ga4gh-visa-issuer/actions/workflows/release.yml/badge.svg)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=GenomicDataInfrastructure_keycloak-ga4gh-visa-issuer&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=GenomicDataInfrastructure_keycloak-ga4gh-visa-issuer)
[![GitHub contributors](https://img.shields.io/github/contributors/GenomicDataInfrastructure/keycloak-ga4gh-visa-issuer)](https://github.com/GenomicDataInfrastructure/keycloak-ga4gh-visa-issuer/graphs/contributors)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](code_of_conduct.md)

# keycloak-ga4gh-visa-issuer

This is a Keycloak Ga4GH Visa Issuer. It suggests an initial setup for a successful open-source project.

## Software Development Guidelines

- We use Maven to build the Java project and Docker to package it.
- GitHub offers free storage for open source projects.
- Testing is fundamental for stable and secure code.
- Follow free and Open Source Software principles:
    - Keep `CHANGELOG.md`, `README.md`, and `CONTRIBUTING.md` up to date.
    - Add license and copyrights to headers for each file - we suggest following [REUSE](https://reuse.software/).
    - Keep an issue tracker open for everyone.
    - Review regularly dependencies licenses and comply with all license requirements.
    - For more suggestions, please check [OpenSSF Best Practices](https://www.bestpractices.dev/en).
- Automated and recurrent CI/CD - GitHub offers a few thousand minutes per month.
- Quality checks are mandatory - SonarCloud is free for open-source projects.
- Vulnerability checks are mandatory - SonarCloud for code, ORT for dependencies, Trivy for packages and libraries inside docker images.

## CI/CD

There are three workflows available, `test.yml`, `main.yml`, and `release.yml`. 

In `test.yml` should go all kinds of tests, like: unit/integration tests, linters, prettiers, sonar, etc. This workflow should be fast and happen on every push.

In `main.yml` should go all kinds of checks that are still needed to enforce code quality, or license and security compliance checks. This workflow can be heavy, so it is advisable to happen only when the PR is open or when changes are merged to main. 

Similarly to the previous workflow, `release.yml` also should enforce code quality, license compliance, or security checks, that can be potentially heavy.

In this template, you will find jobs for [ORT](https://oss-review-toolkit.org/ort/), [REUSE](https://reuse.software/), [Trivy](https://trivy.dev/), and [GitHub Packages](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-docker-registry).

## Installation

### Configuration

The Visa Issuer uses the `elixir_id` user attribute to look up users and issue visas. Ensure your Keycloak users have this attribute set.

### API Endpoints

- **Get JWK**: `GET /realms/{realm}/ga4gh-visa-issuer/api/jwk`
  - Returns the JSON Web Keys used for signing the visas.
- **Get Permissions**: `GET /realms/{realm}/ga4gh-visa-issuer/api/permissions/{user_elixir_id}`
  - Returns the GA4GH Passport with visas for the user identified by their `elixir_id`.
  - Returns `404 Not Found` if the user does not exist.
  - Returns `409 Conflict` if multiple users are found with the same `elixir_id`.
  - Returns `500 Internal Server Error` if there is a server-side error (e.g. visa signing failure).

### Development (Docker Compose)

The development setup includes pre-configured users and realms. Ensure you have Docker and Docker Compose installed with enough resources (at least 4GB of RAM).

For MacOS ARM64, you can use [colima](https://github.com/abiosoft/colima) to manage your Docker environment. You can start it with:

```bash
colima start --arch aarch64 --vm-type=vz --mount-type=virtiofs --vz-rosetta --cpu 4 --memory 10
```

```bash
docker compose up --build
```

- Keycloak: `http://localhost:8080`
- Admin credentials: `admin` / `admin`
- Realm: `gdi` (automatically imported)

If you ever need to delete the Keycloak data, you can use the following command:

```bash
docker compose down -v
```

If you ever need to make changes to the realm or users, the safest way is changing directly in the Keycloak admin console and export the realm via CLI. Then, commit the changes to the repository.

```bash
docker compose exec keycloak /opt/keycloak/bin/kc.sh export --realm gdi --dir /opt/keycloak/data/import --users realm_file --optimized
```

If you ever need to format the files, you can use the following command:

```bash
mvn formatter:format
```

### Production Build

To build the production-ready Docker image:

```bash
docker build -t keycloak-ga4gh-visa-issuer .
```

The production image is optimized and does not include development tools or credentials. You must provide your own configuration (DB, admin user, etc.) at runtime.

## Licenses

This work is licensed under multiple licences:
- All original source code is licensed under [Apache-2.0](./LICENSES/Apache-2.0.txt).
- All documentation and images are licensed under [CC-BY-4.0](./LICENSES/CC-BY-4.0.txt).
- For more accurate information, check the individual files.
