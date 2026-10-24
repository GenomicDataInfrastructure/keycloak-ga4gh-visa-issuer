# SPDX-FileCopyrightText: 2026 PNED G.I.E.
#
# SPDX-License-Identifier: Apache-2.0
# Build stage
FROM maven:3.10.0-eclipse-temurin-17 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests -Dformatter.skip

# Runtime stage
FROM quay.io/keycloak/keycloak:26.8.1
# Fail the build if the base image trusts a root distrusted by RHSB-2026-012 (CVE-2026-91403)
RUN ! keytool -list -v -cacerts -storepass changeit | grep -qE "^Owner: CN=(emSign ECC Root CA - G3|AAA Certificate Services),"
COPY --from=build /app/target/keycloak-ga4gh-visa-issuer-*.jar /opt/keycloak/providers/
RUN /opt/keycloak/bin/kc.sh build

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized"]
