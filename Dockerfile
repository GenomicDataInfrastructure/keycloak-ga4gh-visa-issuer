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
# (keytool output goes to a file first: /bin/sh has no pipefail, so a failing keytool would pass a pipe)
RUN keytool -list -v -cacerts -storepass changeit > /tmp/cacerts.txt \
 && [ "$(grep -c '^Alias name: ' /tmp/cacerts.txt)" -ge 100 ] \
 && ! grep -qE "^Owner: CN=(emSign ECC Root CA - G3|AAA Certificate Services)," /tmp/cacerts.txt \
 && rm /tmp/cacerts.txt
COPY --from=build /app/target/keycloak-ga4gh-visa-issuer-*.jar /opt/keycloak/providers/
# brotli4j 1.23.0 bundles Brotli 1.2.0 (CVE-2026-111497): drop it from the build and the image
RUN echo "quarkus.class-loading.removed-artifacts=com.aayushatharva.brotli4j:brotli4j,com.aayushatharva.brotli4j:native-linux-x86_64,com.aayushatharva.brotli4j:service" >> /opt/keycloak/conf/quarkus.properties
RUN /opt/keycloak/bin/kc.sh build \
 && rm -f /opt/keycloak/lib/lib/main/com.aayushatharva.brotli4j.*

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized"]
