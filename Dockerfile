# SPDX-FileCopyrightText: 2026 PNED G.I.E.
#
# SPDX-License-Identifier: Apache-2.0
# Build stage
FROM maven:3.10.0-eclipse-temurin-17 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests -Dformatter.skip

# brotli4j 1.23.0 bundles Brotli 1.2.0 (CVE-2026-111497). No Keycloak release ships 1.24.0 yet, and
# deleting the jars breaks every later re-augmentation (start-dev, kc.sh build with other options),
# so put 1.24.0 under the file names recorded in lib/quarkus/quarkus-application.dat.
# Remove this stage and the three COPY lines below once Keycloak ships brotli4j >= 1.24.0.
FROM registry.access.redhat.com/ubi9-minimal:1792742129 AS brotli4j
RUN cd /tmp && B=https://repo1.maven.org/maven2/com/aayushatharva/brotli4j \
 && curl -fsSLO $B/brotli4j/1.24.0/brotli4j-1.24.0.jar \
 && curl -fsSLO $B/service/1.24.0/service-1.24.0.jar \
 && curl -fsSLO $B/native-linux-x86_64/1.24.0/native-linux-x86_64-1.24.0.jar \
 && printf '%s\n' \
  'cd0ac4425d2c8449723c93d66ec4379faf1093eb6609ede83e49947f90a772e8  brotli4j-1.24.0.jar' \
  '2fee8a977d617c4904f3260eca8a294927ec5364026478f82014484e96e8bfa5  service-1.24.0.jar' \
  '49e5c5bcefb2d4247d3a2859d15ae90086b4c4089e08f2a560b8ac011e61ab06  native-linux-x86_64-1.24.0.jar' | sha256sum -c -

# Runtime stage
FROM quay.io/keycloak/keycloak:26.8.1
# Fail the build if the base image trusts a root distrusted by RHSB-2026-012 (CVE-2026-91403)
# (keytool output goes to a file first: /bin/sh has no pipefail, so a failing keytool would pass a pipe)
RUN keytool -list -v -cacerts -storepass changeit > /tmp/cacerts.txt \
 && [ "$(grep -c '^Alias name: ' /tmp/cacerts.txt)" -ge 100 ] \
 && ! grep -qE "^Owner: CN=(emSign ECC Root CA - G3|AAA Certificate Services)," /tmp/cacerts.txt \
 && rm /tmp/cacerts.txt
COPY --from=build /app/target/keycloak-ga4gh-visa-issuer-*.jar /opt/keycloak/providers/
# brotli4j 1.24.0 under the 1.23.0 file names (see the brotli4j stage)
COPY --from=brotli4j --chown=1000:0 /tmp/brotli4j-1.24.0.jar            /opt/keycloak/lib/lib/main/com.aayushatharva.brotli4j.brotli4j-1.23.0.jar
COPY --from=brotli4j --chown=1000:0 /tmp/service-1.24.0.jar             /opt/keycloak/lib/lib/main/com.aayushatharva.brotli4j.service-1.23.0.jar
COPY --from=brotli4j --chown=1000:0 /tmp/native-linux-x86_64-1.24.0.jar /opt/keycloak/lib/lib/main/com.aayushatharva.brotli4j.native-linux-x86_64-1.23.0.jar
RUN /opt/keycloak/bin/kc.sh build

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized"]
