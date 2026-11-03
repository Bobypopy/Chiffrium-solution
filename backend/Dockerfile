# syntax=docker/dockerfile:1.7
# Version de cdxgen épinglée (déclarée avant le premier FROM pour être utilisable dans les FROM).
ARG CDXGEN_VERSION=v11.7.0

# ---------------------------------------------------------------------------------------------
# Étape 1 : compilation et tests du backend.
# ---------------------------------------------------------------------------------------------
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /build
COPY pom.xml .
RUN mvn -B -q dependency:go-offline
COPY src ./src
# Le CI passe SKIP_TESTS=true : les tests viennent d'être exécutés par le job Backend.
ARG SKIP_TESTS=false
RUN mvn -B -q package -DskipTests=${SKIP_TESTS}

# ---------------------------------------------------------------------------------------------
# Étape 2 : exécution. Base = image officielle cdxgen, dont la version est ÉPINGLÉE : elle fournit
# cdxgen, atom et les outils de résolution de dépendances (Maven, Gradle, Python, Node, Go, .NET...).
# Changer de version de cdxgen = changer CDXGEN_VERSION et relancer les tests (voir docs/architecture.md).
# ---------------------------------------------------------------------------------------------
FROM ghcr.io/cyclonedx/cdxgen:${CDXGEN_VERSION}

LABEL org.opencontainers.image.title="chiffrium-backend" \
      org.opencontainers.image.description="API d'inventaire cryptographique (CBOM) multi-langages"

USER root
RUN mkdir -p /opt/chiffrium /data && chown -R cyclonedx /data
COPY --from=build /build/target/chiffrium-backend.jar /opt/chiffrium/chiffrium-backend.jar

# Utilisateur non privilégié fourni par l'image cdxgen.
USER cyclonedx
WORKDIR /data

ENV PORT=8080 \
    DATA_DIR=/data \
    CDXGEN_COMMAND=cdxgen \
    JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=50 -Dfile.encoding=UTF-8"

EXPOSE 8080
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl -fsS http://localhost:8080/api/health || exit 1

ENTRYPOINT ["java", "-jar", "/opt/chiffrium/chiffrium-backend.jar"]
