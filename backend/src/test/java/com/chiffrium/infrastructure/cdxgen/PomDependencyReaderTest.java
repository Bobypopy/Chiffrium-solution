package com.chiffrium.infrastructure.cdxgen;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class PomDependencyReaderTest {

    private static final String PARENT = """
            <project xmlns="http://maven.apache.org/POM/4.0.0">
              <groupId>com.exemple</groupId><artifactId>parent</artifactId><version>2.0</version>
              <properties><bc.version>1.78</bc.version></properties>
              <dependencyManagement><dependencies>
                <dependency><groupId>com.google.crypto.tink</groupId><artifactId>tink</artifactId><version>1.13.0</version></dependency>
              </dependencies></dependencyManagement>
            </project>
            """;

    private static final String MODULE = """
            <project>
              <parent><groupId>com.exemple</groupId><artifactId>parent</artifactId><version>2.0</version></parent>
              <artifactId>module</artifactId>
              <dependencies>
                <dependency><groupId>org.bouncycastle</groupId><artifactId>bcprov-jdk18on</artifactId><version>${bc.version}</version></dependency>
                <dependency><groupId>com.google.crypto.tink</groupId><artifactId>tink</artifactId></dependency>
                <dependency><groupId>${project.groupId}</groupId><artifactId>commun</artifactId><version>${project.version}</version></dependency>
                <dependency><groupId>org.junit.jupiter</groupId><artifactId>junit-jupiter</artifactId><version>5.10.0</version><scope>test</scope></dependency>
                <dependency><groupId>org.inconnu</groupId><artifactId>lib</artifactId><version>${absente}</version></dependency>
              </dependencies>
            </project>
            """;

    @Test
    void readsDirectDependenciesWithPropertiesAndManagedVersions(@TempDir Path root) throws IOException {
        Files.writeString(root.resolve("pom.xml"), PARENT);
        Files.createDirectories(root.resolve("module"));
        Files.writeString(root.resolve("module/pom.xml"), MODULE);

        Map<String, DeclaredDependencies.Dependency> deps = PomDependencyReader.read(root);

        assertThat(deps).containsKeys(
                "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78",
                "pkg:maven/com.google.crypto.tink/tink@1.13.0",
                "pkg:maven/com.exemple/commun@2.0",
                "pkg:maven/org.inconnu/lib");
        assertThat(deps.get("pkg:maven/org.junit.jupiter/junit-jupiter@5.10.0").optional()).isTrue();
        assertThat(deps.get("pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78").optional()).isFalse();
    }

    @Test
    void writesCycloneDxReadableByTheLibraryReader(@TempDir Path root) throws IOException {
        Files.writeString(root.resolve("pom.xml"), MODULE.replace("${bc.version}", "1.78"));
        Path bom = DeclaredDependencies.writeBom(DeclaredDependencies.read(root), root.resolve("bom.json")).orElseThrow();

        var components = new ObjectMapper().readTree(bom.toFile()).path("components");
        assertThat(components).isNotEmpty();
        assertThat(components.get(0).path("type").asText()).isEqualTo("library");
        assertThat(CycloneDxLibraryReader.isCryptoLibrary(components.get(0).path("purl").asText())).isTrue();
    }

    @Test
    void refusesExternalEntitiesAndSkipsBuildOutputs(@TempDir Path root) throws IOException {
        Path secret = root.resolve("secret.txt");
        Files.writeString(secret, "motdepasse");
        Files.writeString(root.resolve("pom.xml"), """
                <?xml version="1.0"?>
                <!DOCTYPE project [<!ENTITY xxe SYSTEM "%s">]>
                <project><dependencies>
                  <dependency><groupId>&xxe;</groupId><artifactId>a</artifactId><version>1</version></dependency>
                </dependencies></project>
                """.formatted(secret.toUri()));
        Files.createDirectories(root.resolve("target/classes"));
        Files.writeString(root.resolve("target/classes/pom.xml"), MODULE);

        assertThat(PomDependencyReader.read(root)).isEmpty();
        assertThat(DeclaredDependencies.writeBom(DeclaredDependencies.read(root), root.resolve("bom.json"))).isEmpty();
    }
}
