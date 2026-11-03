package com.chiffrium.infrastructure.cdxgen;

import com.chiffrium.infrastructure.cdxgen.DeclaredDependencies.Dependency;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** Dépendances .NET, Go et transitives Maven lues sans lancer d'outil de build. */
class NugetGoAndTransitiveReaderTest {

    @Test
    void readsNugetFromLockFileProjectAndCentralVersions(@TempDir Path root) throws IOException {
        Files.writeString(root.resolve("packages.lock.json"), """
                {
                  "version": 1,
                  "dependencies": {
                    "net8.0": {
                      "BouncyCastle.Cryptography": { "type": "Direct", "requested": "[2.3.0, )", "resolved": "2.3.0" },
                      "System.Security.Cryptography.Pkcs": { "type": "Transitive", "resolved": "8.0.0" },
                      "Commun": { "type": "Project" }
                    }
                  }
                }
                """);
        Files.writeString(root.resolve("Directory.Packages.props"), """
                <Project>
                  <ItemGroup><PackageVersion Include="Portable.BouncyCastle" Version="1.9.0" /></ItemGroup>
                </Project>
                """);
        Files.writeString(root.resolve("App.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Portable.BouncyCastle" />
                    <PackageReference Include="Newtonsoft.Json" Version="$(JsonVersion)" />
                    <PackageReference Include="xunit" Version="2.6.0" />
                  </ItemGroup>
                </Project>
                """);

        Map<String, Dependency> deps = NugetDependencyReader.read(root);

        assertThat(deps).containsKeys(
                "pkg:nuget/BouncyCastle.Cryptography@2.3.0",
                "pkg:nuget/System.Security.Cryptography.Pkcs@8.0.0",
                "pkg:nuget/Portable.BouncyCastle@1.9.0");
        // Projet de la solution : ce n'est pas un paquet publié.
        assertThat(deps.keySet()).noneMatch(purl -> purl.startsWith("pkg:nuget/Commun"));
        // Version portée par une propriété MSBuild : le paquet est listé, sans version inventée.
        assertThat(deps).containsKey("pkg:nuget/Newtonsoft.Json");
        assertThat(deps.get("pkg:nuget/xunit@2.6.0").optional()).isTrue();
        assertThat(deps.get("pkg:nuget/BouncyCastle.Cryptography@2.3.0").optional()).isFalse();
    }

    @Test
    void readsGoModulesAndMarksSumOnlyEntriesAsOptional(@TempDir Path root) throws IOException {
        Files.writeString(root.resolve("go.mod"), """
                module exemple.com/app

                go 1.22

                require (
                	golang.org/x/crypto v0.21.0
                	github.com/exemple/journal v1.4.0 // indirect
                )

                require gopkg.in/yaml.v3 v3.0.1

                replace exemple.com/interne => ../interne
                """);
        Files.writeString(root.resolve("go.sum"), """
                golang.org/x/crypto v0.21.0 h1:AAAA=
                golang.org/x/crypto v0.21.0/go.mod h1:BBBB=
                golang.org/x/sys v0.18.0/go.mod h1:CCCC=
                """);

        Map<String, Dependency> deps = GoDependencyReader.read(root);

        assertThat(deps).containsKeys(
                "pkg:golang/golang.org/x/crypto@v0.21.0",
                "pkg:golang/github.com/exemple/journal@v1.4.0",
                "pkg:golang/gopkg.in/yaml.v3@v3.0.1");
        // "replace" désigne un chemin local, pas une dépendance publiée.
        assertThat(deps.keySet()).noneMatch(purl -> purl.contains("interne"));
        // Vu pendant la résolution mais pas retenu : présent, mais pas donné comme embarqué.
        assertThat(deps.get("pkg:golang/golang.org/x/sys@v0.18.0").optional()).isTrue();
        assertThat(deps.get("pkg:golang/golang.org/x/crypto@v0.21.0").optional()).isFalse();
    }

    @Test
    @Timeout(5)
    void aCraftedGoModCannotStallTheAnalysis(@TempDir Path root) throws IOException {
        // Motif qui faisait exploser l'ancienne expression (groupes répétés qui se recouvraient).
        Files.writeString(root.resolve("go.mod"), "require " + "-.".repeat(5_000) + "!\n"
                + "require golang.org/x/crypto v0.21.0\n");

        assertThat(GoDependencyReader.read(root)).containsOnlyKeys("pkg:golang/golang.org/x/crypto@v0.21.0");
    }

    @Test
    void completesMavenTreeFromTheLocalCache(@TempDir Path root) throws IOException {
        Path repository = root.resolve("repository");
        // Le pom de la dépendance directe : il hérite la version de sa propre dépendance d'un BOM importé.
        cachedPom(repository, "org.exemple", "client", "1.0", """
                <project>
                  <groupId>org.exemple</groupId><artifactId>client</artifactId><version>1.0</version>
                  <dependencyManagement><dependencies>
                    <dependency><groupId>org.exemple</groupId><artifactId>socle-bom</artifactId>
                      <version>3.0</version><type>pom</type><scope>import</scope></dependency>
                  </dependencies></dependencyManagement>
                  <dependencies>
                    <dependency><groupId>org.bouncycastle</groupId><artifactId>bcprov-jdk18on</artifactId></dependency>
                    <dependency><groupId>org.junit.jupiter</groupId><artifactId>junit-jupiter</artifactId>
                      <version>5.10.0</version><scope>test</scope></dependency>
                  </dependencies>
                </project>
                """);
        cachedPom(repository, "org.exemple", "socle-bom", "3.0", """
                <project>
                  <groupId>org.exemple</groupId><artifactId>socle-bom</artifactId><version>3.0</version>
                  <properties><bc.version>1.78</bc.version></properties>
                  <dependencyManagement><dependencies>
                    <dependency><groupId>org.bouncycastle</groupId><artifactId>bcprov-jdk18on</artifactId>
                      <version>${bc.version}</version></dependency>
                  </dependencies></dependencyManagement>
                </project>
                """);
        // Deuxième niveau : la transitive a elle-même une dépendance.
        cachedPom(repository, "org.bouncycastle", "bcprov-jdk18on", "1.78", """
                <project>
                  <groupId>org.bouncycastle</groupId><artifactId>bcprov-jdk18on</artifactId><version>1.78</version>
                  <dependencies>
                    <dependency><groupId>org.exemple</groupId><artifactId>util</artifactId><version>0.9</version></dependency>
                  </dependencies>
                </project>
                """);
        Map<String, Dependency> direct = Map.of(
                "pkg:maven/org.exemple/client@1.0", new Dependency("org.exemple", "client", "1.0", false),
                "pkg:maven/org.exemple/test-only@1.0", new Dependency("org.exemple", "test-only", "1.0", true));

        Map<String, Dependency> transitive = PomDependencyReader.transitive(direct, repository);

        assertThat(transitive).containsOnlyKeys(
                "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78",
                "pkg:maven/org.exemple/util@0.9");
        // Une portée test ne se propage pas : elle n'apparaît pas dans l'arbre transitif.
        assertThat(transitive.keySet()).noneMatch(purl -> purl.contains("junit"));
    }

    @Test
    void ignoresAMissingLocalCache(@TempDir Path root) {
        Map<String, Dependency> direct = Map.of("pkg:maven/org.exemple/client@1.0",
                new Dependency("org.exemple", "client", "1.0", false));

        assertThat(PomDependencyReader.transitive(direct, root.resolve("absent"))).isEmpty();
    }

    private static void cachedPom(Path repository, String group, String artifact, String version, String content)
            throws IOException {
        Path directory = repository.resolve(group.replace('.', '/')).resolve(artifact).resolve(version);
        Files.createDirectories(directory);
        Files.writeString(directory.resolve(artifact + "-" + version + ".pom"), content);
    }
}
