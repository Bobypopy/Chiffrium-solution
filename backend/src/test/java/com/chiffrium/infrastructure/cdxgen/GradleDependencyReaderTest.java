package com.chiffrium.infrastructure.cdxgen;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class GradleDependencyReaderTest {

    @Test
    void readsLiteralDeclarationsWithVariables(@TempDir Path root) throws IOException {
        Files.writeString(root.resolve("gradle.properties"), "bcVersion=1.78.1\n");
        Files.writeString(root.resolve("build.gradle"), """
                def tinkVersion = '1.13.0'
                ext { joseVersion = "9.37" }
                dependencies {
                    implementation "org.bouncycastle:bcprov-jdk18on:$bcVersion"
                    implementation("com.google.crypto.tink:tink:${tinkVersion}")
                    api 'com.nimbusds:nimbus-jose-jwt:' + joseVersion
                    implementation group: 'commons-codec', name: 'commons-codec', version: '1.16.0'
                    testImplementation 'junit:junit:4.13.2'
                    implementation project(':core')
                    implementation "org.inconnu:lib:$absente"
                }
                """);

        Map<String, DeclaredDependencies.Dependency> deps = GradleDependencyReader.read(root);

        assertThat(deps).containsKeys(
                "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78.1",
                "pkg:maven/com.google.crypto.tink/tink@1.13.0",
                "pkg:maven/commons-codec/commons-codec@1.16.0",
                "pkg:maven/org.inconnu/lib");
        assertThat(deps.get("pkg:maven/junit/junit@4.13.2").optional()).isTrue();
        assertThat(deps.get("pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78.1").optional()).isFalse();
        assertThat(deps.keySet()).noneMatch(k -> k.contains("core"));
    }

    @Test
    void readsOnlyTheCatalogEntriesUsedByTheScripts(@TempDir Path root) throws IOException {
        Files.createDirectories(root.resolve("gradle"));
        Files.writeString(root.resolve("gradle/libs.versions.toml"), """
                [versions]
                bc = "1.78.1"
                jwt = { strictly = "0.12.5" }

                [libraries]
                bc-prov = { module = "org.bouncycastle:bcprov-jdk18on", version.ref = "bc" }
                bc_pkix = { group = "org.bouncycastle", name = "bcpkix-jdk18on", version.ref = "bc" }
                jjwt = { module = "io.jsonwebtoken:jjwt-api", version = { ref = "jwt" } }
                junit = "junit:junit:4.13.2"
                unused = "com.example:jamais-utilise:1.0"

                [bundles]
                bouncy = ["bc-prov", "bc_pkix"]
                """);
        Files.writeString(root.resolve("build.gradle.kts"), """
                dependencies {
                    implementation(libs.bundles.bouncy)
                    implementation(libs.jjwt)
                    testImplementation(libs.junit)
                }
                """);

        Map<String, DeclaredDependencies.Dependency> deps = GradleDependencyReader.read(root);

        assertThat(deps).containsOnlyKeys(
                "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78.1",
                "pkg:maven/org.bouncycastle/bcpkix-jdk18on@1.78.1",
                "pkg:maven/io.jsonwebtoken/jjwt-api@0.12.5",
                "pkg:maven/junit/junit@4.13.2");
        assertThat(deps.get("pkg:maven/junit/junit@4.13.2").optional()).isTrue();
    }

    @Test
    void readsLockfilesWithTransitiveDependencies(@TempDir Path root) throws IOException {
        Files.writeString(root.resolve("gradle.lockfile"), """
                # This is a Gradle generated file for dependency locking.
                org.bouncycastle:bcprov-jdk18on:1.78.1=compileClasspath,runtimeClasspath
                org.bouncycastle:bcutil-jdk18on:1.78.1=runtimeClasspath
                org.hamcrest:hamcrest-core:1.3=testCompileClasspath,testRuntimeClasspath
                empty=annotationProcessor
                """);
        Files.createDirectories(root.resolve("build/tmp"));
        Files.writeString(root.resolve("build/tmp/gradle.lockfile"), "com.exemple:sortie:1=runtimeClasspath\n");

        Map<String, DeclaredDependencies.Dependency> deps = GradleDependencyReader.read(root);

        assertThat(deps).containsOnlyKeys(
                "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78.1",
                "pkg:maven/org.bouncycastle/bcutil-jdk18on@1.78.1",
                "pkg:maven/org.hamcrest/hamcrest-core@1.3");
        assertThat(deps.get("pkg:maven/org.hamcrest/hamcrest-core@1.3").optional()).isTrue();
    }
}
