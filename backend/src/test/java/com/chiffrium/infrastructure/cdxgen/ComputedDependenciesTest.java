package com.chiffrium.infrastructure.cdxgen;

import com.chiffrium.TestSupport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

class ComputedDependenciesTest {

    @Test
    void listsBuildFilesWhoseDependenciesAreComputedByCode(@TempDir Path root) throws Exception {
        TestSupport.write(root, "app/build.gradle", """
                plugins { id 'java' }
                dependencies {
                    implementation 'org.bouncycastle:bcprov-jdk18on:1.78'
                    ['a', 'b'].each { name -> implementation "com.acme:$name:1.0" }
                }
                """);
        TestSupport.write(root, "lib/build.gradle.kts", """
                dependencies {
                    implementation(files("libs/crypto.jar"))
                }
                """);
        TestSupport.write(root, "py/setup.py", """
                setup(name="x", install_requires=read_requirements("requirements.txt"))
                """);

        assertThat(ComputedDependencies.warnings(root)).hasSize(3)
                .anyMatch(w -> w.contains("app/build.gradle (ligne 4)"))
                .anyMatch(w -> w.contains("lib/build.gradle.kts (ligne 2)"))
                .anyMatch(w -> w.contains("py/setup.py (ligne 1)"));
    }

    @Test
    void staticListsAndLoopsOutsideDependenciesAreNotReported(@TempDir Path root) throws Exception {
        TestSupport.write(root, "build.gradle", """
                tasks.each { t -> println t }
                dependencies {
                    implementation 'com.google.crypto.tink:tink:1.13.0'
                }
                """);
        TestSupport.write(root, "setup.py", """
                setup(name="x", install_requires=["cryptography>=42"])
                """);

        assertThat(ComputedDependencies.warnings(root)).isEmpty();
    }
}
