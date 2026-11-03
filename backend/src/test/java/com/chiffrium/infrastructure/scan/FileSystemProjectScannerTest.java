package com.chiffrium.infrastructure.scan;

import com.chiffrium.TestSupport;
import com.chiffrium.application.port.ProjectScanner.ScanResult;
import com.chiffrium.domain.model.Language;
import com.chiffrium.domain.model.ProjectModule;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

class FileSystemProjectScannerTest {

    @Test
    void detectsNestedModulesGitRepositoriesAndLanguages(@TempDir Path root) throws Exception {
        TestSupport.write(root, "pom.xml", "<project/>");
        TestSupport.write(root, "src/main/java/App.java", "class App {}");
        TestSupport.write(root, "web/package.json", "{}");
        TestSupport.write(root, "web/src/index.ts", "export {}");
        TestSupport.write(root, "libs/crypto/.git", "gitdir: ../../.git/modules/crypto");
        TestSupport.write(root, "libs/crypto/main.go", "package main");
        TestSupport.write(root, "node_modules/lib/index.js", "ignored");
        TestSupport.write(root, "certs/server.pem", "-----BEGIN CERTIFICATE-----");
        TestSupport.write(root, "README.md", "not analysed");
        Files.writeString(root.resolve("big.py"), "x".repeat(200));

        ScanResult result = new FileSystemProjectScanner(100).scan(root);

        assertThat(result.modules()).extracting(ProjectModule::path).containsExactlyInAnyOrder(".", "web", "libs/crypto");
        ProjectModule submodule = result.modules().stream().filter(m -> m.path().equals("libs/crypto")).findFirst()
                .orElseThrow();
        assertThat(submodule.gitRepository()).isTrue();
        assertThat(submodule.languages()).containsExactly(Language.GO);
        // pom.xml est lu comme configuration (secrets, suites TLS).
        assertThat(result.languages()).containsExactlyInAnyOrder(Language.JAVA, Language.TYPESCRIPT, Language.GO,
                Language.CONFIG);
        assertThat(result.files()).noneMatch(f -> f.path().startsWith("node_modules"));
        assertThat(result.files()).anyMatch(f -> f.path().equals("certs/server.pem") && f.material());
        assertThat(result.skipped()).isEqualTo(1);
    }

    @Test
    void classifiesFiles() {
        assertThat(FileClassifier.languageOf("a.tsx")).contains(Language.TYPESCRIPT);
        assertThat(FileClassifier.languageOf("Makefile")).contains(Language.CONFIG);
        assertThat(FileClassifier.languageOf(".env.production")).contains(Language.CONFIG);
        assertThat(FileClassifier.languageOf("README.md")).isEmpty();
        assertThat(FileClassifier.isMaterial("id_rsa")).isTrue();
        assertThat(FileClassifier.isManifest("App.csproj")).isTrue();
        assertThat(FileClassifier.isIgnoredDirectory("node_modules")).isTrue();
    }
}
