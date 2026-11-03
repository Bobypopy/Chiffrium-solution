package com.chiffrium.infrastructure.rules;

import com.chiffrium.TestSupport;
import com.chiffrium.application.port.CryptoDetector.DetectionContext;
import com.chiffrium.application.port.SbomGenerator.SbomResult;
import com.chiffrium.infrastructure.findings.FindingRuleLoader;
import com.chiffrium.infrastructure.findings.SecurityFindingDetector;
import com.chiffrium.infrastructure.material.MaterialDetector;
import com.chiffrium.infrastructure.scan.FileSystemProjectScanner;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

/**
 * Fichiers pathologiques (longs vecteurs de test, blobs Base64, lignes minifiées) : aucune règle ne doit
 * déborder la pile ni exploser en temps. Régression : une très longue chaîne dans bc-java faisait
 * échouer l'analyse par StackOverflowError dans le repérage des chaînes et commentaires.
 */
class PathologicalInputTest {

    private static final long MAX_FILE_BYTES = 2L * 1024 * 1024;
    private static final int HUGE = 100_000;
    /** Code ordinaire autour des lignes géantes, comme dans un vrai fichier (sinon il serait classé minifié). */
    private static final int ORDINARY_LINES = 2_000;
    private static final List<String> EXTENSIONS = List.of("java", "py", "js", "ts", "go", "cs", "c", "cpp", "php",
            "rb", "rs", "swift", "kt", "yaml", "conf", "properties", "json", "xml", "dart", "ex", "pl", "m", "sql");

    @Test
    void hugeLinesDoNotBreakAnyDetector(@TempDir Path project) {
        String hex = "0123456789abcdef".repeat(HUGE / 16);
        String escaped = "\\x00\\x01ab".repeat(HUGE / 10);
        String base64 = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=".repeat(HUGE / 36);
        String minified = "a=b|c;".repeat(HUGE / 6);
        String content = String.join("\n",
                "class Vectors {",
                "  void f() {",
                "    String a = \"" + hex + "\";",
                "    String b = \"" + escaped + "\";",
                "    String c = '" + hex + "';",
                "    String d = `" + base64 + "`;",
                "    // " + minified,
                "    MessageDigest.getInstance(\"SHA-1\"); Cipher.getInstance(\"AES\");",
                "  }",
                "}",
                "-----BEGIN CERTIFICATE-----",
                base64,
                "    int unused = 0;\n".repeat(ORDINARY_LINES));
        for (String extension : EXTENSIONS) {
            TestSupport.write(project, "src/Vectors." + extension, content);
        }
        var scan = new FileSystemProjectScanner(MAX_FILE_BYTES).scan(project);
        DetectionContext context = new DetectionContext(project, scan, SbomResult.empty());

        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> {
            var rules = new RuleBasedCryptoDetector(new RulePackLoader(TestSupport.MAPPER).loadBuiltIn(),
                    TestSupport.ASSETS).detect(context);
            assertThat(rules.assets()).as("les détections normales restent trouvées").isNotEmpty();
            new SecurityFindingDetector(new FindingRuleLoader(TestSupport.MAPPER).loadBuiltIn()).detect(context);
            new MaterialDetector(TestSupport.ASSETS).detect(context);
        });
    }
}
