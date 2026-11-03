package com.chiffrium.infrastructure.rules;

import com.chiffrium.TestSupport;
import com.chiffrium.application.port.CallEdgeExtractor.CallEdge;
import com.chiffrium.application.port.CryptoDetector.DetectionContext;
import com.chiffrium.application.port.CryptoDetector.DetectionResult;
import com.chiffrium.application.port.SbomGenerator.SbomResult;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.model.Occurrence;
import com.chiffrium.infrastructure.scan.FileSystemProjectScanner;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** Valeurs transmises par un paramètre, un champ ou un constructeur : retrouvées, avec leur trajet. */
class ValueTraceTest {

    @TempDir
    static Path project;
    private static DetectionResult result;

    @BeforeAll
    static void analyze() {
        TestSupport.write(project, "java/Main.java", """
                public class Main {
                    public static void main(String[] args) throws Exception {
                        Worker worker = new Worker();
                        String algorithm = "DES/ECB/PKCS5Padding";
                        worker.go(algorithm, 1024);
                        new Holder("RC4").use();
                        mystery().go("Twofish/CBC/NoPadding", 2048);
                    }
                }
                """);
        TestSupport.write(project, "java/Worker.java", """
                public class Worker {
                    public void go(String crypto, int size) throws Exception {
                        javax.crypto.Cipher.getInstance(crypto);
                        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("RSA");
                        kpg.initialize(size);
                    }
                }
                """);
        // Homonyme de Worker.go : l'appel "worker.go" est relié par le type de la variable, pas par le nom seul.
        TestSupport.write(project, "java/Other.java", """
                public class Other {
                    public void go(String name, int count) {
                        System.out.println(name + count);
                    }
                }
                """);
        TestSupport.write(project, "java/Holder.java", """
                public class Holder {
                    private final String algo;
                    public Holder(String chosen) {
                        algo = chosen;
                    }
                    public void use() throws Exception {
                        javax.crypto.Cipher.getInstance(String.valueOf(algo));
                    }
                }
                """);
        TestSupport.write(project, "python/digests.py", """
                import hashlib

                def fingerprint(data, algo):
                    return hashlib.new(algo, data)

                def run():
                    return fingerprint(b"x", "md5")
                """);
        TestSupport.write(project, "java/Routes.java", """
                public class Routes {
                    record Request(String name) {}
                    void register() throws Exception {
                        java.security.MessageDigest.getInstance("SHA-256");
                    }
                }
                """);
        TestSupport.write(project, "js/settings.js", """
                const settings = { cipher: 'des-ede3-cbc', checksum: 'sha1' };
                """);
        TestSupport.write(project, "cs/Settings.cs", """
                public static class Settings {
                    public const string Hash = "MD5";
                }
                """);
        TestSupport.write(project, "kotlin/Seal.kt", """
                fun seal(transformation: String) = javax.crypto.Cipher.getInstance(transformation)

                fun main() {
                    seal("Blowfish/CBC/PKCS5Padding")
                }
                """);

        var scan = new FileSystemProjectScanner(1_000_000).scan(project);
        result = new RuleBasedCryptoDetector(new RulePackLoader(TestSupport.MAPPER).loadBuiltIn(), TestSupport.ASSETS)
                .detect(new DetectionContext(project, scan, SbomResult.empty()));
    }

    private static List<Occurrence> occurrences(String namePrefix, String file) {
        return result.assets().stream().filter(a -> a.name().startsWith(namePrefix))
                .flatMap(a -> a.occurrences().stream()).filter(o -> o.file().equals(file)).toList();
    }

    @Test
    void parameterValueIsFoundAtTheCallWithItsPath() {
        assertThat(occurrences("DES-ECB", "java/Worker.java")).singleElement().satisfies(o -> {
            assertThat(o.line()).isEqualTo(3);
            // De l'endroit où la valeur est écrite à l'appel qui la transmet.
            assertThat(o.trace()).containsExactly("Main.main (java/Main.java:4)", "Main.main (java/Main.java:5)");
        });
    }

    @Test
    void theStringWhereTheValueIsWrittenBecomesALocationOfTheSameAsset() {
        CryptoAsset des = result.assets().stream().filter(a -> a.name().startsWith("DES-ECB")).findFirst().orElseThrow();
        assertThat(des.occurrences()).extracting(Occurrence::file).contains("java/Main.java");
    }

    @Test
    void keySizePassedAsParameterIsTraced() {
        assertThat(occurrences("RSA-1024", "java/Worker.java")).isNotEmpty()
                .allSatisfy(o -> assertThat(o.trace()).contains("Main.main (java/Main.java:5)"));
    }

    @Test
    void fieldSetByTheConstructorIsTracedToTheCaller() {
        assertThat(occurrences("RC4", "java/Holder.java")).singleElement()
                .satisfies(o -> assertThat(o.trace()).containsExactly("Main.main (java/Main.java:6)",
                        "Holder.Holder (java/Holder.java:4)"));
    }

    @Test
    void ambiguousCallIsNotLinked() {
        // mystery().go(...) peut viser Worker.go ou Other.go : aucune valeur n'est attribuée.
        assertThat(result.assets()).noneMatch(a -> a.name().startsWith("Twofish"));
    }

    @Test
    void otherLanguagesAreTracedToo() {
        assertThat(occurrences("MD5", "python/digests.py")).singleElement()
                .satisfies(o -> assertThat(o.trace()).containsExactly("digests.run (python/digests.py:7)"));
        assertThat(occurrences("Blowfish", "kotlin/Seal.kt")).isNotEmpty();
    }

    @Test
    void aTypeClosedAboveAMethodIsNotItsContainer() {
        assertThat(occurrences("SHA-256", "java/Routes.java")).singleElement()
                .extracting(Occurrence::function).isEqualTo("Routes.register");
    }

    @Test
    void namesWrittenAloneAreInventoriedBeyondJava() {
        // Nom OpenSSL avec mode : retenu ; nom de hachage seul ('sha1', souvent une clé de dictionnaire) : non.
        assertThat(result.assets().stream().flatMap(a -> a.occurrences().stream().map(o -> a.name() + "@" + o.file())))
                .anyMatch(s -> s.startsWith("3DES") && s.endsWith("@js/settings.js"))
                .noneMatch(s -> s.startsWith("SHA-1") && s.endsWith("@js/settings.js"))
                .contains("MD5@cs/Settings.cs");
    }

    @Test
    void callsBetweenProjectFunctionsFeedTheGraph() {
        assertThat(result.callEdges()).extracting(CallEdge::caller, CallEdge::callee)
                .contains(org.assertj.core.groups.Tuple.tuple("Main.main", "Worker.go"),
                        org.assertj.core.groups.Tuple.tuple("Main.main", "Holder.Holder"),
                        org.assertj.core.groups.Tuple.tuple("digests.run", "digests.fingerprint"))
                .doesNotContain(org.assertj.core.groups.Tuple.tuple("Main.main", "Other.go"));
    }
}
