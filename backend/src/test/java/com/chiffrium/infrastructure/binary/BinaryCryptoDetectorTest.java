package com.chiffrium.infrastructure.binary;

import com.chiffrium.TestSupport;
import com.chiffrium.application.port.CryptoDetector.DetectionContext;
import com.chiffrium.application.port.SbomGenerator.SbomResult;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.model.DetectionSource;
import com.chiffrium.infrastructure.scan.FileSystemProjectScanner;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.tools.ToolProvider;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.assertj.core.api.Assertions.assertThat;

/** Bytecode Java (seul et dans un jar), bibliothèque native, assemblage .NET : algorithmes nommés dans le binaire. */
class BinaryCryptoDetectorTest {

    @TempDir
    static Path project;
    @TempDir
    static Path build;
    private static List<CryptoAsset> assets;

    @BeforeAll
    static void analyze() throws IOException {
        // Une vraie classe compilée : les noms passés à la JCA sont des constantes du bytecode.
        Path source = build.resolve("Legacy.java");
        Files.writeString(source, """
                public class Legacy {
                    void go() throws Exception {
                        javax.crypto.Cipher.getInstance("DES/ECB/PKCS5Padding");
                        java.security.MessageDigest.getInstance("MD5");
                    }
                }
                """);
        assertThat(ToolProvider.getSystemJavaCompiler().run(null, null, null, "-d", build.toString(),
                source.toString())).isZero();
        byte[] classFile = Files.readAllBytes(build.resolve("Legacy.class"));
        Files.createDirectories(project.resolve("bin"));
        Files.write(project.resolve("bin/Legacy.class"), classFile);
        ByteArrayOutputStream jar = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(jar)) {
            zip.putNextEntry(new ZipEntry("com/acme/Legacy.class"));
            zip.write(classFile);
            zip.closeEntry();
        }
        Files.createDirectories(project.resolve("lib"));
        Files.write(project.resolve("lib/legacy.jar"), jar.toByteArray());

        // Bibliothèque native : symboles OpenSSL au milieu d'octets quelconques.
        Files.write(project.resolve("lib/libpay.so"), binary("\u0001\u0002ELF\u0000EVP_des_ede3_cbc\u0000"
                + "MD5_Init\u0000\u0007random-text\u0000"));
        // Assemblage .NET : nom de type en ASCII, chaîne utilisateur en UTF-16.
        ByteArrayOutputStream dll = new ByteArrayOutputStream();
        dll.write(binary("MZ\u0000\u0000RC2CryptoServiceProvider\u0000\u0000"));
        dll.write("TripleDES".getBytes(StandardCharsets.UTF_16LE));
        dll.write(new byte[]{0, 0, 1});
        Files.write(project.resolve("lib/Payments.dll"), dll.toByteArray());

        // Exécutable Go sans extension (Linux) : reconnu à son en-tête ELF, symboles de paquets crypto/....
        Files.createDirectories(project.resolve("bin"));
        Files.write(project.resolve("bin/server"), binary("\u007FELF\u0002\u0001\u0000crypto/des.NewTripleDESCipher\u0000"
                + "crypto/md5.Sum\u0000main.main\u0000md5\u0000"));
        // Fichier sans extension qui n'est pas un exécutable : ignoré.
        Files.writeString(project.resolve("bin/NOTES"), "crypto/rc4.NewCipher\n");
        // Bytecode Python : module PyCryptodome et nom de hachage.
        Files.write(project.resolve("lib/vault.cpython-312.pyc"), binary("Ë\r\r\n\u0000\u0000ã"
                + "\u0010Crypto.Cipher.DES3\u0000\u0003sha1)\u0000"));

        var scan = new FileSystemProjectScanner(1_000_000).scan(project);
        assets = new BinaryCryptoDetector(TestSupport.ASSETS, BinarySignatures.loadBuiltIn(TestSupport.MAPPER))
                .detect(new DetectionContext(project, scan, SbomResult.empty())).assets();
    }

    private static byte[] binary(String text) {
        return text.getBytes(StandardCharsets.ISO_8859_1);
    }

    private static Set<String> namesIn(String file) {
        return assets.stream().filter(a -> a.occurrences().stream().anyMatch(o -> o.file().equals(file)))
                .map(CryptoAsset::name).collect(Collectors.toSet());
    }

    @Test
    void javaBytecodeAloneAndInsideAJar() {
        assertThat(namesIn("bin/Legacy.class")).contains("MD5").anyMatch(n -> n.startsWith("DES-ECB"));
        assertThat(namesIn("lib/legacy.jar!/com/acme/Legacy.class")).contains("MD5");
    }

    @Test
    void nativeLibrarySymbols() {
        assertThat(namesIn("lib/libpay.so")).contains("MD5").anyMatch(n -> n.startsWith("3DES"));
    }

    @Test
    void dotNetTypesAndUtf16Strings() {
        assertThat(namesIn("lib/Payments.dll")).contains("RC2", "3DES");
    }

    @Test
    void goExecutableWithoutExtension() {
        // "md5" seul ne compte que dans du bytecode Python : ici, c'est crypto/md5.Sum qui donne MD5.
        assertThat(namesIn("bin/server")).contains("MD5").anyMatch(n -> n.startsWith("3DES"));
        assertThat(namesIn("bin/NOTES")).isEmpty();
    }

    @Test
    void pythonBytecode() {
        assertThat(namesIn("lib/vault.cpython-312.pyc")).contains("SHA-1").anyMatch(n -> n.startsWith("3DES"));
    }

    @Test
    void assetsComeFromTheBinarySourceWithoutLine() {
        assertThat(assets).isNotEmpty().allSatisfy(a -> {
            assertThat(a.sources()).containsExactly(DetectionSource.BINARY);
            assertThat(a.occurrences()).allSatisfy(o -> assertThat(o.line()).isNull());
        });
    }
}
