package com.chiffrium.infrastructure;

import com.chiffrium.TestSupport;
import com.chiffrium.application.port.CryptoDetector.DetectionContext;
import com.chiffrium.application.port.SbomGenerator.SbomResult;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.model.SecurityFinding;
import com.chiffrium.infrastructure.findings.FindingRuleLoader;
import com.chiffrium.infrastructure.findings.SecurityFindingDetector;
import com.chiffrium.infrastructure.material.MaterialDetector;
import com.chiffrium.infrastructure.scan.ArchiveEntries;
import com.chiffrium.infrastructure.scan.FileSystemProjectScanner;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.GZIPOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.assertj.core.api.Assertions.assertThat;

/** Archives versionnées : lues en mémoire, sans extraction, avec des limites contre les archives piégées. */
class ArchiveDetectionTest {

    private static final String PEM = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIBExampleExampleExampleExample\n"
            + "-----END EC PRIVATE KEY-----\n";

    private static void zip(Path file, String[][] entries) throws IOException {
        Files.createDirectories(file.getParent());
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(file))) {
            for (String[] entry : entries) {
                zip.putNextEntry(new ZipEntry(entry[0]));
                zip.write(entry[1].getBytes(StandardCharsets.UTF_8));
                zip.closeEntry();
            }
        }
    }

    /** Tar minimal (en-têtes ustar), compressé en gzip. */
    private static void tarGz(Path file, String name, String content) throws IOException {
        Files.createDirectories(file.getParent());
        byte[] data = content.getBytes(StandardCharsets.UTF_8);
        byte[] header = new byte[512];
        System.arraycopy(name.getBytes(StandardCharsets.UTF_8), 0, header, 0, name.length());
        byte[] size = String.format("%011o", data.length).getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(size, 0, header, 124, size.length);
        header[156] = '0';
        System.arraycopy("ustar".getBytes(StandardCharsets.US_ASCII), 0, header, 257, 5);
        try (OutputStream out = new GZIPOutputStream(Files.newOutputStream(file))) {
            out.write(header);
            out.write(data);
            out.write(new byte[(512 - data.length % 512) % 512]);
            out.write(new byte[1024]);
        }
    }

    @Test
    void keysAndSecretsInsideArchivesAreFound(@TempDir Path project) throws Exception {
        zip(project.resolve("deploy/release.zip"), new String[][]{
                {"conf/server.key", PEM},
                {"conf/app.properties", "db.password=Hx7kQ2mP9vLr\n"},
                {"lib/App.class", "\u0000\u0001binaire"}});
        tarGz(project.resolve("backup/ssh.tar.gz"), "home/deploy/.ssh/id_ed25519", PEM);

        var scan = new FileSystemProjectScanner(1_000_000).scan(project);
        DetectionContext context = new DetectionContext(project, scan, SbomResult.empty());
        List<CryptoAsset> assets = new MaterialDetector(TestSupport.ASSETS).detect(context).assets();
        List<SecurityFinding> findings = new SecurityFindingDetector(
                new FindingRuleLoader(TestSupport.MAPPER).loadBuiltIn()).detect(context).findings();

        assertThat(assets).extracting(a -> a.occurrences().get(0).file()).containsExactlyInAnyOrder(
                "deploy/release.zip!/conf/server.key", "backup/ssh.tar.gz!/home/deploy/.ssh/id_ed25519");
        assertThat(findings).extracting(SecurityFinding::ruleId, SecurityFinding::file).contains(
                org.assertj.core.groups.Tuple.tuple("secret-config-assignment", "deploy/release.zip!/conf/app.properties"),
                org.assertj.core.groups.Tuple.tuple("secret-private-key", "deploy/release.zip!/conf/server.key"));
        assertThat(findings).allSatisfy(f -> assertThat(f.snippet() + " " + f.evidence()).doesNotContain("Hx7kQ2mP9vLr"));
    }

    @Test
    void oversizedEntriesAreSkippedWithoutReadingThemWhole(@TempDir Path dir) throws Exception {
        Path archive = dir.resolve("bomb.zip");
        ByteArrayOutputStream big = new ByteArrayOutputStream();
        big.write(new byte[ArchiveEntries.MAX_ENTRY_BYTES + 1]);
        zip(archive, new String[][]{{"small.txt", "petit"}, {"big.txt", big.toString(StandardCharsets.UTF_8)}});

        List<String> read = new ArrayList<>();
        ArchiveEntries.forEach(archive, entry -> read.add(entry.path()));

        assertThat(read).containsExactly("small.txt");
    }
}
