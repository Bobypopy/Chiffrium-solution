package com.chiffrium.infrastructure.rules;

import com.chiffrium.TestSupport;
import com.chiffrium.application.port.CryptoDetector.DetectionContext;
import com.chiffrium.application.port.SbomGenerator.SbomResult;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.model.SecurityFinding;
import com.chiffrium.infrastructure.findings.FindingRuleLoader;
import com.chiffrium.infrastructure.findings.SecurityFindingDetector;
import com.chiffrium.infrastructure.scan.FileSystemProjectScanner;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/** Dart, Elixir, Perl, Objective-C et SQL : algorithmes, clés créées et constats. */
class NewLanguagesDetectionTest {

    @TempDir
    static Path project;
    private static List<CryptoAsset> assets;
    private static List<SecurityFinding> findings;

    @BeforeAll
    static void analyze() {
        TestSupport.write(project, "dart/crypto.dart", """
                import 'package:crypto/crypto.dart';
                class Vault {
                  Future<void> seal(List<int> data) async {
                    final digest = sha1.convert(data);
                    final algorithm = AesGcm.with128bits();
                    final rsa = KeyGenerator('RSA');
                  }
                  String token() {
                    final token = Random().nextInt(1 << 32);
                  }
                  void client(HttpClient http) {
                    http.badCertificateCallback = (cert, host, port) => true;
                  }
                }
                """);
        TestSupport.write(project, "elixir/crypto.ex", """
                defmodule Vault do
                  def seal(key, data) do
                    :crypto.crypto_one_time(:aes_128_ecb, key, data, true)
                  end
                  def digest(data), do: :crypto.hash(:sha, data)
                  def keys do
                    :crypto.generate_key(:rsa, {1024, 65537})
                  end
                  def connect(host) do
                    :ssl.connect(host, 443, verify: :verify_none)
                  end
                end
                """);
        TestSupport.write(project, "perl/Vault.pm", """
                package Vault;
                use Digest::MD5 qw(md5_hex);
                sub seal {
                    my $cipher = Crypt::CBC->new(-key => $k, -cipher => 'Crypt::DES');
                    my $sum = md5_hex($data);
                    my $rsa = Crypt::OpenSSL::RSA->generate_key(1024);
                    my $ua = LWP::UserAgent->new(ssl_opts => { verify_hostname => 0 });
                }
                """);
        TestSupport.write(project, "objc/Vault.m", """
                @implementation Vault
                - (NSData *)seal:(NSData *)data {
                    CCCrypt(kCCEncrypt, kCCAlgorithmDES, kCCOptionECBMode, key, kCCKeySizeDES, NULL, data.bytes, data.length, out, size, &moved);
                    CC_MD5(data.bytes, (CC_LONG) data.length, digest);
                    return nil;
                }
                @end
                """);
        TestSupport.write(project, "sql/schema.sql", """
                -- jetons et mots de passe
                SELECT md5(password) FROM users;
                UPDATE secrets SET value = AES_ENCRYPT(value, @key);
                CREATE SYMMETRIC KEY PayrollKey WITH ALGORITHM = TRIPLE_DES ENCRYPTION BY PASSWORD = @pass;
                SELECT DBMS_CRYPTO.HASH(raw, DBMS_CRYPTO.HASH_SH1) FROM dual;
                """);

        var scan = new FileSystemProjectScanner(1_000_000).scan(project);
        DetectionContext context = new DetectionContext(project, scan, SbomResult.empty());
        assets = new RuleBasedCryptoDetector(new RulePackLoader(TestSupport.MAPPER).loadBuiltIn(), TestSupport.ASSETS)
                .detect(context).assets();
        findings = new SecurityFindingDetector(new FindingRuleLoader(TestSupport.MAPPER).loadBuiltIn())
                .detect(context).findings();
    }

    private static Set<String> namesIn(String file) {
        return assets.stream()
                .filter(a -> a.occurrences().stream().anyMatch(o -> o.file().equals(file)))
                .map(CryptoAsset::name)
                .collect(Collectors.toSet());
    }

    private static Set<String> findingsIn(String file) {
        return findings.stream().filter(f -> f.file().equals(file)).map(SecurityFinding::ruleId)
                .collect(Collectors.toSet());
    }

    @Test
    void dart() {
        assertThat(namesIn("dart/crypto.dart"))
                .contains("SHA-1", "AES-128-GCM", "RSA", "Clé privée RSA générée (crypto.dart)");
        assertThat(findingsIn("dart/crypto.dart")).contains("random-dart-insecure", "tls-dart-bad-certificate");
    }

    @Test
    void elixir() {
        assertThat(namesIn("elixir/crypto.ex"))
                .contains("AES-128-ECB", "SHA-1", "RSA-1024", "Clé privée RSA-1024 générée (crypto.ex)");
        assertThat(findingsIn("elixir/crypto.ex")).contains("tls-elixir-verify-none");
    }

    @Test
    void perl() {
        assertThat(namesIn("perl/Vault.pm"))
                .contains("DES-CBC", "MD5", "RSA-1024", "Clé privée RSA-1024 générée (Vault.pm)");
        assertThat(findingsIn("perl/Vault.pm")).contains("tls-perl-verify-none");
    }

    @Test
    void objectiveC() {
        assertThat(namesIn("objc/Vault.m")).contains("DES-ECB", "MD5");
    }

    @Test
    void sql() {
        assertThat(namesIn("sql/schema.sql")).contains("MD5", "AES-128-ECB", "3DES", "SHA-1",
                "Clé secrète 3DES générée (schema.sql)");
    }
}
