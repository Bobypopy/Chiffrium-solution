package com.chiffrium.infrastructure.rules;

import com.chiffrium.TestSupport;
import com.chiffrium.application.port.CryptoDetector.DetectionContext;
import com.chiffrium.application.port.SbomGenerator.SbomResult;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.model.Occurrence;
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

/**
 * VB.NET, F# et Erlang (règles de C# et d'Elixir, syntaxe propre), code dans les composants web, pages
 * serveur et notebooks, scripts et modèles d'infrastructure.
 */
class MoreLanguagesDetectionTest {

    @TempDir
    static Path project;
    private static List<CryptoAsset> assets;
    private static List<SecurityFinding> findings;

    @BeforeAll
    static void analyze() {
        TestSupport.write(project, "vb/Crypto.vb", """
                Imports System.Security.Cryptography
                Public Class Crypto
                    ' MD5.Create() en commentaire : ignoré
                    Public Function Hash(data As Byte()) As Byte()
                        Dim rsa As New RSACryptoServiceProvider(1024)
                        Return SHA1.Create().ComputeHash(data)
                    End Function
                    Public Sub Trust()
                        ServicePointManager.ServerCertificateValidationCallback = Function(s, c, ch, e) True
                    End Sub
                End Class
                """);
        TestSupport.write(project, "fs/Crypto.fs", """
                module Crypto
                open System.Security.Cryptography
                let hash (data: byte[]) = MD5.Create().ComputeHash(data)
                let legacy () = new TripleDESCryptoServiceProvider()
                """);
        TestSupport.write(project, "erl/vault.erl", """
                -module(vault).
                % crypto:hash(sha256, X) en commentaire : ignoré
                hash(Data) ->
                    crypto:hash(md5, Data).
                keys() ->
                    public_key:generate_key({rsa, 1024, 65537}).
                connect(Host) ->
                    ssl:connect(Host, 443, [{verify, verify_none}]).
                """);
        TestSupport.write(project, "web/Hash.vue", """
                <template><div>{{ digest }}</div></template>
                <script>
                import crypto from 'crypto';
                export default { computed: { digest() { return crypto.createHash('md4').update('x').digest('hex'); } } };
                </script>
                """);
        TestSupport.write(project, "web/hash.jsp", """
                <% java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-1"); %>
                """);
        TestSupport.write(project, "web/Index.cshtml", """
                @{ var h = System.Security.Cryptography.MD5.Create(); }
                """);
        TestSupport.write(project, "web/show.html.erb", """
                <%= Digest::MD5.hexdigest(@user.email) %>
                """);
        TestSupport.write(project, "notebooks/analysis.ipynb", """
                {
                 "cells": [
                  {
                   "cell_type": "markdown",
                   "metadata": {},
                   "source": [
                    "hashlib.new(\\"md5\\") cité dans le texte : pas du code\\n"
                   ]
                  },
                  {
                   "cell_type": "code",
                   "execution_count": 1,
                   "metadata": {},
                   "outputs": [],
                   "source": [
                    "import hashlib\\n",
                    "digest = hashlib.new(\\"sha1\\", data)"
                   ]
                  }
                 ]
                }
                """);
        TestSupport.write(project, "scripts/backup.sh", """
                openssl enc -des3 -salt -in dump.sql -out dump.sql.enc
                openssl dgst -md5 dump.sql.enc
                openssl s_client -connect legacy.example.org:443 -tls1
                """);
        TestSupport.write(project, "infra/template.json", """
                { "Resources": { "Key": { "Type": "AWS::KMS::Key", "Properties": { "KeySpec": "RSA_2048" } } } }
                """);
        TestSupport.write(project, "package-lock.json", """
                { "packages": { "node_modules/a": { "integrity": "sha1-abc", "hash": "md5" } } }
                """);

        var scan = new FileSystemProjectScanner(1_000_000).scan(project);
        DetectionContext context = new DetectionContext(project, scan, SbomResult.empty());
        assets = new RuleBasedCryptoDetector(new RulePackLoader(TestSupport.MAPPER).loadBuiltIn(), TestSupport.ASSETS)
                .detect(context).assets();
        findings = new SecurityFindingDetector(new FindingRuleLoader(TestSupport.MAPPER).loadBuiltIn())
                .detect(context).findings();
    }

    private static Set<String> namesIn(String file) {
        return assets.stream().filter(a -> a.occurrences().stream().anyMatch(o -> o.file().equals(file)))
                .map(CryptoAsset::name).collect(Collectors.toSet());
    }

    private static Occurrence occurrence(String name, String file) {
        return assets.stream().filter(a -> a.name().equals(name)).flatMap(a -> a.occurrences().stream())
                .filter(o -> o.file().equals(file)).findFirst()
                .orElseThrow(() -> new AssertionError(name + " absent de " + file + " : " + namesIn(file)));
    }

    private static Set<String> findingsIn(String file) {
        return findings.stream().filter(f -> f.file().equals(file)).map(SecurityFinding::ruleId)
                .collect(Collectors.toSet());
    }

    @Test
    void visualBasicUsesTheDotNetRulesWithItsOwnSyntax() {
        assertThat(namesIn("vb/Crypto.vb")).contains("RSA-1024", "SHA-1").doesNotContain("MD5");
        assertThat(occurrence("SHA-1", "vb/Crypto.vb").function()).isEqualTo("Crypto.Hash");
        assertThat(findingsIn("vb/Crypto.vb")).contains("tls-csharp-accept-any");
    }

    @Test
    void fSharpUsesTheDotNetRules() {
        assertThat(namesIn("fs/Crypto.fs")).contains("MD5").anyMatch(n -> n.startsWith("3DES"));
        assertThat(occurrence("MD5", "fs/Crypto.fs").function()).isEqualTo("Crypto.hash");
    }

    @Test
    void erlangUsesTheElixirRulesWithItsOwnSyntax() {
        assertThat(namesIn("erl/vault.erl")).contains("MD5", "RSA-1024").doesNotContain("SHA-256");
        assertThat(occurrence("MD5", "erl/vault.erl").function()).isEqualTo("vault.hash");
        assertThat(findingsIn("erl/vault.erl")).contains("tls-elixir-verify-none");
    }

    @Test
    void codeInsideWebComponentsAndServerPages() {
        assertThat(namesIn("web/Hash.vue")).contains("MD4");
        assertThat(namesIn("web/hash.jsp")).contains("SHA-1");
        assertThat(namesIn("web/Index.cshtml")).contains("MD5");
        assertThat(namesIn("web/show.html.erb")).contains("MD5");
    }

    @Test
    void notebookCodeCellsAreReadAtTheirLine() {
        assertThat(namesIn("notebooks/analysis.ipynb")).contains("SHA-1").doesNotContain("MD5");
        assertThat(occurrence("SHA-1", "notebooks/analysis.ipynb").line()).isEqualTo(17);
    }

    @Test
    void opensslCommandsInScripts() {
        assertThat(namesIn("scripts/backup.sh")).contains("MD5", "TLS 1.0").anyMatch(n -> n.startsWith("3DES"));
    }

    @Test
    void cloudTemplatesInJsonButNotLockFiles() {
        assertThat(namesIn("infra/template.json")).anyMatch(n -> n.startsWith("RSA"));
        assertThat(namesIn("package-lock.json")).isEmpty();
    }
}
