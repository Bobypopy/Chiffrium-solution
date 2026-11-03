package com.chiffrium.infrastructure;

import com.chiffrium.TestSupport;
import com.chiffrium.application.port.CryptoDetector.DetectionContext;
import com.chiffrium.application.port.SbomGenerator.SbomResult;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.model.Language;
import com.chiffrium.domain.model.SecurityFinding;
import com.chiffrium.domain.model.Severity;
import com.chiffrium.infrastructure.findings.FindingRuleLoader;
import com.chiffrium.infrastructure.findings.SecurityFindingDetector;
import com.chiffrium.infrastructure.rules.RuleBasedCryptoDetector;
import com.chiffrium.infrastructure.rules.RulePackLoader;
import com.chiffrium.infrastructure.scan.FileClassifier;
import com.chiffrium.infrastructure.scan.FileSystemProjectScanner;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** Scripts PowerShell (administration Windows et Azure, PowerSploit) et CryptoSwift (applications iOS). */
class PowerShellAndCryptoSwiftTest {

    private static DetectionContext context(Path root) {
        return new DetectionContext(root, new FileSystemProjectScanner(1_000_000).scan(root), SbomResult.empty());
    }

    private static List<String> assets(Path root, String file) {
        return new RuleBasedCryptoDetector(new RulePackLoader(TestSupport.MAPPER).loadBuiltIn(), TestSupport.ASSETS)
                .detect(context(root)).assets().stream()
                .filter(a -> a.occurrences().stream().anyMatch(o -> o.file().equals(file)))
                .map(CryptoAsset::name).toList();
    }

    private static List<SecurityFinding> findings(Path root) {
        return new SecurityFindingDetector(new FindingRuleLoader(TestSupport.MAPPER).loadBuiltIn(),
                new RulePackLoader(TestSupport.MAPPER).loadBuiltIn()).detect(context(root)).findings();
    }

    @Test
    void powershellScriptsAreAnalysedAsTheirOwnLanguage() {
        assertThat(FileClassifier.languageOf("Get-GPPPassword.ps1")).contains(Language.POWERSHELL);
        assertThat(FileClassifier.languageOf("PowerUp.psm1")).contains(Language.POWERSHELL);
        assertThat(FileClassifier.languageOf("Module.psd1")).contains(Language.POWERSHELL);
    }

    @Test
    void dotNetCryptographyCalledFromPowershellIsInventoried(@TempDir Path root) {
        TestSupport.write(root, "scripts/crypto.ps1", """
                # [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Ssl3
                $aes = [System.Security.Cryptography.Aes]::Create()
                $aes.Mode = [System.Security.Cryptography.CipherMode]::ECB
                $md5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
                $hash = [System.Security.Cryptography.HashAlgorithm]::Create('SHA1')
                $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
                $rsa.KeySize = 1024
                Get-FileHash -Path $file -Algorithm MD5
                Get-FileHash -Path $other
                $secure | ConvertFrom-SecureString -Key $key | Set-Content cred.txt
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                """);

        assertThat(assets(root, "scripts/crypto.ps1")).contains("AES-ECB", "MD5", "SHA-1", "RSA-1024", "SHA-256",
                "TLS 1.2").doesNotContain("SSL 3.0");
    }

    /** Get-GPPPassword (PowerSploit) : la clé AES publiée par Microsoft, écrite dans le script. */
    @Test
    void powershellWeaknessesAreReported(@TempDir Path root) {
        TestSupport.write(root, "Exfiltration/Get-GPPPassword.ps1", """
                <#
                .EXAMPLE
                    $SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
                    Invoke-RestMethod -Uri $uri -SkipCertificateCheck
                #>
                function Get-DecryptedCpassword {
                    [Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8)
                    $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
                }
                """);
        TestSupport.write(root, "deploy/connect.ps1", """
                $password = ConvertTo-SecureString "Zq8vR2pL9wKx" -AsPlainText -Force
                $fromVault = ConvertTo-SecureString $env:DEPLOY_PASSWORD -AsPlainText -Force
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
                Invoke-RestMethod -Uri $uri -SkipCertificateCheck
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls12
                $resetToken = Get-Random -Minimum 100000 -Maximum 999999
                $delay = Get-Random -Maximum 30
                """);

        List<SecurityFinding> found = findings(root);

        assertThat(found).extracting(f -> f.ruleId() + " " + f.file() + ":" + f.line()).containsExactlyInAnyOrder(
                "key-powershell-literal Exfiltration/Get-GPPPassword.ps1:7",
                "secret-powershell-plaintext-securestring deploy/connect.ps1:1",
                "tls-powershell-trust-all deploy/connect.ps1:3",
                "tls-powershell-trust-all deploy/connect.ps1:4",
                "tls-powershell-old-protocol deploy/connect.ps1:5",
                "random-powershell-insecure deploy/connect.ps1:6",
                "random-powershell-general deploy/connect.ps1:7");
        assertThat(found).filteredOn(f -> f.ruleId().equals("random-powershell-general")).singleElement()
                .satisfies(f -> assertThat(f.severity()).isEqualTo(Severity.LOW));
        // AesCryptoServiceProvider : AES (lu en entier, le nom contenait "scrypt").
        assertThat(assets(root, "Exfiltration/Get-GPPPassword.ps1")).containsExactly("AES");
    }

    /** Bicep : une valeur sans guillemets est une référence ; un littéral s'écrit entre apostrophes. */
    @Test
    void bicepReferencesAreNotSecretsButLiteralsAre(@TempDir Path root) {
        TestSupport.write(root, "avm/ptn/app/main.bicep", """
                module vm 'br/public:avm/res/compute/virtual-machine:0.1.0' = {
                  params: {
                    adminPassword: virtualMachineConfiguration.?adminPassword
                    DOCKER_REGISTRY_SERVER_PASSWORD: containerRegistryPassword
                    keyVaultSecretId: keyVaultCertUri
                    sqlAdminPassword: 'Zq8vR2pL9wKx'
                  }
                }
                """);

        assertThat(findings(root)).extracting(f -> f.ruleId() + ":" + f.line())
                .containsExactly("secret-generic-assignment:6");
    }

    /** Exemples de la documentation de CryptoSwift. */
    @Test
    void cryptoSwiftIsInventoried(@TempDir Path root) {
        TestSupport.write(root, "App/Crypto.swift", """
                import CryptoSwift
                func protect() throws {
                    let aes = try AES(key: key, blockMode: CBC(iv: iv), padding: .pkcs7)
                    let gcm = try AES(key: key, blockMode: GCM(iv: iv, mode: .combined), padding: .noPadding)
                    let ecb = try Blowfish(key: key, blockMode: ECB(), padding: .pkcs7)
                    let stream = try ChaCha20(key: key, iv: iv)
                    let digest = "123".md5()
                    let sha = data.sha256()
                    let keccak = data.sha3(.keccak256)
                    let mac = try HMAC(key: key, variant: .sha2(.sha256)).authenticate(bytes)
                    let derived = try PKCS5.PBKDF2(password: password, salt: salt, iterations: 4096, keyLength: 32, variant: .sha2(.sha256)).calculate()
                    let scrypt = try Scrypt(password: password, salt: salt, dkLen: 64, N: 16384, r: 8, p: 1).calculate()
                    let tag = try Poly1305(key: key).authenticate(bytes)
                    let sealed = try AES.GCM.seal(plain, using: symmetricKey)
                }
                """);

        assertThat(assets(root, "App/Crypto.swift")).contains("AES-CBC", "AES-GCM", "Blowfish-ECB", "ChaCha20", "MD5",
                "SHA-256", "HMAC-SHA-256", "PBKDF2", "scrypt", "Poly1305").anyMatch(n -> n.startsWith("Keccak"));
    }
}
