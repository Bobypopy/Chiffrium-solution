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

/** COBOL (ICSF), ABAP, Lua (OpenResty), Solidity, Apex, Haskell et R. */
class LastLanguagesDetectionTest {

    @TempDir
    static Path project;
    private static List<CryptoAsset> assets;
    private static List<SecurityFinding> findings;

    @BeforeAll
    static void analyze() {
        TestSupport.write(project, "cobol/PAYCRYPT.cbl", """
                       IDENTIFICATION DIVISION.
                       PROGRAM-ID. PAYCRYPT.
                       PROCEDURE DIVISION.
                       ENCRYPT-CARD.
                           CALL 'CSNBENC' USING RETURN-CODE REASON-CODE KEY-ID.
                      *    CALL 'CSNBSAE' en commentaire : ignoré
                       HASH-PAN.
                           MOVE 'SHA-1   ' TO RULE-ARRAY.
                           CALL 'CSNBOWH' USING RETURN-CODE RULE-ARRAY.
                """);
        TestSupport.write(project, "abap/zcl_crypto.abap", """
                CLASS zcl_crypto IMPLEMENTATION.
                  METHOD hash.
                    cl_abap_message_digest=>calculate_hash_for_char(
                      EXPORTING if_algorithm = 'MD5'
                                if_data      = lv_data
                      IMPORTING ef_hashstring = lv_hash ).
                    cl_abap_hmac=>calculate_hmac_for_char(
                      EXPORTING if_algorithm = 'SHA1'
                                if_key       = lv_key
                                if_data      = lv_data ).
                  ENDMETHOD.
                ENDCLASS.
                """);
        TestSupport.write(project, "lua/auth.lua", """
                local aes = require "resty.aes"
                local function encrypt(key, data)
                  local cipher = aes:new(key, nil, aes.cipher(128, "ecb"), aes.hash.md5)
                  return cipher:encrypt(data)
                end
                local digest = ngx.md5(data)
                local res = httpc:request_uri(url, { ssl_verify = false })
                """);
        TestSupport.write(project, "solidity/Lottery.sol", """
                contract Lottery {
                    function draw() public view returns (uint) {
                        return uint(keccak256(abi.encodePacked(block.timestamp, msg.sender)));
                    }
                    function check(bytes32 h, uint8 v, bytes32 r, bytes32 s) public pure returns (address) {
                        return ecrecover(h, v, r, s);
                    }
                }
                """);
        TestSupport.write(project, "apex/TokenService.cls", """
                public with sharing class TokenService {
                    public static Blob hash(String value) {
                        return Crypto.generateDigest('MD5', Blob.valueOf(value));
                    }
                    public static Blob seal(Blob key, Blob data) {
                        return Crypto.encryptWithManagedIV('AES128', key, data);
                    }
                }
                """);
        TestSupport.write(project, "haskell/Vault.hs", """
                module Vault where
                import Crypto.Hash (hashWith, SHA1 (..))
                import qualified Crypto.Cipher.TripleDES as TripleDES
                fingerprint :: ByteString -> Digest SHA1
                fingerprint = hashWith SHA1
                keys :: IO (PublicKey, PrivateKey)
                keys = RSA.generate 128 65537
                """);
        TestSupport.write(project, "r/report.R", """
                fingerprint <- function(x) {
                  digest::digest(x)
                }
                secure <- digest(x, algo = "sha256")
                key <- openssl::rsa_keygen(1024)
                httr::set_config(httr::config(ssl_verifypeer = 0L))
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
    void cobolIcsfServices() {
        assertThat(namesIn("cobol/PAYCRYPT.cbl")).contains("DES-CBC", "SHA-1").doesNotContain("AES");
        assertThat(occurrence("DES-CBC", "cobol/PAYCRYPT.cbl").function()).isEqualTo("PAYCRYPT.ENCRYPT-CARD");
    }

    @Test
    void abapHashAndHmac() {
        assertThat(namesIn("abap/zcl_crypto.abap")).contains("MD5", "HMAC-SHA-1");
        assertThat(occurrence("MD5", "abap/zcl_crypto.abap").function()).isEqualTo("zcl_crypto.hash");
    }

    @Test
    void luaOpenResty() {
        assertThat(namesIn("lua/auth.lua")).contains("AES-128-ECB", "MD5");
        assertThat(findingsIn("lua/auth.lua")).contains("tls-lua-ssl-verify-off");
    }

    @Test
    void solidityHashesSignaturesAndBlockRandomness() {
        assertThat(namesIn("solidity/Lottery.sol")).anyMatch(n -> n.startsWith("Keccak")).contains("ECDSA");
        assertThat(findingsIn("solidity/Lottery.sol")).contains("random-solidity-block-values");
    }

    @Test
    void apexCryptoClass() {
        assertThat(namesIn("apex/TokenService.cls")).contains("MD5", "AES-128-CBC");
    }

    @Test
    void haskellCryptonite() {
        assertThat(namesIn("haskell/Vault.hs")).contains("SHA-1", "3DES", "RSA-1024");
    }

    @Test
    void rDigestAndOpenssl() {
        assertThat(namesIn("r/report.R")).contains("MD5", "SHA-256", "RSA-1024");
        assertThat(findingsIn("r/report.R")).contains("tls-r-verifypeer-off");
    }
}
