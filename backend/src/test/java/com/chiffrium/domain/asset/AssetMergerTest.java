package com.chiffrium.domain.asset;

import com.chiffrium.TestSupport;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.model.CryptoFunction;
import com.chiffrium.domain.model.DetectionSource;
import com.chiffrium.domain.model.Language;
import com.chiffrium.domain.model.Occurrence;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class AssetMergerTest {

    private static Occurrence occurrence(String file, int line, DetectionSource source, CryptoFunction function) {
        return new Occurrence(file, line, null, null, "snippet", Language.JAVA, source, "rule", Set.of(function));
    }

    @Test
    void sameAlgorithmFromTwoEnginesBecomesOneAssetWithMergedEvidence() {
        CryptoAsset fromRules = TestSupport.ASSETS.fromAlgorithmName("AES/GCM/NoPadding",
                occurrence("A.java", 10, DetectionSource.RULES, CryptoFunction.ENCRYPT), Set.of(CryptoFunction.ENCRYPT),
                DetectionSource.RULES, null);
        CryptoAsset fromCdxgen = TestSupport.ASSETS.fromAlgorithmName("AES/GCM/NoPadding",
                occurrence("A.java", 10, DetectionSource.CDXGEN, CryptoFunction.DECRYPT), Set.of(CryptoFunction.DECRYPT),
                DetectionSource.CDXGEN, "NIST Algorithm");
        CryptoAsset elsewhere = TestSupport.ASSETS.fromAlgorithmName("AES/GCM/NoPadding",
                occurrence("B.java", 3, DetectionSource.RULES, CryptoFunction.ENCRYPT), Set.of(CryptoFunction.ENCRYPT),
                DetectionSource.RULES, null);

        List<CryptoAsset> merged = AssetMerger.merge(List.of(fromRules, fromCdxgen, elsewhere));

        assertThat(merged).hasSize(1);
        CryptoAsset asset = merged.get(0);
        assertThat(asset.sources()).containsExactlyInAnyOrder(DetectionSource.RULES, DetectionSource.CDXGEN);
        assertThat(asset.occurrences()).hasSize(2);
        assertThat(asset.occurrences().get(0).functions())
                .containsExactlyInAnyOrder(CryptoFunction.ENCRYPT, CryptoFunction.DECRYPT);
        assertThat(asset.functions()).containsExactlyInAnyOrder(CryptoFunction.ENCRYPT, CryptoFunction.DECRYPT);
        assertThat(asset.description()).isEqualTo("NIST Algorithm");
    }

    @Test
    void differentParametersStaySeparate() {
        CryptoAsset gcm = TestSupport.ASSETS.fromAlgorithmName("AES/GCM/NoPadding", null, Set.of(),
                DetectionSource.RULES, null);
        CryptoAsset ecb = TestSupport.ASSETS.fromAlgorithmName("AES/ECB/PKCS5Padding", null, Set.of(),
                DetectionSource.RULES, null);
        assertThat(AssetMerger.merge(List.of(gcm, ecb))).hasSize(2);
    }

    @Test
    void mostSpecificDescriptionWinsAtTheSameLocation() {
        CryptoAsset generic = TestSupport.ASSETS.fromAlgorithmName("AES",
                occurrence("A.java", 43, DetectionSource.CDXGEN, CryptoFunction.ENCRYPT), Set.of(),
                DetectionSource.CDXGEN, null);
        CryptoAsset precise = TestSupport.ASSETS.fromAlgorithmName("AES/ECB/PKCS5Padding",
                occurrence("A.java", 43, DetectionSource.RULES, CryptoFunction.ENCRYPT), Set.of(),
                DetectionSource.RULES, null);
        CryptoAsset genericElsewhere = TestSupport.ASSETS.fromAlgorithmName("AES",
                occurrence("B.java", 7, DetectionSource.CDXGEN, CryptoFunction.ENCRYPT), Set.of(),
                DetectionSource.CDXGEN, null);

        List<CryptoAsset> merged = AssetMerger.merge(List.of(generic, precise, genericElsewhere));

        CryptoAsset aes = merged.stream().filter(a -> a.name().equals("AES")).findFirst().orElseThrow();
        assertThat(aes.occurrences()).extracting(Occurrence::file).containsExactly("B.java");
        assertThat(merged).anySatisfy(a -> assertThat(a.name()).isEqualTo("AES-ECB-PKCS7"));
    }

    @Test
    void unlocatedAssetsCoveredByALocatedCompositeAreDropped() {
        CryptoAsset pbkdf2 = TestSupport.ASSETS.fromAlgorithmName("PBKDF2WithHmacSHA256",
                occurrence("A.java", 3, DetectionSource.RULES, CryptoFunction.KEYDERIVE), Set.of(),
                DetectionSource.RULES, null);
        CryptoAsset hmac = TestSupport.ASSETS.fromAlgorithmName("HMAC", null, Set.of(), DetectionSource.CDXGEN, null);
        CryptoAsset sha = TestSupport.ASSETS.fromAlgorithmName("SHA-256", null, Set.of(), DetectionSource.CDXGEN, null);
        CryptoAsset md5 = TestSupport.ASSETS.fromAlgorithmName("MD5", null, Set.of(), DetectionSource.CDXGEN, null);

        assertThat(AssetMerger.merge(List.of(pbkdf2, hmac, sha, md5))).extracting(CryptoAsset::name)
                .containsExactlyInAnyOrder("PBKDF2-HMAC-SHA-256", "MD5");
    }

    @Test
    void functionHintsIgnoreHashCode() {
        assertThat(CryptoFunctionHints.fromCallName("generateKeyPair")).containsExactly(CryptoFunction.KEYGEN);
        assertThat(CryptoFunctionHints.fromCallName("decryptAES")).containsExactly(CryptoFunction.DECRYPT);
        assertThat(CryptoFunctionHints.fromCallName("generateSecret")).containsExactly(CryptoFunction.KEYDERIVE);
        assertThat(CryptoFunctionHints.fromCallName("hashCode")).isEmpty();
        assertThat(CryptoFunctionHints.fromCallName(null)).isEmpty();
    }
}
