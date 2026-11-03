package com.chiffrium.domain.policy;

import com.chiffrium.TestSupport;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.model.CryptoFunction;
import com.chiffrium.domain.model.DetectionSource;
import com.chiffrium.domain.model.Language;
import com.chiffrium.domain.model.Library;
import com.chiffrium.domain.model.Occurrence;
import com.chiffrium.domain.model.Summary;
import com.chiffrium.domain.model.Vulnerability;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class SummaryCalculatorTest {

    private final PolicyEvaluator evaluator = new PolicyEvaluator(TestSupport.CATALOG, TestSupport.clockAt(2026));
    private final SummaryCalculator calculator = new SummaryCalculator();

    private CryptoAsset evaluated(String raw) {
        Occurrence occurrence = new Occurrence("A.java", 1, 1, null, null, Language.JAVA, DetectionSource.RULES,
                "test", Set.of(CryptoFunction.DIGEST));
        return evaluator.evaluate(TestSupport.ASSETS.fromAlgorithmName(raw, occurrence, Set.of(), DetectionSource.RULES,
                null));
    }

    @Test
    void emptyProjectScoresMaximum() {
        Summary summary = calculator.summarize(List.of(), List.of());
        assertThat(summary.score()).isEqualTo(100);
        assertThat(summary.totalAssets()).isZero();
    }

    @Test
    void scoreAveragesAssetWeights() {
        Summary summary = calculator.summarize(List.of(evaluated("SHA-256"), evaluated("MD5")), List.of());
        long expected = Math.round(100 * (SummaryCalculator.WEIGHT_RECOMMENDED + SummaryCalculator.WEIGHT_DISALLOWED) / 2);
        assertThat(summary.score()).isEqualTo((int) expected);
        assertThat(summary.byStatus()).containsEntry("recommended", 1).containsEntry("disallowed", 1);
        assertThat(summary.byPrimitive()).containsEntry("hash", 2);
        assertThat(summary.byLanguage()).containsEntry("java", 2);
        assertThat(summary.totalOccurrences()).isEqualTo(2);
    }

    @Test
    void countsQuantumVulnerableAssetsAndLibraryVulnerabilities() {
        Library vulnerable = new Library("ref", "pkg:maven/org.bouncycastle/bcprov-jdk15on@1.60", "org.bouncycastle",
                "bcprov-jdk15on", "1.60", "required", true,
                List.of(new Vulnerability("GHSA-1", "test", "HIGH", List.of("CVE-1"), "url")));
        Summary summary = calculator.summarize(List.of(evaluated("RSA")), List.of(vulnerable));
        assertThat(summary.quantumVulnerable()).isEqualTo(1);
        assertThat(summary.vulnerabilities()).isEqualTo(1);
        assertThat(summary.cryptoLibraries()).isEqualTo(1);
    }
}
