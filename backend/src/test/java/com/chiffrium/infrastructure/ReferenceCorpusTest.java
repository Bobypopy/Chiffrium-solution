package com.chiffrium.infrastructure;

import com.chiffrium.TestSupport;
import com.chiffrium.application.port.CryptoDetector.DetectionContext;
import com.chiffrium.application.port.SbomGenerator.SbomResult;
import com.chiffrium.domain.asset.AssetMerger;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.policy.PolicyEvaluator;
import com.chiffrium.infrastructure.binary.BinaryCryptoDetector;
import com.chiffrium.infrastructure.binary.BinarySignatures;
import com.chiffrium.infrastructure.findings.FindingRuleLoader;
import com.chiffrium.infrastructure.findings.SecurityFindingDetector;
import com.chiffrium.infrastructure.material.MaterialDetector;
import com.chiffrium.infrastructure.rules.RuleBasedCryptoDetector;
import com.chiffrium.infrastructure.rules.RulePack;
import com.chiffrium.infrastructure.rules.RulePackLoader;
import com.chiffrium.infrastructure.scan.FileSystemProjectScanner;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Corpus de référence ({@code src/test/resources/reference}) : un petit projet par langage, avec de la
 * cryptographie faible, correcte et des pièges. Le résultat exact (actif, emplacement et statut ; constat,
 * emplacement et gravité) est comparé à {@code expected.txt} : une perte comme une nouvelle alerte fait échouer
 * le test, ce que la campagne nocturne (au moins N-1 algorithmes par projet) laissait passer.
 *
 * <p>Après une évolution voulue de la détection : {@code CHIFFRIUM_UPDATE_REFERENCE=1 mvn test
 * -Dtest=ReferenceCorpusTest}, puis relire la différence de {@code expected.txt} avant de la valider.
 */
class ReferenceCorpusTest {

    private static final Path CORPUS = Path.of("src/test/resources/reference");
    private static final Path EXPECTED = CORPUS.resolve("expected.txt");

    @Test
    void detectionMatchesTheReference() throws IOException {
        List<String> actual = inventory();
        if (System.getenv("CHIFFRIUM_UPDATE_REFERENCE") != null) {
            Files.write(EXPECTED, actual, StandardCharsets.UTF_8);
        }
        List<String> expected = Files.readAllLines(EXPECTED, StandardCharsets.UTF_8).stream()
                .filter(line -> !line.isBlank()).toList();
        List<String> missing = expected.stream().filter(line -> !actual.contains(line)).toList();
        List<String> unexpected = actual.stream().filter(line -> !expected.contains(line)).toList();
        assertThat(missing).as("détections perdues").isEmpty();
        assertThat(unexpected).as("détections nouvelles (à vérifier puis ajouter à expected.txt)").isEmpty();
    }

    /** Une ligne par emplacement d'actif ("A fichier:ligne nom statut") et par constat ("F fichier:ligne règle gravité"). */
    private static List<String> inventory() {
        var scan = new FileSystemProjectScanner(2_000_000).scan(CORPUS);
        DetectionContext context = new DetectionContext(CORPUS, scan, SbomResult.empty());
        List<RulePack> packs = new RulePackLoader(TestSupport.MAPPER).loadBuiltIn();
        List<CryptoAsset> detected = new ArrayList<>();
        detected.addAll(new RuleBasedCryptoDetector(packs, TestSupport.ASSETS).detect(context).assets());
        detected.addAll(new MaterialDetector(TestSupport.ASSETS).detect(context).assets());
        detected.addAll(new BinaryCryptoDetector(TestSupport.ASSETS, BinarySignatures.loadBuiltIn(TestSupport.MAPPER))
                .detect(context).assets());
        PolicyEvaluator evaluator = new PolicyEvaluator(TestSupport.CATALOG, TestSupport.clockAt(2026));
        TreeSet<String> lines = new TreeSet<>();
        for (CryptoAsset asset : AssetMerger.merge(detected).stream().map(evaluator::evaluate).toList()) {
            asset.occurrences().forEach(o -> lines.add("A " + o.file() + ":" + o.line() + " " + asset.name() + " "
                    + asset.verdict().status().id()));
        }
        new SecurityFindingDetector(new FindingRuleLoader(TestSupport.MAPPER).loadBuiltIn(), packs).detect(context)
                .findings().forEach(f -> lines.add("F " + f.file() + ":" + f.line() + " " + f.ruleId() + " "
                        + f.severity().id()));
        lines.removeIf(line -> line.contains(" README.md:"));
        return new ArrayList<>(lines);
    }
}
