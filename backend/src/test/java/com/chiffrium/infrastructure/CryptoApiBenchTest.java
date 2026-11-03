package com.chiffrium.infrastructure;

import com.chiffrium.TestSupport;
import com.chiffrium.application.port.CryptoDetector.DetectionContext;
import com.chiffrium.application.port.SbomGenerator.SbomResult;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.model.FindingCategory;
import com.chiffrium.domain.model.PolicyStatus;
import com.chiffrium.domain.model.Primitive;
import com.chiffrium.domain.model.SecurityFinding;
import com.chiffrium.domain.policy.PolicyEvaluator;
import com.chiffrium.infrastructure.findings.FindingRuleLoader;
import com.chiffrium.infrastructure.findings.SecurityFindingDetector;
import com.chiffrium.infrastructure.rules.RuleBasedCryptoDetector;
import com.chiffrium.infrastructure.rules.RulePackLoader;
import com.chiffrium.infrastructure.scan.FileSystemProjectScanner;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Predicate;

import static java.util.Map.entry;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Mesure de la détection sur CryptoAPI-Bench (Afrose et al., SecDev 2019 ; licence MIT), banc d'essai public de
 * mauvais usages cryptographiques en Java. Un fichier "Corrected" ne doit rien déclencher ; tous les autres
 * contiennent la faiblesse de leur catégorie. Les cas "AB..." (valeur transmise entre méthodes, champs ou
 * classes) demandent une analyse de flux que l'outil ne fait pas : le rappel reste donc partiel, et ce test
 * empêche surtout qu'il baisse.
 *
 * <p>Lancé par la campagne nocturne, avec {@code CRYPTOAPI_BENCH} = dossier {@code src/main/java/org/cryptoapi}
 * d'un clone du dépôt.
 */
@EnabledIfEnvironmentVariable(named = "CRYPTOAPI_BENCH", matches = ".+")
class CryptoApiBenchTest {

    /** Valeurs mesurées en version 1.0.8 : à relever quand la détection progresse, jamais à baisser. */
    private static final int MIN_DETECTED = 81;
    private static final int MAX_FALSE_ALARMS = 1;

    private static final Set<PolicyStatus> WEAK = Set.of(PolicyStatus.DISALLOWED, PolicyStatus.DEPRECATED);

    private static Predicate<CryptoAsset> weak(Primitive... primitives) {
        Set<Primitive> wanted = Set.of(primitives);
        return a -> WEAK.contains(a.verdict().status()) && a.algorithm() != null && wanted.contains(a.algorithm().primitive());
    }

    private static final Map<String, Predicate<CryptoAsset>> BY_ASSET = Map.ofEntries(
            entry("brokencrypto", weak(Primitive.BLOCK_CIPHER, Primitive.STREAM_CIPHER)),
            entry("brokenhash", weak(Primitive.HASH)),
            entry("brokenmac", weak(Primitive.MAC)),
            entry("ecbcrypto", a -> a.algorithm() != null && "ECB".equals(a.algorithm().mode())),
            entry("insecureasymmetriccrypto", a -> WEAK.contains(a.verdict().status()) && a.algorithm() != null
                    && a.algorithm().keySize() != null));

    private static final Map<String, FindingCategory> BY_FINDING = Map.ofEntries(
            entry("credentialinstring", FindingCategory.SECRET),
            entry("predictablekeystorepassword", FindingCategory.SECRET),
            entry("predictablepbepassword", FindingCategory.SECRET),
            entry("predictablecryptographickey", FindingCategory.HARDCODED_KEY_MATERIAL),
            entry("staticinitializationvector", FindingCategory.HARDCODED_KEY_MATERIAL),
            entry("staticsalts", FindingCategory.HARDCODED_KEY_MATERIAL),
            entry("pbeiteration", FindingCategory.WEAK_KEY_DERIVATION),
            entry("predictableseeds", FindingCategory.WEAK_RANDOM),
            entry("untrustedprng", FindingCategory.WEAK_RANDOM),
            entry("dummycertvalidation", FindingCategory.CERTIFICATE_VALIDATION),
            entry("dummyhostnameverifier", FindingCategory.CERTIFICATE_VALIDATION),
            entry("impropersslsocketfactory", FindingCategory.CERTIFICATE_VALIDATION));

    @Test
    void detectionDoesNotRegress() {
        Path root = Path.of(System.getenv("CRYPTOAPI_BENCH"));
        var scan = new FileSystemProjectScanner(2_000_000).scan(root);
        DetectionContext context = new DetectionContext(root, scan, SbomResult.empty());
        PolicyEvaluator evaluator = new PolicyEvaluator(TestSupport.CATALOG, TestSupport.clockAt(2026));
        List<CryptoAsset> assets = new RuleBasedCryptoDetector(new RulePackLoader(TestSupport.MAPPER).loadBuiltIn(),
                TestSupport.ASSETS).detect(context).assets().stream().map(evaluator::evaluate).toList();
        List<SecurityFinding> findings = new SecurityFindingDetector(
                new FindingRuleLoader(TestSupport.MAPPER).loadBuiltIn()).detect(context).findings();

        // Par catégorie : vrais cas trouvés, ratés, fausses alertes, cas sûrs laissés tranquilles.
        Map<String, int[]> counts = new TreeMap<>();
        for (var file : scan.files()) {
            String[] parts = file.path().split("/");
            if (parts.length < 3 || !parts[0].equals("bench")) {
                continue;
            }
            String category = parts[1];
            String path = file.path();
            boolean hit;
            if (BY_ASSET.containsKey(category)) {
                hit = assets.stream().anyMatch(a -> BY_ASSET.get(category).test(a)
                        && a.occurrences().stream().anyMatch(o -> o.file().equals(path)));
            } else if (BY_FINDING.containsKey(category)) {
                hit = findings.stream().anyMatch(f -> f.file().equals(path) && f.category() == BY_FINDING.get(category));
            } else {
                continue;
            }
            boolean secure = parts[2].contains("Corrected");
            counts.computeIfAbsent(category, k -> new int[4])[(secure ? 2 : 0) + (hit ? 0 : 1)]++;
        }
        int detected = counts.values().stream().mapToInt(c -> c[0]).sum();
        int missed = counts.values().stream().mapToInt(c -> c[1]).sum();
        int falseAlarms = counts.values().stream().mapToInt(c -> c[2]).sum();
        counts.forEach((category, c) -> System.out.printf("%-28s trouvés %3d  ratés %3d  fausses alertes %d%n",
                category, c[0], c[1], c[2]));
        System.out.printf("CryptoAPI-Bench : %d/%d cas trouvés (%.0f %%), %d fausse(s) alerte(s)%n",
                detected, detected + missed, 100.0 * detected / (detected + missed), falseAlarms);

        assertThat(detected).isGreaterThanOrEqualTo(MIN_DETECTED);
        assertThat(falseAlarms).isLessThanOrEqualTo(MAX_FALSE_ALARMS);
    }
}
