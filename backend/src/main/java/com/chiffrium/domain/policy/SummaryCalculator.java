package com.chiffrium.domain.policy;

import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.model.Library;
import com.chiffrium.domain.model.Occurrence;
import com.chiffrium.domain.model.PolicyStatus;
import com.chiffrium.domain.model.PolicyVerdict;
import com.chiffrium.domain.model.PqcReadiness;
import com.chiffrium.domain.model.Primitive;
import com.chiffrium.domain.model.SecurityFinding;
import com.chiffrium.domain.model.Summary;
import com.chiffrium.domain.model.Vulnerability;

import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Calcule les indicateurs du tableau de bord et le score de sécurité.
 * <p>
 * Score = moyenne des poids de chaque actif x 100. Un projet sans cryptographie obtient 100.
 * Les poids reflètent l'effort de remédiation : un actif recommandé ne coûte rien, un actif
 * interdit coûte tout, un actif vulnérable au quantique est pénalisé même s'il est acceptable.
 * <p>
 * Une clé générée par le code reprend l'algorithme déjà compté au même emplacement : elle figure dans
 * l'inventaire (nombre d'actifs) mais ne pèse pas une seconde fois sur les indicateurs ni sur le score.
 */
public final class SummaryCalculator {

    static final double WEIGHT_RECOMMENDED = 1.0;
    static final double WEIGHT_ACCEPTABLE = 0.85;
    static final double WEIGHT_ACCEPTABLE_QUANTUM_VULNERABLE = 0.7;
    static final double WEIGHT_UNKNOWN = 0.5;
    static final double WEIGHT_DEPRECATED = 0.25;
    static final double WEIGHT_DISALLOWED = 0.0;

    private static final int MAX_SCORE = 100;
    /** Taille exigée par CNSA 2.0 pour le chiffrement symétrique face à Grover. */
    static final int CNSA_SYMMETRIC_BITS = 256;
    private static final Set<Primitive> ASYMMETRIC = EnumSet.of(Primitive.SIGNATURE, Primitive.PUBLIC_KEY_ENCRYPTION,
            Primitive.KEM, Primitive.KEY_AGREEMENT);
    private static final Set<Primitive> SYMMETRIC_CIPHERS = EnumSet.of(Primitive.BLOCK_CIPHER, Primitive.STREAM_CIPHER,
            Primitive.AUTHENTICATED_ENCRYPTION);

    public Summary summarize(List<CryptoAsset> assets, List<Library> libraries) {
        return summarize(assets, libraries, List.of());
    }

    public Summary summarize(List<CryptoAsset> assets, List<Library> libraries, List<SecurityFinding> findings) {
        Map<String, Integer> byStatus = new TreeMap<>();
        Map<String, Integer> byPrimitive = new TreeMap<>();
        Map<String, Integer> byLanguage = new TreeMap<>();
        int quantumVulnerable = 0;
        int postQuantum = 0;
        int symmetricBelow256 = 0;
        int occurrences = 0;

        List<CryptoAsset> counted = assets.stream()
                .filter(a -> a.material() == null || !a.material().generated())
                .toList();
        for (CryptoAsset asset : counted) {
            PolicyVerdict verdict = asset.verdict();
            PolicyStatus status = verdict == null ? PolicyStatus.UNKNOWN : verdict.status();
            byStatus.merge(status.id(), 1, Integer::sum);
            if (asset.algorithm() != null) {
                byPrimitive.merge(asset.algorithm().primitive().cycloneDxValue(), 1, Integer::sum);
            }
            if (verdict != null && verdict.quantumVulnerable()) {
                quantumVulnerable++;
            } else if (asset.algorithm() != null && asset.algorithm().isRecognized()
                    && ASYMMETRIC.contains(asset.algorithm().primitive())) {
                postQuantum++;
            }
            if (asset.algorithm() != null && SYMMETRIC_CIPHERS.contains(asset.algorithm().primitive())
                    && asset.algorithm().keySize() != null && asset.algorithm().keySize() < CNSA_SYMMETRIC_BITS) {
                symmetricBelow256++;
            }
            for (Occurrence occurrence : asset.occurrences()) {
                occurrences++;
                if (occurrence.language() != null) {
                    byLanguage.merge(occurrence.language().id(), 1, Integer::sum);
                }
            }
        }

        int vulnerabilities = libraries.stream().mapToInt(l -> l.vulnerabilities().size()).sum();
        int knownExploited = (int) libraries.stream().flatMap(l -> l.vulnerabilities().stream())
                .filter(Vulnerability::knownExploited).count();
        Map<String, Integer> licenseRisks = new TreeMap<>();
        libraries.forEach(l -> licenseRisks.merge(l.licenseRisk().id(), 1, Integer::sum));
        Map<String, Integer> bySeverity = new TreeMap<>();
        findings.forEach(f -> bySeverity.merge(f.severity().id(), 1, Integer::sum));
        int cryptoLibraries = (int) libraries.stream().filter(Library::cryptoLibrary).count();

        return new Summary(assets.size(), occurrences, byStatus, byPrimitive, byLanguage, quantumVulnerable,
                score(counted), libraries.size(), cryptoLibraries, vulnerabilities, knownExploited, findings.size(),
                bySeverity, PqcReadiness.of(quantumVulnerable, postQuantum, symmetricBelow256), licenseRisks);
    }

    static int score(List<CryptoAsset> assets) {
        if (assets.isEmpty()) {
            return MAX_SCORE;
        }
        double total = assets.stream().mapToDouble(SummaryCalculator::weight).sum();
        return (int) Math.round(MAX_SCORE * total / assets.size());
    }

    private static double weight(CryptoAsset asset) {
        PolicyVerdict verdict = asset.verdict();
        if (verdict == null) {
            return WEIGHT_UNKNOWN;
        }
        return switch (verdict.status()) {
            case RECOMMENDED -> WEIGHT_RECOMMENDED;
            case ACCEPTABLE -> verdict.quantumVulnerable() ? WEIGHT_ACCEPTABLE_QUANTUM_VULNERABLE : WEIGHT_ACCEPTABLE;
            case UNKNOWN -> WEIGHT_UNKNOWN;
            case DEPRECATED -> WEIGHT_DEPRECATED;
            case DISALLOWED -> WEIGHT_DISALLOWED;
        };
    }
}
