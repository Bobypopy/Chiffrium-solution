package com.chiffrium.domain.policy;

import com.chiffrium.domain.model.AnalysisReport;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.model.Library;
import com.chiffrium.domain.model.PolicyStatus;
import com.chiffrium.domain.model.SecurityFinding;
import com.chiffrium.domain.model.Vulnerability;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * Dérive entre deux analyses (en général le même dépôt à deux dates) : actifs apparus ou disparus,
 * changements de statut, nouveaux constats et constats corrigés, vulnérabilités apparues ou corrigées.
 *
 * <p>Les constats sont rapprochés par règle, fichier et contenu de la ligne (et non par numéro de ligne), pour
 * qu'un simple décalage de code ne les fasse pas passer pour "corrigés puis nouveaux".
 */
public final class ReportComparator {

    private static final Pattern OID_SUFFIX = Pattern.compile("@[0-2](\\.\\d+)+$");

    /**
     * @param bomRef identifiant stable de l'actif
     * @param status statut de politique (null si non évalué)
     */
    public record AssetRef(String bomRef, String name, PolicyStatus status) {
    }

    public record StatusChange(String bomRef, String name, PolicyStatus before, PolicyStatus after) {
    }

    public record VulnerabilityRef(String library, String id, String severity, boolean knownExploited) {
    }

    /**
     * @param baseId          analyse de référence (la plus ancienne en général)
     * @param targetId        analyse comparée
     * @param baseDate        date de la référence
     * @param targetDate      date de l'analyse comparée
     * @param baseScore       score de référence
     * @param targetScore     score comparé
     * @param basePqcStage    étape post-quantique de référence
     * @param targetPqcStage  étape post-quantique comparée
     */
    public record Comparison(String baseId, String targetId, Instant baseDate, Instant targetDate, int baseScore,
                             int targetScore, String basePqcStage, String targetPqcStage, List<AssetRef> assetsAdded,
                             List<AssetRef> assetsRemoved, List<StatusChange> statusChanges,
                             List<SecurityFinding> findingsNew, List<SecurityFinding> findingsResolved,
                             List<VulnerabilityRef> vulnerabilitiesNew, List<VulnerabilityRef> vulnerabilitiesFixed) {

        @JsonProperty("scoreDelta")
        public int scoreDelta() {
            return targetScore - baseScore;
        }
    }

    public Comparison compare(AnalysisReport base, AnalysisReport target) {
        Map<String, CryptoAsset> before = index(base.assets(), ReportComparator::assetKey);
        Map<String, CryptoAsset> after = index(target.assets(), ReportComparator::assetKey);
        List<AssetRef> added = new ArrayList<>();
        List<AssetRef> removed = new ArrayList<>();
        List<StatusChange> changes = new ArrayList<>();
        after.forEach((ref, asset) -> {
            CryptoAsset previous = before.get(ref);
            if (previous == null) {
                added.add(ref(asset));
            } else if (status(previous) != status(asset)) {
                changes.add(new StatusChange(asset.bomRef(), asset.name(), status(previous), status(asset)));
            }
        });
        before.forEach((ref, asset) -> {
            if (!after.containsKey(ref)) {
                removed.add(ref(asset));
            }
        });

        Map<String, SecurityFinding> findingsBefore = index(base.findings(), ReportComparator::findingKey);
        Map<String, SecurityFinding> findingsAfter = index(target.findings(), ReportComparator::findingKey);
        Map<String, VulnerabilityRef> vulnerabilitiesBefore = vulnerabilities(base.libraries());
        Map<String, VulnerabilityRef> vulnerabilitiesAfter = vulnerabilities(target.libraries());

        return new Comparison(base.analysisId(), target.analysisId(), base.generatedAt(), target.generatedAt(),
                base.summary().score(), target.summary().score(), pqcStage(base), pqcStage(target), added, removed,
                changes, missingFrom(findingsAfter, findingsBefore), missingFrom(findingsBefore, findingsAfter),
                missingFrom(vulnerabilitiesAfter, vulnerabilitiesBefore),
                missingFrom(vulnerabilitiesBefore, vulnerabilitiesAfter));
    }

    /**
     * Clé de rapprochement d'un actif : son bom-ref sans l'OID final ("crypto/algorithm/AES-256-GCM@2.16..."), pour
     * qu'un OID corrigé par une version plus récente du catalogue ne fasse pas apparaître un nouvel actif.
     */
    static String assetKey(CryptoAsset asset) {
        return OID_SUFFIX.matcher(asset.bomRef()).replaceFirst("");
    }

    /** Clé de rapprochement d'un constat, indépendante du numéro de ligne. */
    static String findingKey(SecurityFinding finding) {
        String content = finding.snippet() == null ? Objects.toString(finding.evidence(), "")
                : finding.snippet().replaceAll("\\s+", " ").strip();
        return finding.ruleId() + '\u0000' + finding.file() + '\u0000' + content;
    }

    private static Map<String, VulnerabilityRef> vulnerabilities(List<Library> libraries) {
        Map<String, VulnerabilityRef> result = new LinkedHashMap<>();
        for (Library library : libraries) {
            String name = library.group() == null ? library.name() : library.group() + "/" + library.name();
            for (Vulnerability v : library.vulnerabilities()) {
                result.putIfAbsent(name + '\u0000' + v.id(), new VulnerabilityRef(name, v.id(), v.severity(),
                        v.knownExploited()));
            }
        }
        return result;
    }

    private static <T> List<T> missingFrom(Map<String, T> source, Map<String, T> reference) {
        return source.entrySet().stream().filter(e -> !reference.containsKey(e.getKey())).map(Map.Entry::getValue)
                .toList();
    }

    private static <T> Map<String, T> index(List<T> items, Function<T, String> key) {
        Map<String, T> result = new LinkedHashMap<>();
        items.forEach(item -> result.putIfAbsent(key.apply(item), item));
        return result;
    }

    private static AssetRef ref(CryptoAsset asset) {
        return new AssetRef(asset.bomRef(), asset.name(), status(asset));
    }

    private static PolicyStatus status(CryptoAsset asset) {
        return asset.verdict() == null ? null : asset.verdict().status();
    }

    private static String pqcStage(AnalysisReport report) {
        return report.summary().pqc() == null ? null : report.summary().pqc().stage().id();
    }
}
