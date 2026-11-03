package com.chiffrium.infrastructure.sarif;

import com.chiffrium.application.port.AnalysisRepository.Artifact;
import com.chiffrium.application.port.ReportExporter;
import com.chiffrium.domain.model.AnalysisReport;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.model.Occurrence;
import com.chiffrium.domain.model.PolicyVerdict;
import com.chiffrium.domain.model.SecurityFinding;
import com.chiffrium.domain.model.Severity;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Export SARIF 2.1.0 (OASIS) : constats de sécurité et actifs cryptographiques non conformes, lisibles par
 * GitHub Code Scanning, GitLab, Azure DevOps, SonarQube ou les IDE.
 *
 * <p>Niveaux : critique/élevé -> error, moyen -> warning, faible/info -> note. La propriété
 * {@code security-severity} suit l'échelle CVSS utilisée par GitHub pour trier les alertes.
 */
public final class SarifReportExporter implements ReportExporter {

    static final String SARIF_VERSION = "2.1.0";
    static final String SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";
    static final String TOOL_NAME = "Chiffrium";
    static final String FINGERPRINT_KEY = "chiffrium/v1";
    private static final String POLICY_RULE_PREFIX = "crypto-policy/";
    private static final String QUANTUM_RULE = POLICY_RULE_PREFIX + "quantum-vulnerable";

    private final ObjectMapper mapper;

    public SarifReportExporter(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public Artifact artifact() {
        return Artifact.SARIF;
    }

    @Override
    public void export(AnalysisReport report, Path target) {
        try {
            mapper.writerWithDefaultPrettyPrinter().writeValue(target.toFile(), toSarif(report));
        } catch (IOException e) {
            throw new UncheckedIOException("Écriture SARIF impossible : " + target, e);
        }
    }

    ObjectNode toSarif(AnalysisReport report) {
        Map<String, ObjectNode> rules = new LinkedHashMap<>();
        ArrayNode results = mapper.createArrayNode();
        for (SecurityFinding finding : report.findings()) {
            rules.computeIfAbsent(finding.ruleId(), id -> findingRule(finding));
            ObjectNode result = result(finding.ruleId(), finding.severity(),
                    finding.title() + (finding.evidence() == null ? "" : " : " + finding.evidence()),
                    finding.file(), finding.line(), finding.column());
            result.putObject("partialFingerprints").put(FINGERPRINT_KEY, finding.id());
            results.add(result);
        }
        for (CryptoAsset asset : report.assets()) {
            PolicyVerdict verdict = asset.verdict();
            if (verdict == null) {
                continue;
            }
            String ruleId;
            if (verdict.status().isProblematic()) {
                ruleId = POLICY_RULE_PREFIX + verdict.status().id();
            } else if (verdict.quantumVulnerable()) {
                ruleId = QUANTUM_RULE;
            } else {
                continue;
            }
            rules.computeIfAbsent(ruleId, id -> policyRule(id, verdict));
            String message = asset.name() + " : " + String.join(" ", verdict.reasons())
                    + (verdict.recommendation() == null ? "" : " -> " + verdict.recommendation());
            Severity severity = ruleId.equals(QUANTUM_RULE) ? Severity.LOW : verdict.severity();
            for (Occurrence occurrence : asset.occurrences()) {
                if (occurrence.file() != null) {
                    results.add(result(ruleId, severity, message, occurrence.file(), occurrence.line(),
                            occurrence.column()));
                }
            }
        }

        ObjectNode root = mapper.createObjectNode();
        root.put("$schema", SARIF_SCHEMA);
        root.put("version", SARIF_VERSION);
        ObjectNode run = root.putArray("runs").addObject();
        ObjectNode driver = run.putObject("tool").putObject("driver");
        driver.put("name", TOOL_NAME);
        driver.put("version", report.toolVersions().getOrDefault("chiffrium", "dev"));
        ArrayNode ruleArray = driver.putArray("rules");
        rules.values().forEach(ruleArray::add);
        if (report.source() != null && report.source().commit() != null) {
            ObjectNode provenance = run.putArray("versionControlProvenance").addObject();
            provenance.put("repositoryUri", report.source().target());
            provenance.put("revisionId", report.source().commit());
            if (report.source().branch() != null) {
                provenance.put("branch", report.source().branch());
            }
        }
        run.set("results", results);
        return root;
    }

    private ObjectNode findingRule(SecurityFinding finding) {
        ObjectNode rule = mapper.createObjectNode();
        rule.put("id", finding.ruleId());
        rule.put("name", finding.category().label());
        rule.putObject("shortDescription").put("text", finding.title());
        if (finding.description() != null) {
            rule.putObject("fullDescription").put("text", finding.description());
        }
        rule.putObject("help").put("text", finding.recommendation());
        rule.putObject("defaultConfiguration").put("level", level(finding.severity()));
        ObjectNode properties = rule.putObject("properties");
        ArrayNode tags = properties.putArray("tags").add("security").add(finding.category().id());
        if (finding.cwe() != null) {
            tags.add("external/cwe/" + finding.cwe().toLowerCase(Locale.ROOT));
        }
        properties.put("security-severity", securitySeverity(finding.severity()));
        return rule;
    }

    private ObjectNode policyRule(String id, PolicyVerdict verdict) {
        ObjectNode rule = mapper.createObjectNode();
        rule.put("id", id);
        boolean quantum = id.equals(QUANTUM_RULE);
        rule.putObject("shortDescription").put("text", quantum
                ? "Algorithme vulnérable à un ordinateur quantique (Shor)"
                : "Algorithme cryptographique " + verdict.status().id() + " par la politique");
        rule.putObject("help").put("text", quantum
                ? "Planifier la migration vers ML-KEM / ML-DSA (FIPS 203/204), idéalement en mode hybride."
                : "Remplacer l'algorithme selon la recommandation du catalogue.");
        Severity severity = quantum ? Severity.LOW : verdict.severity();
        rule.putObject("defaultConfiguration").put("level", level(severity));
        ObjectNode properties = rule.putObject("properties");
        properties.putArray("tags").add("security").add("cryptography");
        properties.put("security-severity", securitySeverity(severity));
        return rule;
    }

    private ObjectNode result(String ruleId, Severity severity, String message, String file, Integer line,
                              Integer column) {
        ObjectNode result = mapper.createObjectNode();
        result.put("ruleId", ruleId);
        result.put("level", level(severity));
        result.putObject("message").put("text", message);
        ObjectNode physical = result.putArray("locations").addObject().putObject("physicalLocation");
        physical.putObject("artifactLocation").put("uri", file);
        if (line != null && line > 0) {
            ObjectNode region = physical.putObject("region");
            region.put("startLine", line);
            if (column != null && column > 0) {
                region.put("startColumn", column);
            }
        }
        return result;
    }

    static String level(Severity severity) {
        return switch (severity) {
            case CRITICAL, HIGH -> "error";
            case MEDIUM -> "warning";
            default -> "note";
        };
    }

    /** Échelle CVSS attendue par GitHub : >= 9 critique, >= 7 élevé, >= 4 moyen, sinon faible. */
    static String securitySeverity(Severity severity) {
        return switch (severity) {
            case CRITICAL -> "9.5";
            case HIGH -> "8.0";
            case MEDIUM -> "5.5";
            case LOW -> "3.0";
            default -> "1.0";
        };
    }
}
