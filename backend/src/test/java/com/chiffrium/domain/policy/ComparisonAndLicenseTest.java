package com.chiffrium.domain.policy;

import com.chiffrium.TestSupport;
import com.chiffrium.domain.model.AnalysisReport;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.model.FindingCategory;
import com.chiffrium.domain.model.Library;
import com.chiffrium.domain.model.LicenseRisk;
import com.chiffrium.domain.model.PolicyStatus;
import com.chiffrium.domain.model.PolicyVerdict;
import com.chiffrium.domain.model.SecurityFinding;
import com.chiffrium.domain.model.Severity;
import com.chiffrium.domain.model.Vulnerability;
import com.chiffrium.infrastructure.licenses.LicensePolicyLoader;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ComparisonAndLicenseTest {

    private static CryptoAsset asset(String ref, PolicyStatus status) {
        return new CryptoAsset(ref, ref.toUpperCase(), null, null, null, null, null, null, List.of(),
                new PolicyVerdict(status, Severity.NONE, false, List.of(), null, null));
    }

    private static SecurityFinding finding(String rule, int line, String snippet) {
        return new SecurityFinding(rule + line, rule, FindingCategory.SECRET, Severity.HIGH, "t", null, "r", null,
                "src/A.java", line, 1, snippet, null, null, false);
    }

    private static Library library(String name, String... vulnerabilities) {
        return new Library(name, "pkg:npm/" + name + "@1", null, name, "1", null, false,
                java.util.Arrays.stream(vulnerabilities).map(v -> new Vulnerability(v, null, null, List.of(), null))
                        .toList());
    }

    private static AnalysisReport report(String id, List<CryptoAsset> assets, List<SecurityFinding> findings,
                                         List<Library> libraries) {
        return new AnalysisReport(AnalysisReport.CURRENT_SCHEMA_VERSION, id, Instant.now(), null, null,
                new SummaryCalculator().summarize(assets, libraries, findings), assets, libraries, findings, null,
                null, null);
    }

    @Test
    void comparisonReportsDriftAndIgnoresShiftedLines() {
        AnalysisReport before = report("a", List.of(asset("md5", PolicyStatus.DISALLOWED), asset("rsa", PolicyStatus.ACCEPTABLE)),
                List.of(finding("secret-x", 10, "token = \"abc...\""), finding("secret-y", 3, "old")),
                List.of(library("lodash", "GHSA-1")));
        AnalysisReport after = report("b", List.of(asset("rsa", PolicyStatus.DEPRECATED), asset("ml-kem", PolicyStatus.RECOMMENDED)),
                List.of(finding("secret-x", 42, "token  =  \"abc...\""), finding("secret-z", 7, "new")),
                List.of(library("lodash", "GHSA-2")));

        ReportComparator.Comparison diff = new ReportComparator().compare(before, after);

        assertThat(diff.assetsAdded()).extracting(ReportComparator.AssetRef::bomRef).containsExactly("ml-kem");
        assertThat(diff.assetsRemoved()).extracting(ReportComparator.AssetRef::bomRef).containsExactly("md5");
        assertThat(diff.statusChanges()).singleElement().extracting(ReportComparator.StatusChange::after)
                .isEqualTo(PolicyStatus.DEPRECATED);
        assertThat(diff.findingsNew()).extracting(SecurityFinding::ruleId).containsExactly("secret-z");
        assertThat(diff.findingsResolved()).extracting(SecurityFinding::ruleId).containsExactly("secret-y");
        assertThat(diff.vulnerabilitiesNew()).extracting(ReportComparator.VulnerabilityRef::id).containsExactly("GHSA-2");
        assertThat(diff.vulnerabilitiesFixed()).extracting(ReportComparator.VulnerabilityRef::id).containsExactly("GHSA-1");
    }

    @Test
    void licenseRiskFollowsSpdxExpressions() {
        LicensePolicy policy = LicensePolicyLoader.loadBuiltIn(TestSupport.MAPPER);
        assertThat(policy.classify(List.of("MIT"))).isEqualTo(LicenseRisk.PERMISSIVE);
        assertThat(policy.classify(List.of("LGPL-2.1-only"))).isEqualTo(LicenseRisk.WEAK_COPYLEFT);
        assertThat(policy.classify(List.of("AGPL-3.0-or-later"))).isEqualTo(LicenseRisk.STRONG_COPYLEFT);
        assertThat(policy.classify(List.of("GPL-2.0 OR MIT"))).as("choix libre").isEqualTo(LicenseRisk.PERMISSIVE);
        assertThat(policy.classify(List.of("(MIT AND GPL-3.0)"))).isEqualTo(LicenseRisk.STRONG_COPYLEFT);
        assertThat(policy.classify(List.of("Apache-2.0", "MPL-2.0"))).isEqualTo(LicenseRisk.WEAK_COPYLEFT);
        assertThat(policy.classify(List.of("Licence maison"))).isEqualTo(LicenseRisk.UNKNOWN);
        assertThat(policy.classify(List.of())).isEqualTo(LicenseRisk.UNKNOWN);
    }
}
