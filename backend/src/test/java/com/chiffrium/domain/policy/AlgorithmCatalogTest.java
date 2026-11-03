package com.chiffrium.domain.policy;

import com.chiffrium.TestSupport;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class AlgorithmCatalogTest {

    private final AlgorithmCatalog catalog = TestSupport.CATALOG;

    @Test
    void defaultCatalogIsValid() {
        assertThat(catalog.validate()).isEmpty();
        assertThat(catalog.algorithms()).hasSizeGreaterThan(80);
    }

    @Test
    void noAliasIsSharedBetweenTwoAlgorithms() {
        Map<String, String> owners = new HashMap<>();
        List<String> collisions = new ArrayList<>();
        for (AlgorithmDefinition def : catalog.algorithms()) {
            List<String> keys = new ArrayList<>(def.aliases());
            keys.addAll(def.tokens());
            for (String alias : keys) {
                String previous = owners.putIfAbsent(alias, def.id());
                if (previous != null && !previous.equals(def.id())) {
                    collisions.add(alias + " : " + previous + " / " + def.id());
                }
            }
        }
        assertThat(collisions).isEmpty();
    }

    @Test
    void findsDefinitionByOid() {
        assertThat(catalog.findByOid("1.2.840.113549.2.5")).get().extracting(AlgorithmDefinition::id).isEqualTo("md5");
        assertThat(catalog.findByOid("9.9.9")).isEmpty();
    }

    @Test
    void validationReportsMalformedEntries() {
        AlgorithmDefinition broken = new AlgorithmDefinition("Bad Id", "", null, null, List.of("With-Dash"),
                List.of(), List.of(new AlgorithmDefinition.OidRef("abc", null)), null, false, null, null, null,
                null, null, null);
        List<String> errors = catalog.withAlgorithm(broken).validate();
        assertThat(errors).anyMatch(e -> e.contains("identifiant invalide"))
                .anyMatch(e -> e.contains("nom obligatoire"))
                .anyMatch(e -> e.contains("alias"))
                .anyMatch(e -> e.contains("OID invalide"));
    }

    @Test
    void withAlgorithmReplacesExistingEntry() {
        AlgorithmDefinition md5 = catalog.findAlgorithm("md5").orElseThrow();
        AlgorithmDefinition changed = new AlgorithmDefinition(md5.id(), "MD5 modifié", md5.primitive(),
                md5.assetType(), md5.aliases(), md5.tokens(), md5.oids(), md5.status(), false, md5.keySizeRules(),
                null, null, "note", null, List.of());
        AlgorithmCatalog updated = catalog.withAlgorithm(changed);
        assertThat(updated.algorithms()).hasSameSizeAs(catalog.algorithms());
        assertThat(updated.findAlgorithm("md5")).get().extracting(AlgorithmDefinition::name).isEqualTo("MD5 modifié");
    }
}
