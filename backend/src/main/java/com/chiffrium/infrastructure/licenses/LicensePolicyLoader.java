package com.chiffrium.infrastructure.licenses;

import com.chiffrium.domain.model.LicenseRisk;
import com.chiffrium.domain.policy.LicensePolicy;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Charge la politique de licences embarquée ({@code resources/licenses/license-policy.json}).
 */
public final class LicensePolicyLoader {

    private static final String RESOURCE = "/licenses/license-policy.json";

    record Document(String comment, List<RuleDocument> rules) {
    }

    record RuleDocument(String pattern, String risk) {
    }

    private LicensePolicyLoader() {
    }

    public static LicensePolicy loadBuiltIn(ObjectMapper mapper) {
        try (InputStream in = LicensePolicyLoader.class.getResourceAsStream(RESOURCE)) {
            if (in == null) {
                throw new IllegalStateException("Ressource absente : " + RESOURCE);
            }
            Document document = mapper.readValue(in, Document.class);
            return new LicensePolicy(document.rules().stream()
                    .map(r -> new LicensePolicy.Rule(Pattern.compile(r.pattern()), LicenseRisk.fromId(r.risk())))
                    .toList());
        } catch (IOException e) {
            throw new UncheckedIOException("Lecture impossible : " + RESOURCE, e);
        }
    }
}
