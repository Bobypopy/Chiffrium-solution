package com.chiffrium.domain.policy;

import com.chiffrium.domain.model.LicenseRisk;

import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Classe les licences des dépendances par risque juridique. Les correspondances (identifiant SPDX -> risque)
 * sont des données ({@code resources/licenses/license-policy.json}), modifiables sans toucher au code.
 *
 * <p>Expressions SPDX : pour {@code A OR B}, le choix de l'utilisateur est libre, on retient l'option la moins
 * contraignante ; pour {@code A AND B}, toutes s'appliquent, on retient la plus contraignante. Plusieurs licences
 * déclarées séparément sont traitées comme un {@code AND}.
 */
public final class LicensePolicy {

    private static final Pattern OR = Pattern.compile("\\s+OR\\s+", Pattern.CASE_INSENSITIVE);
    private static final Pattern AND = Pattern.compile("\\s+(?:AND|WITH)\\s+", Pattern.CASE_INSENSITIVE);
    private static final Pattern PARENTHESES = Pattern.compile("[()]");

    /**
     * @param pattern motif sur l'identifiant SPDX ou le nom de licence
     * @param risk    risque associé
     */
    public record Rule(Pattern pattern, LicenseRisk risk) {
    }

    private final List<Rule> rules;

    public LicensePolicy(List<Rule> rules) {
        this.rules = List.copyOf(rules);
    }

    public LicenseRisk classify(List<String> licenses) {
        if (licenses == null || licenses.isEmpty()) {
            return LicenseRisk.UNKNOWN;
        }
        return licenses.stream().map(this::classifyExpression).max(Comparator.naturalOrder()).orElse(LicenseRisk.UNKNOWN);
    }

    LicenseRisk classifyExpression(String expression) {
        String flat = PARENTHESES.matcher(expression).replaceAll(" ").strip();
        return Arrays.stream(OR.split(flat))
                .map(alternative -> Arrays.stream(AND.split(alternative)).map(this::classifyOne)
                        .max(Comparator.naturalOrder()).orElse(LicenseRisk.UNKNOWN))
                .min(Comparator.naturalOrder())
                .orElse(LicenseRisk.UNKNOWN);
    }

    private LicenseRisk classifyOne(String license) {
        String id = license.strip();
        return rules.stream().filter(r -> r.pattern().matcher(id).matches()).map(Rule::risk).findFirst()
                .orElse(LicenseRisk.UNKNOWN);
    }
}
