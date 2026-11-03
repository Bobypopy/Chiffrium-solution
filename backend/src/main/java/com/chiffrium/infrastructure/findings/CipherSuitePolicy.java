package com.chiffrium.infrastructure.findings;

import com.chiffrium.domain.model.Severity;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Évalue une suite de chiffrement TLS, au format IANA ({@code TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}) ou
 * OpenSSL ({@code ECDHE-RSA-AES128-GCM-SHA256}, {@code HIGH:!aNULL}). Les faiblesses sont décrites dans
 * {@code resources/findings/tls-cipher-suites.json} : aucune table n'est codée ici.
 *
 * <p>Les éléments d'exclusion OpenSSL ({@code !x}, {@code -x}), les réordonnancements ({@code +x}) et les
 * directives ({@code @STRENGTH}, {@code @SECLEVEL=n}) ne sont pas des suites activées et sont ignorés.
 */
final class CipherSuitePolicy {

    private static final Pattern SEPARATORS = Pattern.compile("[\\s,:;\"'\\[\\]{}()]+");
    private static final String EXCLUSION_PREFIXES = "!-+@";

    /**
     * @param pattern  motif sur le nom de suite en majuscules
     * @param reason   explication
     */
    record Weakness(Pattern pattern, Severity severity, String reason) {
    }

    /** Suite faible et raison la plus grave. */
    record Verdict(String suite, Severity severity, String reason) {
    }

    private final List<Weakness> weaknesses;

    CipherSuitePolicy(List<Weakness> weaknesses) {
        this.weaknesses = List.copyOf(weaknesses);
    }

    /** Suites faibles d'une liste (dans l'ordre d'apparition, sans doublon). */
    List<Verdict> weakSuites(String list) {
        List<Verdict> verdicts = new ArrayList<>();
        for (String token : SEPARATORS.split(list)) {
            if (token.isEmpty() || EXCLUSION_PREFIXES.indexOf(token.charAt(0)) >= 0) {
                continue;
            }
            evaluate(token).filter(v -> verdicts.stream().noneMatch(x -> x.suite().equals(v.suite())))
                    .ifPresent(verdicts::add);
        }
        return verdicts;
    }

    Optional<Verdict> evaluate(String suite) {
        String normalized = suite.trim().toUpperCase(Locale.ROOT);
        Verdict worst = null;
        for (Weakness weakness : weaknesses) {
            if (weakness.pattern().matcher(normalized).find()
                    && (worst == null || weakness.severity().compareTo(worst.severity()) > 0)) {
                worst = new Verdict(normalized, weakness.severity(), weakness.reason());
            }
        }
        return Optional.ofNullable(worst);
    }
}
