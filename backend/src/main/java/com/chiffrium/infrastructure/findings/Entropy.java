package com.chiffrium.infrastructure.findings;

import java.util.HashMap;
import java.util.Map;

/**
 * Entropie de Shannon d'une chaîne (bits par caractère) : un vrai secret aléatoire dépasse nettement
 * un mot du dictionnaire ou un identifiant, ce qui élimine la plupart des faux positifs des règles génériques.
 */
final class Entropy {

    private Entropy() {
    }

    static double shannon(String value) {
        if (value == null || value.isEmpty()) {
            return 0;
        }
        Map<Integer, Integer> counts = new HashMap<>();
        value.codePoints().forEach(c -> counts.merge(c, 1, Integer::sum));
        double length = value.codePointCount(0, value.length());
        double entropy = 0;
        for (int count : counts.values()) {
            double p = count / length;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }
}
