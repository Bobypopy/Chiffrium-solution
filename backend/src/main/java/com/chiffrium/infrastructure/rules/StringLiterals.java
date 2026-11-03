package com.chiffrium.infrastructure.rules;

import com.chiffrium.domain.model.Language;

import java.util.EnumSet;
import java.util.Set;

/**
 * Position dans une chaîne littérale : un texte affiché ({@code "Rsa{algorithmId=" + algorithmId}) ressemble à
 * une affectation sans en être une.
 */
final class StringLiterals {

    /** Langages où l'apostrophe n'ouvre pas une chaîne (durée de vie Rust, commentaire VB, type 'a F#...). */
    private static final Set<Language> APOSTROPHE_NOT_QUOTE = EnumSet.of(Language.RUST, Language.VBNET,
            Language.FSHARP, Language.HASKELL, Language.SCALA);
    /** Fichiers de données : les guillemets y entourent des clés et des valeurs, pas des messages. */
    private static final Set<Language> NOT_CODE = EnumSet.of(Language.CONFIG, Language.SQL, Language.UNKNOWN);

    private StringLiterals() {
    }

    static boolean apostrophesQuote(Language language) {
        return !APOSTROPHE_NOT_QUOTE.contains(language);
    }

    static boolean isCode(Language language) {
        return language != null && !NOT_CODE.contains(language);
    }

    /**
     * Vrai si la position tombe dans une chaîne ouverte plus tôt sur sa ligne (échappements compris).
     *
     * @param apostrophes faux pour les langages où l'apostrophe n'ouvre pas une chaîne (durée de vie Rust...)
     */
    static boolean inside(String content, int position, boolean apostrophes) {
        char open = 0;
        for (int i = content.lastIndexOf('\n', position - 1) + 1; i < position; i++) {
            char c = content.charAt(i);
            if (open != 0) {
                if (c == '\\') {
                    i++;
                } else if (c == open) {
                    open = 0;
                }
            } else if (c == '"' || c == '`' || apostrophes && c == '\'') {
                open = c;
            }
        }
        return open != 0;
    }
}
