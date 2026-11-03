package com.chiffrium.infrastructure.rules;

/**
 * Position dans une chaîne littérale : un texte affiché ({@code "Rsa{algorithmId=" + algorithmId}) ressemble à
 * une affectation sans en être une.
 */
final class StringLiterals {

    private StringLiterals() {
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
