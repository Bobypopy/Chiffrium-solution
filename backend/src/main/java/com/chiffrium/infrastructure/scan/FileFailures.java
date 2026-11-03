package com.chiffrium.infrastructure.scan;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Fichiers qu'un détecteur n'a pas pu analyser (format inattendu, clé tronquée, expression pathologique...).
 * Un fichier en erreur est ignoré et signalé : il ne doit jamais faire échouer toute l'étape de détection.
 */
public final class FileFailures {

    private static final Logger LOG = LoggerFactory.getLogger(FileFailures.class);
    /** Au-delà, seul le nombre total est rapporté (les dépôts de vecteurs de test en contiennent beaucoup). */
    static final int MAX_LISTED = 10;

    private final String detector;
    private final List<String> listed = new ArrayList<>();
    private int count;

    public FileFailures(String detector) {
        this.detector = detector;
    }

    public void record(String file, Throwable error) {
        count++;
        LOG.warn("{} : fichier ignoré {} ({})", detector, file, error.toString());
        LOG.debug("Détail", error);
        if (listed.size() < MAX_LISTED) {
            listed.add(file);
        }
    }

    public int count() {
        return count;
    }

    /** Avertissement unique pour le rapport, vide si tout a été analysé. */
    public List<String> warnings() {
        if (count == 0) {
            return List.of();
        }
        String files = String.join(", ", listed) + (count > listed.size() ? ", ..." : "");
        return List.of("Détection " + detector + " : " + count + " fichier(s) ignoré(s) car illisibles ou au format "
                + "inattendu (" + files + "). Le reste du projet a été analysé normalement.");
    }
}
