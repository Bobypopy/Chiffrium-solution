package com.chiffrium.application.port;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

/**
 * File des analyses à exécuter. En local : une file en mémoire. En serveur d'équipe multi-répliques : une file
 * partagée en base, chaque réplique "réserve" une analyse à la fois ; un signe de vie régulier permet de
 * reprendre les analyses d'une réplique arrêtée.
 */
public interface JobQueue {

    /** Ajoute une analyse (déjà enregistrée à l'état "en attente"). */
    void enqueue(String analysisId);

    /**
     * Réserve la prochaine analyse pour cette réplique.
     *
     * @return l'identifiant, ou vide si rien n'est arrivé dans le délai
     * @throws InterruptedException à l'arrêt du service
     */
    Optional<String> take(Duration wait) throws InterruptedException;

    /** Nombre d'analyses en attente (toutes répliques confondues). */
    int pending();

    /** Signe de vie d'une analyse en cours sur cette réplique. */
    void heartbeat(String analysisId);

    /**
     * Analyses en cours dont la réplique ne donne plus signe de vie depuis {@code staleAfter} (réplique arrêtée
     * brutalement) : à marquer en échec.
     */
    List<String> abandoned(Duration staleAfter);
}
