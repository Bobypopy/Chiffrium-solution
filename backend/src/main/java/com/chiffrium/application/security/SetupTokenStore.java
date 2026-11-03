package com.chiffrium.application.security;

import java.util.Optional;

/**
 * Jeton à usage unique exigé pour créer le premier administrateur : sans lui, n'importe qui atteignant le
 * serveur avant l'installateur pourrait prendre le contrôle de l'instance.
 */
public interface SetupTokenStore {

    /** Jeton courant (créé au besoin) tant qu'aucun compte n'existe. */
    Optional<String> current();

    /** Invalide le jeton une fois l'administrateur créé. */
    void consume();
}
