package com.chiffrium.application.port;

import com.chiffrium.application.settings.Settings;

import java.util.List;

/**
 * Fournisseur d'identité externe (OpenID Connect) pour l'authentification unique.
 */
public interface IdentityProvider {

    /**
     * Demande d'autorisation à ouvrir dans le navigateur.
     *
     * @param url          URL du fournisseur
     * @param state        valeur anti-CSRF à retrouver au retour
     * @param nonce        valeur liant le jeton ID à cette demande (anti-rejeu)
     * @param codeVerifier secret PKCE conservé côté serveur
     */
    record AuthorizationRequest(String url, String state, String nonce, String codeVerifier) {
    }

    /**
     * Identité vérifiée (signature, émetteur, audience, expiration et nonce du jeton ID contrôlés).
     *
     * @param subject     identifiant stable chez le fournisseur
     * @param username    identifiant proposé (preferred_username, sinon e-mail)
     * @param displayName nom affiché
     * @param email       adresse e-mail
     * @param groups      groupes (revendication configurée)
     */
    record Identity(String subject, String username, String displayName, String email, List<String> groups) {

        public Identity {
            groups = groups == null ? List.of() : List.copyOf(groups);
        }
    }

    AuthorizationRequest authorizationRequest(Settings.Oidc config);

    /**
     * @throws com.chiffrium.application.security.AuthenticationException si l'échange ou la validation échoue
     */
    Identity exchange(Settings.Oidc config, String code, String codeVerifier, String expectedNonce);
}
