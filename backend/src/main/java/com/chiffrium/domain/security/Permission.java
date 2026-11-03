package com.chiffrium.domain.security;

/**
 * Actions protégées de l'application. Les rôles sont des ensembles de permissions (voir {@link Role}).
 */
public enum Permission {
    /** Consulter les analyses visibles (les siennes, celles de ses groupes), rapports et CBOM. */
    VIEW_REPORTS,
    /** Consulter toutes les analyses, quel que soit leur groupe. */
    VIEW_ALL_ANALYSES,
    /** Proposer des modifications du catalogue (soumises à validation). */
    REQUEST_CATALOG_CHANGE,
    /** Lancer des analyses. */
    RUN_ANALYSIS,
    /** Supprimer ses propres analyses. */
    DELETE_OWN_ANALYSIS,
    /** Supprimer n'importe quelle analyse. */
    DELETE_ANY_ANALYSIS,
    /** Modifier le catalogue d'algorithmes (politique). */
    EDIT_CATALOG,
    /** Gérer les comptes utilisateurs. */
    MANAGE_USERS,
    /** Modifier les paramètres (sources de vulnérabilités, SSO, rétention...). */
    MANAGE_SETTINGS,
    /** Consulter le journal d'audit. */
    VIEW_AUDIT,
    /** Gérer les groupes et leurs membres. */
    MANAGE_GROUPS
}
