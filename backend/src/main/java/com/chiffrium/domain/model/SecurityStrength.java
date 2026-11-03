package com.chiffrium.domain.model;

/**
 * Niveau de sécurité d'un algorithme tel qu'utilisé, repris dans le CBOM (CycloneDX 1.6) et dans le rapport.
 *
 * @param classicalBits    sécurité face à un attaquant classique, en bits (NIST SP 800-57), null si inconnue
 * @param nistQuantumLevel catégorie de sécurité NIST face à un attaquant quantique, de 1 (comme AES-128) à 5
 *                         (comme AES-256) ; 0 si aucune n'est atteinte (algorithme cassé par Shor, clé trop
 *                         courte) ; null si inconnue
 */
public record SecurityStrength(Integer classicalBits, Integer nistQuantumLevel) {
}
