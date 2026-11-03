package com.chiffrium.domain.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Objects;

/**
 * Entrée du journal d'audit. Chaque entrée contient l'empreinte de la précédente (chaînage SHA-256) :
 * toute modification ou suppression a posteriori d'une entrée casse la chaîne et est détectée.
 *
 * @param sequence     numéro d'ordre croissant
 * @param timestamp    date de l'événement
 * @param actor        utilisateur à l'origine (ou "system")
 * @param action       type d'action (ex. LOGIN_FAILURE, ANALYSIS_SUBMITTED)
 * @param target       objet concerné (identifiant d'analyse, utilisateur...)
 * @param details      précisions lisibles (jamais de secret)
 * @param sourceIp     adresse d'origine si connue
 * @param previousHash empreinte de l'entrée précédente
 * @param hash         empreinte de cette entrée
 */
public record AuditEvent(
        long sequence,
        Instant timestamp,
        String actor,
        String action,
        String target,
        String details,
        String sourceIp,
        String previousHash,
        String hash) {

    public static final String GENESIS_HASH = "0".repeat(64);
    public static final String SYSTEM_ACTOR = "system";
    private static final char SEPARATOR = '\u001f';

    /** Crée une entrée en calculant son empreinte à partir de la précédente. */
    public static AuditEvent chained(long sequence, Instant timestamp, String actor, String action, String target,
                                     String details, String sourceIp, String previousHash) {
        String hash = computeHash(sequence, timestamp, actor, action, target, details, sourceIp, previousHash);
        return new AuditEvent(sequence, timestamp, actor, action, target, details, sourceIp, previousHash, hash);
    }

    /** Vrai si l'empreinte stockée correspond au contenu. */
    public boolean isIntact() {
        return hash.equals(computeHash(sequence, timestamp, actor, action, target, details, sourceIp, previousHash));
    }

    static String computeHash(long sequence, Instant timestamp, String actor, String action, String target,
                              String details, String sourceIp, String previousHash) {
        String canonical = String.join(String.valueOf(SEPARATOR), String.valueOf(sequence), timestamp.toString(),
                Objects.toString(actor, ""), Objects.toString(action, ""), Objects.toString(target, ""),
                Objects.toString(details, ""), Objects.toString(sourceIp, ""), previousHash);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(canonical.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 indisponible", e);
        }
    }
}
