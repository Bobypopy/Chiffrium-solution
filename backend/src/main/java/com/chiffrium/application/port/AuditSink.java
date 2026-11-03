package com.chiffrium.application.port;

import com.chiffrium.domain.security.AuditEvent;

import java.util.List;

/**
 * Destination d'archivage externe du journal d'audit (dossier monté sur un stockage WORM, SIEM...).
 * Hors de la base, une copie ne peut pas être altérée par qui modifierait la base.
 */
public interface AuditSink {

    /** Description courte (tracée avec l'ancrage). */
    String name();

    /**
     * Publie un lot ordonné d'entrées.
     *
     * @throws RuntimeException en cas d'échec : le lot sera republié au prochain passage
     */
    void publish(List<AuditEvent> events);
}
