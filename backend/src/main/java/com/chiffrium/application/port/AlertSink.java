package com.chiffrium.application.port;

/**
 * Relais externe des alertes importantes (canal Teams, Slack, Discord, webhook générique), en plus du centre
 * de notifications de l'application.
 */
public interface AlertSink {

    /**
     * @param title intitulé
     * @param body  détail
     * @param link  lien relatif dans l'application (peut être null)
     */
    void send(String title, String body, String link);
}
