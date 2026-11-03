package com.chiffrium.application.port;

/**
 * Envoi d'un courriel simple (texte), pour doubler les notifications de l'application. Beaucoup
 * d'organisations attendent l'e-mail : la cloche de l'interface ne se voit que si l'on est connecté.
 */
public interface MailSender {

    /**
     * @param to      adresse du destinataire
     * @param subject objet
     * @param body    corps en texte brut
     * @throws IllegalStateException si le relais refuse ou est injoignable
     */
    void send(String to, String subject, String body);
}
