package com.chiffrium.application.security;

import com.chiffrium.application.port.AlertSink;
import com.chiffrium.application.port.MailSender;
import com.chiffrium.application.port.NotificationRepository;
import com.chiffrium.application.port.UserRepository;
import com.chiffrium.domain.security.Notification;
import com.chiffrium.domain.security.Permission;
import com.chiffrium.domain.security.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Duration;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * Centre de notifications : invitations, décisions, fin d'analyse... Une notification ne doit jamais faire
 * échouer l'action qui la déclenche (erreurs journalisées). Les alertes importantes sont aussi relayées vers un
 * canal externe si l'administrateur en a configuré un.
 */
public final class NotificationService {

    private static final Logger LOG = LoggerFactory.getLogger(NotificationService.class);
    /** Les notifications lues sont conservées ce délai, puis purgées. */
    static final Duration READ_RETENTION = Duration.ofDays(90);
    static final int MAX_LISTED = 100;

    /** Types de notification (identifiants stables pour l'interface). */
    public static final String GROUP_INVITATION = "GROUP_INVITATION";
    public static final String GROUP_JOIN_REQUEST = "GROUP_JOIN_REQUEST";
    public static final String GROUP_MEMBERSHIP = "GROUP_MEMBERSHIP";
    public static final String CATALOG_REQUEST = "CATALOG_REQUEST";
    public static final String ANALYSIS_FINISHED = "ANALYSIS_FINISHED";
    public static final String ACCOUNT = "ACCOUNT";

    private final NotificationRepository notifications;
    private final UserRepository users;
    private final Supplier<Optional<AlertSink>> alerts;
    private final Supplier<Optional<MailSender>> mail;
    private final Clock clock;

    public NotificationService(NotificationRepository notifications, UserRepository users,
                               Supplier<Optional<AlertSink>> alerts, Supplier<Optional<MailSender>> mail,
                               Clock clock) {
        this.notifications = notifications;
        this.users = users;
        this.alerts = alerts;
        this.mail = mail;
        this.clock = clock;
    }

    public void notifyUser(String userId, String kind, String title, String body, String link) {
        notifyUsers(List.of(userId), kind, title, body, link);
    }

    public void notifyUsers(Collection<String> userIds, String kind, String title, String body, String link) {
        Set<String> unique = new LinkedHashSet<>(userIds);
        for (String userId : unique) {
            if (userId == null) {
                continue;
            }
            try {
                notifications.save(new Notification(UUID.randomUUID().toString(), userId, kind, truncate(title,
                        Notification.MAX_TITLE_LENGTH), truncate(body, Notification.MAX_BODY_LENGTH), link,
                        clock.instant(), null));
            } catch (RuntimeException e) {
                LOG.warn("Notification non enregistrée pour {} : {}", userId, e.getMessage());
            }
            email(userId, title, body, link);
        }
    }

    /**
     * Double la notification par un courriel, si un relais est configuré et que le compte a une adresse.
     *
     * <p>Toujours au mieux : un relais en panne ne doit pas empêcher l'action en cours (inviter quelqu'un,
     * terminer une analyse). L'échec part dans les journaux, la notification reste dans l'application.
     */
    private void email(String userId, String title, String body, String link) {
        Optional<MailSender> sender = mail.get();
        if (sender.isEmpty()) {
            return;
        }
        users.findById(userId)
                .filter(user -> user.enabled() && user.email() != null && user.email().contains("@"))
                .ifPresent(user -> {
                    String texte = (body == null ? "" : body)
                            + (link == null ? "" : System.lineSeparator() + System.lineSeparator()
                            + "Dans l'application : " + link)
                            + System.lineSeparator() + System.lineSeparator()
                            + "- Chiffrium (message automatique, ne pas répondre)";
                    try {
                        sender.get().send(user.email(), title, texte);
                    } catch (RuntimeException e) {
                        LOG.warn("Courriel non envoyé à {} : {}", user.username(), e.getMessage());
                    }
                });
    }

    /** Notifie un utilisateur désigné par son identifiant de connexion (ignoré s'il n'existe plus). */
    public void notifyUsername(String username, String kind, String title, String body, String link) {
        if (username != null) {
            users.findByUsername(username).ifPresent(user -> notifyUser(user.id(), kind, title, body, link));
        }
    }

    /** Notifie tous les comptes actifs disposant d'une permission (ex. les administrateurs du catalogue). */
    public void notifyPermission(Permission permission, String kind, String title, String body, String link) {
        notifyUsers(users.findAll().stream().filter(User::enabled).filter(u -> u.role().can(permission))
                .map(User::id).toList(), kind, title, body, link);
    }

    /** Relais vers le canal externe configuré (alertes d'équipe). */
    public void alert(String title, String body, String link) {
        alerts.get().ifPresent(sink -> {
            try {
                sink.send(title, body, link);
            } catch (RuntimeException e) {
                LOG.warn("Alerte non relayée : {}", e.getMessage());
            }
        });
    }

    /**
     * Envoie un message de test à l'adresse de l'acteur, avec les réglages enregistrés.
     *
     * @return l'adresse servie
     * @throws IllegalStateException si aucun relais n'est configuré, ou si le compte n'a pas d'adresse
     */
    public String sendTestEmail(Actor actor) {
        MailSender sender = mail.get().orElseThrow(() -> new IllegalStateException(
                "Aucun relais de courriel configuré (ou envoi désactivé) : enregistrez d'abord les réglages."));
        String address = users.findById(actor.userId()).map(User::email).filter(a -> a.contains("@"))
                .orElseThrow(() -> new IllegalStateException(
                        "Votre compte n'a pas d'adresse de courriel : renseignez-la dans \"Mon compte\"."));
        sender.send(address, "Chiffrium : message de test",
                "Ce message confirme que le relais SMTP de Chiffrium fonctionne." + System.lineSeparator()
                        + "Les notifications qui vous concernent arriveront désormais aussi par courriel.");
        return address;
    }

    public List<Notification> list(Actor actor, boolean unreadOnly) {
        return actor.userId() == null ? List.of() : notifications.forUser(actor.userId(), unreadOnly, MAX_LISTED);
    }

    public long unreadCount(Actor actor) {
        return actor.userId() == null ? 0 : notifications.unreadCount(actor.userId());
    }

    /** Marque des notifications de l'acteur comme lues (toutes si la liste est vide). */
    public void markRead(Actor actor, List<String> ids) {
        if (actor.userId() != null) {
            notifications.markRead(actor.userId(), ids == null ? List.of() : ids, clock.instant());
        }
    }

    public int purgeOld() {
        return notifications.purgeReadBefore(clock.instant().minus(READ_RETENTION));
    }

    private static String truncate(String value, int max) {
        if (value == null) {
            return null;
        }
        return value.length() > max ? value.substring(0, max - 1) + "..." : value;
    }
}
