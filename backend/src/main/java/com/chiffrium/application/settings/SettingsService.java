package com.chiffrium.application.settings;

import com.chiffrium.application.port.SettingsRepository;
import com.chiffrium.application.security.Actor;
import com.chiffrium.application.security.AuditService;
import com.chiffrium.domain.security.Permission;
import com.chiffrium.domain.security.Role;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Lecture / modification des paramètres. Les secrets ne sortent jamais en clair : l'API reçoit
 * {@link #MASK} à leur place, et renvoyer {@link #MASK} (ou null) conserve la valeur existante.
 */
public final class SettingsService {

    public static final String MASK = "********";
    static final int MAX_RETENTION_DAYS = 3_650;
    static final int MIN_IDLE_MINUTES = 5;
    static final int MAX_IDLE_MINUTES = 480;
    static final int MAX_SESSION_HOURS = 168;
    static final int MAX_STORAGE_MB = 1_048_576;
    /** Journaux de sécurité : 6 mois minimum (recommandation CNIL pour la traçabilité des accès). */
    static final int MIN_AUDIT_RETENTION_DAYS = 180;
    static final int MAX_NOTICE_LENGTH = 10_000;
    static final int MAX_PORT = 65_535;
    /** Port SMTPS : la liaison est chiffrée d'emblée, STARTTLS n'a pas lieu d'être. */
    static final int SMTPS_PORT = 465;

    private final SettingsRepository repository;
    private final AuditService audit;
    private volatile Settings cached;

    public SettingsService(SettingsRepository repository, AuditService audit) {
        this.repository = repository;
        this.audit = audit;
    }

    /** Paramètres effectifs (usage interne, secrets en clair). */
    public Settings current() {
        Settings value = cached;
        if (value == null) {
            value = repository.load().map(Settings::withDefaultsForMissing).orElseGet(Settings::defaults);
            cached = value;
        }
        return value;
    }

    /** Vue destinée à l'interface d'administration, secrets masqués. */
    public Settings view(Actor actor) {
        actor.require(Permission.MANAGE_SETTINGS);
        return masked(current());
    }

    public synchronized Settings update(Actor actor, Settings incoming) {
        actor.require(Permission.MANAGE_SETTINGS);
        Settings existing = current();
        Settings merged = new Settings(
                Objects.requireNonNullElse(incoming.storage(), existing.storage()),
                Objects.requireNonNullElse(incoming.sessions(), existing.sessions()),
                mergeIntelligence(existing.intelligence(), incoming.intelligence()),
                Objects.requireNonNullElse(incoming.analysis(), existing.analysis()),
                mergeOidc(existing.oidc(), incoming.oidc()),
                mergeAudit(existing.audit(), incoming.audit()),
                mergeOrganization(existing.organization(), incoming.organization()),
                Objects.requireNonNullElse(incoming.collaboration(), existing.collaboration()),
                mergeAlerts(existing.alerts(), incoming.alerts()),
                mergeEmail(existing.email(), incoming.email()));
        List<String> errors = validate(merged);
        if (!errors.isEmpty()) {
            throw new IllegalArgumentException(String.join(" ", errors));
        }
        repository.save(merged);
        cached = merged;
        audit.record(actor, "SETTINGS_UPDATED", null, changedSections(existing, merged));
        return masked(merged);
    }

    static List<String> validate(Settings s) {
        List<String> errors = new ArrayList<>();
        if (s.storage().retentionDays() < 0 || s.storage().retentionDays() > MAX_RETENTION_DAYS) {
            errors.add("Rétention entre 0 et " + MAX_RETENTION_DAYS + " jours.");
        }
        if (s.storage().maxStorageMb() < 0 || s.storage().maxStorageMb() > MAX_STORAGE_MB) {
            errors.add("Volume maximal invalide.");
        }
        if (s.sessions().idleMinutes() < MIN_IDLE_MINUTES || s.sessions().idleMinutes() > MAX_IDLE_MINUTES) {
            errors.add("Inactivité entre " + MIN_IDLE_MINUTES + " et " + MAX_IDLE_MINUTES + " minutes.");
        }
        if (s.sessions().maxHours() < 1 || s.sessions().maxHours() > MAX_SESSION_HOURS) {
            errors.add("Durée de session entre 1 et " + MAX_SESSION_HOURS + " heures.");
        }
        Settings.Oidc oidc = s.oidc();
        if (oidc.enabled()) {
            if (oidc.issuer() == null || !isHttps(oidc.issuer())) {
                errors.add("SSO : l'émetteur doit être une URL https.");
            }
            if (oidc.clientId() == null || oidc.clientId().isBlank()) {
                errors.add("SSO : identifiant client obligatoire.");
            }
            if (oidc.redirectUri() == null || !isHttps(oidc.redirectUri()) && !isLoopback(oidc.redirectUri())) {
                errors.add("SSO : l'URL de retour doit être en https (ou sur 127.0.0.1 pour l'application de bureau).");
            }
            if (oidc.defaultRole() == Role.ADMIN) {
                errors.add("SSO : le rôle par défaut ne peut pas être administrateur.");
            }
        }
        Settings.Audit audit = s.audit();
        if (audit.retentionDays() != 0
                && (audit.retentionDays() < MIN_AUDIT_RETENTION_DAYS || audit.retentionDays() > MAX_RETENTION_DAYS)) {
            errors.add("Rétention du journal d'audit : 0 (illimitée) ou entre " + MIN_AUDIT_RETENTION_DAYS + " et "
                    + MAX_RETENTION_DAYS + " jours.");
        }
        if (audit.webhookUrl() != null && !isHttps(audit.webhookUrl())) {
            errors.add("Archivage du journal : l'URL doit être en https.");
        }
        if (s.alerts().webhookUrl() != null && !isHttps(s.alerts().webhookUrl())) {
            errors.add("Alertes : l'URL du webhook doit être en https.");
        }
        Settings.Email email = s.email();
        if (email.enabled()) {
            if (email.host() == null || email.host().isBlank()) {
                errors.add("Courriel : serveur SMTP obligatoire.");
            }
            if (email.port() < 1 || email.port() > MAX_PORT) {
                errors.add("Courriel : port entre 1 et " + MAX_PORT + ".");
            }
            if (email.from() == null || !email.from().contains("@")) {
                errors.add("Courriel : adresse d'expédition invalide.");
            }
            if (email.username() != null && !email.username().isBlank() && !email.startTls()
                    && email.port() != SMTPS_PORT && !isLocalHost(email.host())) {
                errors.add("Courriel : avec un compte, il faut TLS (STARTTLS ou port 465) - sinon le mot de "
                        + "passe partirait en clair.");
            }
        }
        Settings.Organization organization = s.organization();
        if (organization.usageNotice() != null && organization.usageNotice().length() > MAX_NOTICE_LENGTH) {
            errors.add("Charte d'utilisation trop longue (" + MAX_NOTICE_LENGTH + " caractères max).");
        }
        return errors;
    }

    private static Settings.Audit mergeAudit(Settings.Audit existing, Settings.Audit incoming) {
        if (incoming == null) {
            return existing;
        }
        return new Settings.Audit(incoming.retentionDays(), trim(incoming.webhookUrl()),
                keepSecret(existing.webhookSecret(), incoming.webhookSecret()));
    }

    private static Settings.Email mergeEmail(Settings.Email existing, Settings.Email incoming) {
        if (incoming == null) {
            return existing;
        }
        return new Settings.Email(incoming.enabled(), trim(incoming.host()),
                incoming.port() <= 0 ? Settings.Email.DEFAULT_PORT : incoming.port(), incoming.startTls(),
                trim(incoming.username()), keepSecret(existing.password(), incoming.password()),
                trim(incoming.from()));
    }

    private static boolean isLocalHost(String host) {
        String value = host == null ? "" : host.toLowerCase(java.util.Locale.ROOT);
        return "localhost".equals(value) || "127.0.0.1".equals(value) || "::1".equals(value);
    }

    private static Settings.Alerts mergeAlerts(Settings.Alerts existing, Settings.Alerts incoming) {
        if (incoming == null) {
            return existing;
        }
        return new Settings.Alerts(keepSecret(existing.webhookUrl(), incoming.webhookUrl()),
                Objects.requireNonNullElse(incoming.format(), Settings.Alerts.Format.GENERIC));
    }

    private static Settings.Organization mergeOrganization(Settings.Organization existing,
                                                           Settings.Organization incoming) {
        if (incoming == null) {
            return existing;
        }
        String notice = incoming.usageNotice() == null || incoming.usageNotice().isBlank() ? null
                : incoming.usageNotice().strip();
        return new Settings.Organization(trim(incoming.name()), trim(incoming.privacyContact()), notice);
    }

    private static boolean isLoopback(String url) {
        try {
            URI uri = URI.create(url);
            return "http".equalsIgnoreCase(uri.getScheme())
                    && ("127.0.0.1".equals(uri.getHost()) || "localhost".equalsIgnoreCase(uri.getHost()));
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static boolean isHttps(String url) {
        try {
            return "https".equalsIgnoreCase(URI.create(url).getScheme());
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static Settings.Intelligence mergeIntelligence(Settings.Intelligence existing, Settings.Intelligence incoming) {
        if (incoming == null) {
            return existing;
        }
        return new Settings.Intelligence(incoming.osv(), incoming.kev(), incoming.epss(), incoming.nvd(),
                keepSecret(existing.nvdApiKey(), incoming.nvdApiKey()));
    }

    private static Settings.Oidc mergeOidc(Settings.Oidc existing, Settings.Oidc incoming) {
        if (incoming == null) {
            return existing;
        }
        return new Settings.Oidc(incoming.enabled(), trim(incoming.issuer()), trim(incoming.clientId()),
                keepSecret(existing.clientSecret(), incoming.clientSecret()), trim(incoming.redirectUri()),
                Objects.requireNonNullElse(incoming.defaultRole(), Role.VIEWER),
                Objects.requireNonNullElse(trim(incoming.groupsClaim()), "groups"),
                trim(incoming.adminGroup()), trim(incoming.analystGroup()));
    }

    /** null ou masque = inchangé ; chaîne vide = suppression du secret. */
    private static String keepSecret(String existing, String incoming) {
        if (incoming == null || MASK.equals(incoming)) {
            return existing;
        }
        return incoming.isBlank() ? null : incoming.trim();
    }

    private static Settings masked(Settings s) {
        Settings.Intelligence i = s.intelligence();
        Settings.Oidc o = s.oidc();
        return new Settings(s.storage(), s.sessions(),
                new Settings.Intelligence(i.osv(), i.kev(), i.epss(), i.nvd(), mask(i.nvdApiKey())),
                s.analysis(),
                new Settings.Oidc(o.enabled(), o.issuer(), o.clientId(), mask(o.clientSecret()), o.redirectUri(),
                        o.defaultRole(), o.groupsClaim(), o.adminGroup(), o.analystGroup()),
                new Settings.Audit(s.audit().retentionDays(), s.audit().webhookUrl(), mask(s.audit().webhookSecret())),
                s.organization(), s.collaboration(),
                new Settings.Alerts(mask(s.alerts().webhookUrl()), s.alerts().format()),
                new Settings.Email(s.email().enabled(), s.email().host(), s.email().port(), s.email().startTls(),
                        s.email().username(), mask(s.email().password()), s.email().from()));
    }

    private static String mask(String secret) {
        return secret == null ? null : MASK;
    }

    private static String trim(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    /** Sections modifiées, pour l'audit (sans jamais y écrire de valeur secrète). */
    private static String changedSections(Settings before, Settings after) {
        List<String> changed = new ArrayList<>();
        if (!before.storage().equals(after.storage())) {
            changed.add("stockage");
        }
        if (!before.sessions().equals(after.sessions())) {
            changed.add("sessions");
        }
        if (!before.intelligence().equals(after.intelligence())) {
            changed.add("sources de vulnérabilités");
        }
        if (!before.analysis().equals(after.analysis())) {
            changed.add("analyse");
        }
        if (!before.oidc().equals(after.oidc())) {
            changed.add("SSO");
        }
        if (!before.audit().equals(after.audit())) {
            changed.add("journal d'audit");
        }
        if (!before.email().equals(after.email())) {
            changed.add("courriel");
        }
        if (!before.organization().equals(after.organization())) {
            changed.add("informations légales");
        }
        if (!before.collaboration().equals(after.collaboration())) {
            changed.add("collaboration");
        }
        if (!before.alerts().equals(after.alerts())) {
            changed.add("alertes");
        }
        return changed.isEmpty() ? "aucun changement" : String.join(", ", changed);
    }
}
