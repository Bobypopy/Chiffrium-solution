package com.chiffrium.application.settings;

import com.chiffrium.domain.security.Role;

/**
 * Paramètres modifiables à chaud par un administrateur (stockés dans la base locale, secrets chiffrés).
 * Les réglages d'infrastructure (port, dossier de données...) restent dans les variables d'environnement.
 *
 * @param storage       rétention et volumétrie
 * @param sessions      durée des sessions
 * @param intelligence  sources de renseignement sur les vulnérabilités
 * @param analysis      options d'analyse
 * @param oidc          authentification unique (SSO)
 * @param audit         conservation et archivage externe du journal d'audit
 * @param organization  informations légales affichées aux utilisateurs
 * @param collaboration règles des groupes
 * @param alerts        relais des alertes vers un canal d'équipe
 * @param email         relais SMTP pour doubler les notifications par courriel
 */
public record Settings(Storage storage, Sessions sessions, Intelligence intelligence, Analysis analysis, Oidc oidc,
                       Audit audit, Organization organization, Collaboration collaboration, Alerts alerts,
                       Email email) {

    public static final int DEFAULT_RETENTION_DAYS = 90;
    public static final int DEFAULT_IDLE_MINUTES = 30;
    public static final int DEFAULT_MAX_HOURS = 12;

    public static Settings defaults() {
        return new Settings(
                new Storage(DEFAULT_RETENTION_DAYS, 0, false),
                new Sessions(DEFAULT_IDLE_MINUTES, DEFAULT_MAX_HOURS),
                new Intelligence(true, true, true, false, null),
                new Analysis(true),
                new Oidc(false, null, null, null, null, Role.VIEWER, "groups", null, null),
                new Audit(0, null, null),
                new Organization(null, null, null),
                new Collaboration(true),
                new Alerts(null, Alerts.Format.GENERIC),
                Email.disabled());
    }

    /** Modification partielle : les sections nulles sont conservées. */
    public Settings(Storage storage, Sessions sessions, Intelligence intelligence, Analysis analysis, Oidc oidc) {
        this(storage, sessions, intelligence, analysis, oidc, null, null, null, null, null);
    }

    /** Complète les sections absentes (paramètres enregistrés par une version antérieure). */
    public Settings withDefaultsForMissing() {
        Settings d = defaults();
        return new Settings(storage == null ? d.storage : storage, sessions == null ? d.sessions : sessions,
                intelligence == null ? d.intelligence : intelligence, analysis == null ? d.analysis : analysis,
                oidc == null ? d.oidc : oidc, audit == null ? d.audit : audit,
                organization == null ? d.organization : organization,
                collaboration == null ? d.collaboration : collaboration, alerts == null ? d.alerts : alerts,
                email == null ? d.email : email);
    }

    /**
     * Relais SMTP. Sans lui, une notification ne se voit qu'en ouvrant l'application ; beaucoup
     * d'organisations attendent un courriel.
     *
     * @param enabled   envoi activé
     * @param host      serveur SMTP
     * @param port      port (465 : liaison chiffrée d'emblée ; 587 ou 25 : STARTTLS)
     * @param startTls  passer la liaison en TLS après connexion (sans objet sur le port 465)
     * @param username  compte d'authentification, null si le relais n'en demande pas
     * @param password  mot de passe (chiffré au repos, jamais renvoyé en clair)
     * @param from      adresse d'expédition
     */
    public record Email(boolean enabled, String host, int port, boolean startTls, String username, String password,
                        String from) {

        public static final int DEFAULT_PORT = 587;

        public static Email disabled() {
            return new Email(false, null, DEFAULT_PORT, true, null, null, null);
        }

        /** Utilisable seulement si l'essentiel est renseigné : sans serveur ni expéditeur, rien ne partira. */
        public boolean usable() {
            return enabled && host != null && !host.isBlank() && from != null && !from.isBlank();
        }
    }

    /**
     * @param usersCanCreateGroups tout utilisateur peut créer un groupe (il en devient responsable) ; sinon réservé
     *                             aux administrateurs
     */
    public record Collaboration(boolean usersCanCreateGroups) {
    }

    /**
     * @param webhookUrl URL du webhook entrant (secret : elle suffit à publier dans le canal), null si aucun
     * @param format     format attendu par la plateforme
     */
    public record Alerts(String webhookUrl, Format format) {

        /** Plateformes de discussion gratuites prises en charge. */
        public enum Format {
            /** JSON complet (titre, détail, lien) pour un collecteur maison. */
            GENERIC,
            /** Slack, Mattermost, Rocket.Chat, anciens connecteurs Teams : {@code {"text": ...}}. */
            SLACK,
            /** Discord : {@code {"content": ...}}. */
            DISCORD,
            /** Microsoft Teams (flux "Workflows") : carte adaptative. */
            TEAMS
        }
    }

    /**
     * @param retentionDays   suppression automatique des analyses plus anciennes (0 = jamais)
     * @param maxStorageMb    volume maximal des analyses ; les plus anciennes sont purgées au-delà (0 = illimité)
     * @param keepRawOutputs  conserver les sorties brutes de cdxgen (volumineuses)
     */
    public record Storage(int retentionDays, int maxStorageMb, boolean keepRawOutputs) {
    }

    /**
     * @param idleMinutes expiration après inactivité
     * @param maxHours    durée maximale d'une session
     */
    public record Sessions(int idleMinutes, int maxHours) {
    }

    /**
     * @param osv       base OSV (vulnérabilités des dépendances, sans clé)
     * @param kev       catalogue CISA KEV (vulnérabilités exploitées activement, sans clé)
     * @param epss      score EPSS de probabilité d'exploitation (FIRST, sans clé)
     * @param nvd       base NVD du NIST (score CVSS officiel, clé recommandée)
     * @param nvdApiKey clé NVD (secret, chiffrée au repos)
     */
    public record Intelligence(boolean osv, boolean kev, boolean epss, boolean nvd, String nvdApiKey) {
    }

    /**
     * @param generateNpmLockfile générer un package-lock.json (sans exécuter de script) quand il manque
     */
    public record Analysis(boolean generateNpmLockfile) {
    }

    /**
     * @param retentionDays  conservation des entrées déjà archivées à l'extérieur (0 = illimitée)
     * @param webhookUrl     destination https des exports (SIEM, collecteur), null si aucune
     * @param webhookSecret  secret de signature HMAC-SHA256 des envois (chiffré au repos)
     */
    public record Audit(int retentionDays, String webhookUrl, String webhookSecret) {
    }

    /**
     * @param name           organisation responsable de l'outil (responsable de traitement au sens du RGPD)
     * @param privacyContact contact pour l'exercice des droits (DPO, e-mail)
     * @param usageNotice    charte d'utilisation / mention d'information affichée à la connexion
     */
    public record Organization(String name, String privacyContact, String usageNotice) {
    }

    /**
     * @param enabled       SSO actif
     * @param issuer        URL de l'émetteur OIDC (ex. https://login.microsoftonline.com/.../v2.0)
     * @param clientId      identifiant du client
     * @param clientSecret  secret du client (chiffré au repos)
     * @param redirectUri   URL de retour déclarée chez le fournisseur (.../api/auth/oidc/callback)
     * @param defaultRole   rôle attribué à la première connexion
     * @param groupsClaim   revendication contenant les groupes
     * @param adminGroup    groupe donnant le rôle administrateur
     * @param analystGroup  groupe donnant le rôle analyste
     */
    public record Oidc(boolean enabled, String issuer, String clientId, String clientSecret, String redirectUri,
                       Role defaultRole, String groupsClaim, String adminGroup, String analystGroup) {
    }
}
