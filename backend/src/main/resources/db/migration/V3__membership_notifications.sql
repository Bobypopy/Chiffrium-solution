-- Adhésion consentie aux groupes (invitations, demandes), notifications, analyses partagées entre serveurs.

-- PRIVATE : sur invitation uniquement ; PUBLIC : visible dans l'annuaire, on peut demander à le rejoindre.
ALTER TABLE user_groups ADD COLUMN visibility VARCHAR(16) DEFAULT 'PRIVATE' NOT NULL;

-- kind INVITATION : un responsable invite, l'invité accepte ou refuse.
-- kind JOIN_REQUEST : un utilisateur demande, un responsable accepte ou refuse.
CREATE TABLE group_invitations (
    id           VARCHAR(36)  PRIMARY KEY,
    group_id     VARCHAR(36)  NOT NULL REFERENCES user_groups(id) ON DELETE CASCADE,
    user_id      VARCHAR(36)  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind         VARCHAR(16)  NOT NULL,
    manager      BOOLEAN      NOT NULL,
    message      VARCHAR(500),
    created_by   VARCHAR(64)  NOT NULL,
    status       VARCHAR(16)  NOT NULL,
    responded_by VARCHAR(64),
    created_at   TIMESTAMP WITH TIME ZONE NOT NULL,
    responded_at TIMESTAMP WITH TIME ZONE
);
CREATE INDEX group_invitations_user ON group_invitations(user_id, status);
CREATE INDEX group_invitations_group ON group_invitations(group_id, status);

CREATE TABLE notifications (
    id         VARCHAR(36)  PRIMARY KEY,
    user_id    VARCHAR(36)  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind       VARCHAR(40)  NOT NULL,
    title      VARCHAR(200) NOT NULL,
    body       VARCHAR(1000),
    link       VARCHAR(300),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    read_at    TIMESTAMP WITH TIME ZONE
);
CREATE INDEX notifications_user ON notifications(user_id, read_at);

-- Serveur d'équipe multi-répliques : état des analyses en base (document chiffré) et file partagée.
-- worker / heartbeat_at : réplique qui exécute l'analyse et dernier signe de vie (reprise si elle s'arrête).
CREATE TABLE analyses (
    id           VARCHAR(36)  PRIMARY KEY,
    requested_by VARCHAR(64),
    group_id     VARCHAR(36),
    status       VARCHAR(16)  NOT NULL,
    created_at   TIMESTAMP WITH TIME ZONE NOT NULL,
    worker       VARCHAR(100),
    heartbeat_at TIMESTAMP WITH TIME ZONE,
    document     ${BINARY}    NOT NULL
);
CREATE INDEX analyses_status ON analyses(status, created_at)
