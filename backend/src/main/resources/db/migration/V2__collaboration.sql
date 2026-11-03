-- Travail en équipe : groupes, favoris, demandes de modification du catalogue, ancrage du journal d'audit.

CREATE TABLE user_groups (
    id          VARCHAR(36)  PRIMARY KEY,
    name        VARCHAR(100) NOT NULL UNIQUE,
    description VARCHAR(500),
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL
);

-- manager : responsable du groupe (voit et gère les analyses du groupe, suit les demandes de ses membres).
CREATE TABLE group_members (
    group_id VARCHAR(36) NOT NULL REFERENCES user_groups(id) ON DELETE CASCADE,
    user_id  VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    manager  BOOLEAN     NOT NULL,
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX group_members_user ON group_members(user_id);

CREATE TABLE favorites (
    user_id     VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    analysis_id VARCHAR(36) NOT NULL,
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (user_id, analysis_id)
);

-- proposal : entrée de catalogue proposée (JSON), absente pour une demande de suppression.
CREATE TABLE catalog_requests (
    id             VARCHAR(36)   PRIMARY KEY,
    kind           VARCHAR(16)   NOT NULL,
    algorithm_id   VARCHAR(100)  NOT NULL,
    proposal       ${TEXT},
    justification  VARCHAR(2000) NOT NULL,
    requested_by   VARCHAR(64)   NOT NULL,
    group_id       VARCHAR(36),
    status         VARCHAR(16)   NOT NULL,
    reviewed_by    VARCHAR(64),
    review_comment VARCHAR(2000),
    created_at     TIMESTAMP WITH TIME ZONE NOT NULL,
    reviewed_at    TIMESTAMP WITH TIME ZONE
);
CREATE INDEX catalog_requests_status ON catalog_requests(status);

-- Dernière entrée purgée (rétention) : la vérification de la chaîne repart de cette empreinte.
CREATE TABLE audit_checkpoint (
    id       INT       PRIMARY KEY,
    sequence BIGINT    NOT NULL,
    hash     CHAR(64)  NOT NULL
);

-- Exports vers un stockage externe : la dernière entrée exportée ne peut plus être modifiée ni supprimée
-- sans que la vérification ne le détecte.
CREATE TABLE audit_anchors (
    sequence    BIGINT       PRIMARY KEY,
    hash        CHAR(64)     NOT NULL,
    exported_at TIMESTAMP WITH TIME ZONE NOT NULL,
    target      VARCHAR(300) NOT NULL
)
