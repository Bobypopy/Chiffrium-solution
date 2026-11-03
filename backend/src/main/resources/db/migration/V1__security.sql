-- Comptes, sessions, journal d'audit et paramètres.
CREATE TABLE users (
    id                   VARCHAR(36)  PRIMARY KEY,
    username             VARCHAR(64)  NOT NULL UNIQUE,
    display_name         VARCHAR(200) NOT NULL,
    email                VARCHAR(320),
    role                 VARCHAR(16)  NOT NULL,
    source               VARCHAR(16)  NOT NULL,
    password_hash        VARCHAR(200),
    enabled              BOOLEAN      NOT NULL,
    must_change_password BOOLEAN      NOT NULL,
    failed_attempts      INT          NOT NULL,
    locked_until         TIMESTAMP WITH TIME ZONE,
    created_at           TIMESTAMP WITH TIME ZONE NOT NULL,
    last_login_at        TIMESTAMP WITH TIME ZONE
);

CREATE TABLE sessions (
    token_hash   CHAR(64)    PRIMARY KEY,
    user_id      VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at   TIMESTAMP WITH TIME ZONE NOT NULL,
    source_ip    VARCHAR(64)
);
CREATE INDEX sessions_user ON sessions(user_id);

-- Journal en ajout seul, chaîné par empreintes SHA-256 (l'horodatage est stocké en texte ISO-8601
-- pour être relu à l'identique lors de la vérification).
CREATE TABLE audit_log (
    sequence      BIGINT        PRIMARY KEY,
    ts            VARCHAR(40)   NOT NULL,
    actor         VARCHAR(64)   NOT NULL,
    action        VARCHAR(64)   NOT NULL,
    target        VARCHAR(300),
    details       VARCHAR(1100),
    source_ip     VARCHAR(64),
    previous_hash CHAR(64)      NOT NULL,
    hash          CHAR(64)      NOT NULL
);
CREATE INDEX audit_actor ON audit_log(actor);
CREATE INDEX audit_action ON audit_log(action);

-- Document de paramètres unique, chiffré (AES-GCM) avant stockage.
CREATE TABLE settings (
    id       INT PRIMARY KEY,
    document ${BINARY} NOT NULL
);
