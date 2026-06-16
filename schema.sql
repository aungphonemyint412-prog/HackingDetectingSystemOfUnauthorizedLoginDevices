-- ============================================================
--  HDS – Hacking Detection System
--  MySQL Schema  (run once to create all tables)
--  Compatible with MySQL 5.7+ / MariaDB 10.3+
-- ============================================================

CREATE DATABASE IF NOT EXISTS hds_db
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE hds_db;

-- ── users ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id             INT            NOT NULL AUTO_INCREMENT,
    username       VARCHAR(80)    NOT NULL,
    email          VARCHAR(120)   NOT NULL,
    password_hash  VARCHAR(256)   DEFAULT NULL,
    google_id      VARCHAR(100)   DEFAULT NULL,
    profile_pic    TEXT           DEFAULT NULL,
    email_verified TINYINT(1)     NOT NULL DEFAULT 0,
    two_fa_enabled TINYINT(1)     NOT NULL DEFAULT 0,
    is_active      TINYINT(1)     NOT NULL DEFAULT 1,
    is_locked      TINYINT(1)     NOT NULL DEFAULT 0,
    locked_until   DATETIME       DEFAULT NULL,
    lock_reason    VARCHAR(300)   DEFAULT NULL,
    created_at     DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login     DATETIME       DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_users_username (username),
    UNIQUE KEY uq_users_email    (email),
    UNIQUE KEY uq_users_google   (google_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── login_history ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS login_history (
    id                 INT           NOT NULL AUTO_INCREMENT,
    user_id            INT           NOT NULL,
    ip_address         VARCHAR(45)   DEFAULT NULL,
    device_type        VARCHAR(50)   DEFAULT NULL,
    browser            VARCHAR(120)  DEFAULT NULL,
    os                 VARCHAR(120)  DEFAULT NULL,
    user_agent         VARCHAR(500)  DEFAULT NULL,
    location           VARCHAR(200)  DEFAULT NULL,
    lat                DOUBLE        DEFAULT NULL,
    lon                DOUBLE        DEFAULT NULL,
    is_vpn             TINYINT(1)    NOT NULL DEFAULT 0,
    risk_score         INT           NOT NULL DEFAULT 0,
    user_confirmed     TINYINT(1)    DEFAULT NULL,
    login_time         DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    login_status       VARCHAR(20)   DEFAULT NULL,
    is_suspicious      TINYINT(1)    NOT NULL DEFAULT 0,
    suspicious_reasons TEXT          DEFAULT NULL,
    two_fa_required    TINYINT(1)    NOT NULL DEFAULT 0,
    two_fa_verified    TINYINT(1)    DEFAULT NULL,
    PRIMARY KEY (id),
    INDEX idx_login_time (login_time),
    CONSTRAINT fk_lh_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── alerts ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
    id               INT          NOT NULL AUTO_INCREMENT,
    user_id          INT          NOT NULL,
    login_history_id INT          DEFAULT NULL,
    alert_type       VARCHAR(50)  DEFAULT NULL,
    message          TEXT         DEFAULT NULL,
    created_at       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_read          TINYINT(1)   NOT NULL DEFAULT 0,
    email_sent       TINYINT(1)   NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    INDEX idx_alerts_created (created_at),
    CONSTRAINT fk_alerts_user  FOREIGN KEY (user_id)          REFERENCES users(id)          ON DELETE CASCADE,
    CONSTRAINT fk_alerts_lh    FOREIGN KEY (login_history_id) REFERENCES login_history(id)  ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── otp_codes ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS otp_codes (
    id               INT          NOT NULL AUTO_INCREMENT,
    user_id          INT          NOT NULL,
    code             VARCHAR(6)   NOT NULL,
    is_used          TINYINT(1)   NOT NULL DEFAULT 0,
    expires_at       DATETIME     NOT NULL,
    created_at       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip_address       VARCHAR(45)  DEFAULT NULL,
    login_history_id INT          DEFAULT NULL,
    PRIMARY KEY (id),
    CONSTRAINT fk_otp_user FOREIGN KEY (user_id)          REFERENCES users(id)         ON DELETE CASCADE,
    CONSTRAINT fk_otp_lh   FOREIGN KEY (login_history_id) REFERENCES login_history(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── known_ips ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS known_ips (
    id          INT         NOT NULL AUTO_INCREMENT,
    user_id     INT         NOT NULL,
    ip_address  VARCHAR(45) NOT NULL,
    first_seen  DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen   DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    login_count INT         NOT NULL DEFAULT 1,
    PRIMARY KEY (id),
    UNIQUE KEY uq_user_ip (user_id, ip_address),
    CONSTRAINT fk_kip_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── known_devices ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS known_devices (
    id                 INT          NOT NULL AUTO_INCREMENT,
    user_id            INT          NOT NULL,
    device_fingerprint VARCHAR(64)  NOT NULL,
    device_type        VARCHAR(20)  DEFAULT NULL,
    browser            VARCHAR(120) DEFAULT NULL,
    os                 VARCHAR(120) DEFAULT NULL,
    first_seen         DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen          DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_user_device (user_id, device_fingerprint),
    CONSTRAINT fk_kd_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── failed_attempts ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS failed_attempts (
    id           INT         NOT NULL AUTO_INCREMENT,
    user_id      INT         NOT NULL,
    ip_address   VARCHAR(45) NOT NULL,
    attempt_time DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_fa_time (attempt_time),
    CONSTRAINT fk_fa_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── security_tokens ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS security_tokens (
    id               INT         NOT NULL AUTO_INCREMENT,
    user_id          INT         NOT NULL,
    token            VARCHAR(64) NOT NULL,
    token_type       VARCHAR(50) DEFAULT NULL,
    login_history_id INT         DEFAULT NULL,
    is_used          TINYINT(1)  NOT NULL DEFAULT 0,
    expires_at       DATETIME    NOT NULL,
    created_at       DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_token (token),
    INDEX idx_token_lookup (token),
    CONSTRAINT fk_st_user FOREIGN KEY (user_id)          REFERENCES users(id)         ON DELETE CASCADE,
    CONSTRAINT fk_st_lh   FOREIGN KEY (login_history_id) REFERENCES login_history(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── email_queue ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS email_queue (
    id         INT          NOT NULL AUTO_INCREMENT,
    user_id    INT          DEFAULT NULL,
    recipient  VARCHAR(120) NOT NULL,
    email_type VARCHAR(50)  DEFAULT NULL,
    subject    VARCHAR(300) DEFAULT NULL,
    status     VARCHAR(20)  NOT NULL DEFAULT 'sent',
    attempts   INT          NOT NULL DEFAULT 1,
    created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    sent_at    DATETIME     DEFAULT NULL,
    error_msg  VARCHAR(500) DEFAULT NULL,
    PRIMARY KEY (id),
    INDEX idx_eq_created (created_at),
    CONSTRAINT fk_eq_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── security_incidents ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS security_incidents (
    id            INT          NOT NULL AUTO_INCREMENT,
    incident_ref  VARCHAR(25)  NOT NULL,
    user_id       INT          DEFAULT NULL,
    incident_type VARCHAR(100) DEFAULT NULL,
    severity      VARCHAR(20)  DEFAULT NULL,
    status        VARCHAR(20)  NOT NULL DEFAULT 'open',
    details       TEXT         DEFAULT NULL,
    source_ip     VARCHAR(45)  DEFAULT NULL,
    risk_score    INT          NOT NULL DEFAULT 0,
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    resolved_at   DATETIME     DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_incident_ref (incident_ref),
    INDEX idx_si_created (created_at),
    CONSTRAINT fk_si_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── DONE ──────────────────────────────────────────────────────
-- All 10 tables created. Connect the app with:
--   DATABASE_URL=mysql+pymysql://root:yourpassword@localhost:3306/hds_db
