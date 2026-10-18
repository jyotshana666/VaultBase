-- VaultBase PostgreSQL Database Schema (Phase 10 Production Persistence)

-- Extension for UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users Table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    face_registered BOOLEAN DEFAULT FALSE,
    face_descriptor JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Trusted Devices Table
CREATE TABLE IF NOT EXISTS trusted_devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id VARCHAR(255) NOT NULL,
    device_name VARCHAR(255),
    fingerprint TEXT NOT NULL,
    public_key TEXT,
    is_trusted BOOLEAN DEFAULT TRUE,
    is_revoked BOOLEAN DEFAULT FALSE,
    registered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_ip VARCHAR(45),
    revoked_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT unique_user_device_fingerprint UNIQUE (user_id, fingerprint)
);

ALTER TABLE trusted_devices ADD COLUMN IF NOT EXISTS is_revoked BOOLEAN DEFAULT FALSE;
ALTER TABLE trusted_devices ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE trusted_devices ADD COLUMN IF NOT EXISTS last_ip VARCHAR(45);

-- Active & Historical Sessions Table (Authoritative Session Store)
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    jti VARCHAR(255) UNIQUE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    device_fingerprint TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    status VARCHAR(32) NOT NULL DEFAULT 'active', -- 'active' | 'revoked' | 'expired'
    revoke_reason VARCHAR(64),
    revoked_at TIMESTAMP WITH TIME ZONE,
    context_changes INT NOT NULL DEFAULT 0,
    issued_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE sessions ADD COLUMN IF NOT EXISTS jti VARCHAR(255) UNIQUE;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS email VARCHAR(255);
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS device_fingerprint TEXT;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS status VARCHAR(32) DEFAULT 'active';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS revoke_reason VARCHAR(64);
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS context_changes INT DEFAULT 0;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS issued_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;

-- Security Audit Logs Table (Chronological Authentication Trail)
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    email VARCHAR(255),
    event_type VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL,
    ip_address VARCHAR(45),
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS email VARCHAR(255);

-- Risk & Anomaly Events Table (Evaluations & Detected Threats)
CREATE TABLE IF NOT EXISTS risk_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    email VARCHAR(255),
    event_type VARCHAR(64) NOT NULL,
    risk_score INT,
    risk_level VARCHAR(32),
    signals JSONB,
    details JSONB,
    ip_address VARCHAR(45),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Security Alerts Table (Persisted Alerts for Security Dashboard)
CREATE TABLE IF NOT EXISTS security_alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    email VARCHAR(255),
    alert_type VARCHAR(64) NOT NULL,
    severity VARCHAR(32) NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    metadata JSONB,
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- WebAuthn Credentials Table (FIDO2 / WebAuthn Public Keys)
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    transports TEXT[],
    device_type VARCHAR(64),
    backed_up BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT fk_webauthn_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Indices for performance and security lookups
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_devices_user_id ON trusted_devices(user_id);
CREATE INDEX IF NOT EXISTS idx_devices_fingerprint ON trusted_devices(fingerprint);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_jti ON sessions(jti);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_email ON audit_logs(email);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_risk_user_id ON risk_events(user_id);
CREATE INDEX IF NOT EXISTS idx_risk_email ON risk_events(email);
CREATE INDEX IF NOT EXISTS idx_risk_created_at ON risk_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_user_id ON security_alerts(user_id);
CREATE INDEX IF NOT EXISTS idx_alerts_email ON security_alerts(email);
CREATE INDEX IF NOT EXISTS idx_webauthn_user_id ON webauthn_credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_credential_id ON webauthn_credentials(credential_id);
