-- ============================================================
-- side-go-server BUSINESS schema
-- ============================================================
-- This script is for BUSINESS mode user cloud-sync configuration data.

CREATE TABLE IF NOT EXISTS auth_identity_uzid (
    id BIGSERIAL PRIMARY KEY,
    identity_hash CHAR(64) NOT NULL UNIQUE,
    uzid VARCHAR(36) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_auth_identity_uzid_uzid ON auth_identity_uzid(uzid);
CREATE INDEX IF NOT EXISTS idx_auth_identity_uzid_updated_at ON auth_identity_uzid(updated_at);

CREATE TABLE IF NOT EXISTS user_conf (
    id BIGSERIAL PRIMARY KEY,
    uzid VARCHAR(36) NOT NULL,
    conf_key VARCHAR(100) NOT NULL,
    conf_value JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_user_conf_uzid_key UNIQUE (uzid, conf_key)
);

CREATE INDEX IF NOT EXISTS idx_user_conf_uzid ON user_conf(uzid);
CREATE INDEX IF NOT EXISTS idx_user_conf_key ON user_conf(conf_key);
CREATE INDEX IF NOT EXISTS idx_user_conf_updated_at ON user_conf(updated_at);

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS update_user_conf_updated_at ON user_conf;
CREATE TRIGGER update_user_conf_updated_at
    BEFORE UPDATE ON user_conf
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_auth_identity_uzid_updated_at ON auth_identity_uzid;
CREATE TRIGGER update_auth_identity_uzid_updated_at
    BEFORE UPDATE ON auth_identity_uzid
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
