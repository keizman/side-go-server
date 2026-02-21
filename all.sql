-- ============================================================
-- Chrome Extension Backend - Database Schema
-- ============================================================
-- Database: extension_db
-- This script creates the users table and inserts default admin account
-- Run this script ONCE during initial setup
-- ============================================================

-- Create database (run as postgres superuser if needed)
-- CREATE DATABASE extension_db;

-- Connect to the database
-- \c extension_db;

-- ============================================================
-- Users Table
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    -- Primary Key
    id SERIAL PRIMARY KEY,
    uzid VARCHAR(36) NOT NULL UNIQUE DEFAULT md5(random()::text || clock_timestamp()::text),
    
    -- Basic Information
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    display_name VARCHAR(100),
    
    -- User Status and Role
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    -- Values: active, inactive, suspended, banned
    
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    -- Values: user, admin, moderator

    tier SMALLINT NOT NULL DEFAULT 2,
    -- Values: 1=free(含temp/guest), 2=user, 3=pay
    
    -- Registration Information
    register_ip INET,
    -- IP address from which user registered
    
    -- Usage Tracking
    request_count BIGINT NOT NULL DEFAULT 0,
    -- Total number of API requests made by this user
    
    last_login_at TIMESTAMP WITH TIME ZONE,
    -- Last successful login timestamp
    
    last_login_ip INET,
    -- IP address of last login
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    -- Email Verification (future use)
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    email_verified_at TIMESTAMP WITH TIME ZONE,
    
    -- Soft Delete (optional)
    deleted_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT chk_users_tier_1_2_3 CHECK (tier IN (1, 2, 3))
);

-- ============================================================
-- Indexes for Performance
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_uzid ON users(uzid);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_tier ON users(tier);
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);

-- ============================================================
-- User Conf Table (BUSINESS mode data sync)
-- ============================================================
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

-- ============================================================
-- Updated At Trigger Function
-- ============================================================
-- Automatically update updated_at column on row modification
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for users table
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_user_conf_updated_at ON user_conf;
CREATE TRIGGER update_user_conf_updated_at
    BEFORE UPDATE ON user_conf
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================
-- Default Admin Account
-- ============================================================
-- NOTE: The actual admin account will be created by the application
-- on first startup using the credentials from .env file
-- This ensures the password is properly hashed using bcrypt
-- 
-- The application will:
-- 1. Read ADMIN_USERNAME, ADMIN_PASSWORD, ADMIN_EMAIL from .env
-- 2. Hash the password using bcrypt (cost 10)
-- 3. Insert the admin account if it doesn't exist
-- 4. Set role='admin', status='active'
-- 
-- DO NOT insert admin account manually here with plain text password!

-- ============================================================
-- Sample Data (Development Only - Remove in Production)
-- ============================================================
-- Uncomment below to insert sample test users
-- Note: These passwords are hashed with bcrypt (cost 10)
-- Plain text password for all test users: "Test123!@#"

-- INSERT INTO users (username, email, password_hash, display_name, role, status, register_ip, request_count) VALUES
-- ('testuser1', 'testuser1@example.com', '$2a$10$N9qo8uLOickgx2ZMRZoMye.ILVjWKZZpXUaJhpJqYQfWjPqFj0q9i', 'Test User 1', 'user', 'active', '127.0.0.1', 0),
-- ('testuser2', 'testuser2@example.com', '$2a$10$N9qo8uLOickgx2ZMRZoMye.ILVjWKZZpXUaJhpJqYQfWjPqFj0q9i', 'Test User 2', 'user', 'active', '127.0.0.1', 0)
-- ON CONFLICT (username) DO NOTHING;

-- ============================================================
-- Verification Queries (Run after setup)
-- ============================================================
-- Check table structure:
-- \d users

-- Check admin account exists:
-- SELECT id, username, email, role, status, created_at FROM users WHERE role = 'admin';

-- Count total users:
-- SELECT COUNT(*) FROM users;

-- ============================================================
-- End of Schema
-- ============================================================
