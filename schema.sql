-- ==========================================================================
-- ALCHERINGA SYSTEM - DATABASE SCHEMA DATABASE DEFINITION SCRIPT
-- PostgreSQL Relational Table Setup
-- ==========================================================================

-- Clean old instances to prevent conflict errors upon initialization scripts
DROP TABLE IF EXISTS otps CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- --------------------------------------------------------------------------
-- 1. PERSISTENT USER RECORDS TABLE
-- --------------------------------------------------------------------------
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL, 
    email VARCHAR(255) UNIQUE NOT NULL,    
    hardwareid VARCHAR(255) DEFAULT NULL,  
    password_hash VARCHAR(64) NOT NULL,    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Comment explanations for GitHub documentation
COMMENT ON COLUMN users.password_hash IS 'Stores secure fixed 64-character SHA-256 encrypted password strings';
COMMENT ON COLUMN users.hardwareid IS 'Reserved system parameter initialization placeholder mapping (defaulted as NULL)';

-- --------------------------------------------------------------------------
-- 2. VOLATILE ONE-TIME PASSKEY (OTP) TRACKING TABLE
-- --------------------------------------------------------------------------
CREATE TABLE otps (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL REFERENCES users(email) ON DELETE CASCADE, 
    otp_code VARCHAR(6) NOT NULL,       
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON COLUMN otps.expires_at IS 'Enforces absolute security lifetime limitations (valid for exactly 5 minutes)';
