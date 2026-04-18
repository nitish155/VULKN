-- VULKN Database Schema
-- PostgreSQL
-- Run this file once to create all tables

-- Enable UUID generation (needed for gen_random_uuid())
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================
-- TABLE: users
-- Stores VULKN user accounts
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    email         VARCHAR(255) NOT NULL UNIQUE,
    password_hash TEXT        NOT NULL,
    is_active     BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMP   NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMP   NOT NULL DEFAULT NOW()
);

-- ============================================================
-- TABLE: scans
-- One row per scan job submitted by a user
-- ============================================================
CREATE TABLE IF NOT EXISTS scans (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target_url    TEXT        NOT NULL,
    status        VARCHAR(20) NOT NULL DEFAULT 'queued',
    -- status values: queued, running, completed, failed
    scanners_run  INTEGER     NOT NULL DEFAULT 0,
    scanners_total INTEGER    NOT NULL DEFAULT 6,
    started_at    TIMESTAMP,
    completed_at  TIMESTAMP,
    created_at    TIMESTAMP   NOT NULL DEFAULT NOW()
);

-- ============================================================
-- TABLE: findings
-- One row per vulnerability found during a scan
-- This is the most important table for VULKN
-- ============================================================
CREATE TABLE IF NOT EXISTS findings (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID        NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    vuln_type       VARCHAR(50) NOT NULL,
    -- vuln_type values: SQLi, XSS, CSRF, PathTraversal, OpenPort, DirTraversal
    severity        VARCHAR(10) NOT NULL DEFAULT 'Medium',
    -- severity values: Critical, High, Medium, Low
    cvss_score      FLOAT,
    -- AI-generated CVSS-inspired score (0.0 to 10.0)
    description     TEXT        NOT NULL,
    evidence        TEXT,
    -- The actual payload + response that proves the vulnerability
    request_url     TEXT,
    request_method  VARCHAR(10),
    -- The HTTP request that triggered the finding
    ai_score        FLOAT,
    -- Isolation Forest anomaly score from ai_service
    ai_label        VARCHAR(20),
    -- 'anomalous' or 'normal' from ai_service
    confirmed       BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMP   NOT NULL DEFAULT NOW()
);

-- ============================================================
-- TABLE: reports
-- Tracks generated PDF reports for each scan
-- ============================================================
CREATE TABLE IF NOT EXISTS reports (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID        NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    s3_key          TEXT,
    -- Path in AWS S3 where the PDF is stored
    s3_url          TEXT,
    -- Presigned download URL (generated on demand)
    status          VARCHAR(20) NOT NULL DEFAULT 'pending',
    -- status values: pending, generating, ready, failed
    generated_at    TIMESTAMP,
    created_at      TIMESTAMP   NOT NULL DEFAULT NOW()
);

-- ============================================================
-- INDEXES
-- Make common queries fast
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_scans_user_id
    ON scans(user_id);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id
    ON findings(scan_id);

CREATE INDEX IF NOT EXISTS idx_findings_vuln_type
    ON findings(vuln_type);

CREATE INDEX IF NOT EXISTS idx_findings_severity
    ON findings(severity);

CREATE INDEX IF NOT EXISTS idx_reports_scan_id
    ON reports(scan_id);