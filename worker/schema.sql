-- Signups table for Navi early access
CREATE TABLE IF NOT EXISTS signups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    ip_hash TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

-- Index for faster email lookups (duplicate checking)
CREATE INDEX IF NOT EXISTS idx_signups_email ON signups(email);

-- Index for rate limiting queries
CREATE INDEX IF NOT EXISTS idx_signups_ip_created ON signups(ip_hash, created_at);
