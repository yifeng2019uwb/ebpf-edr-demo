-- Supabase alerts table schema
-- For persistent storage of all detected alerts for investigation and behavioral analysis

CREATE TABLE alerts (
    id BIGSERIAL PRIMARY KEY,

    -- Alert metadata
    timestamp TIMESTAMPTZ NOT NULL,        -- When threat was detected (kernel time)
    level TEXT NOT NULL,                   -- CRITICAL, HIGH, MEDIUM, LOW
    rule TEXT NOT NULL,                    -- Rule name (e.g., T1059_unix_shell_execution)
    message TEXT NOT NULL,                 -- Human readable message

    -- Process information
    pid INTEGER,
    ppid INTEGER,
    uid INTEGER,
    comm TEXT,                             -- Command/process name

    -- Workload identification
    runtime TEXT,                          -- docker, k8s
    service TEXT,                          -- Container/service name
    pod TEXT,                              -- K8s pod name
    namespace TEXT,                        -- K8s namespace
    node TEXT,                             -- K8s node name
    cluster TEXT,                          -- K8s cluster name
    env TEXT,                              -- Application environment (dev, staging, prod)
    region TEXT,                           -- Cloud region or location

    -- Detection context
    state TEXT,                            -- Workload state (resolved, host, pending, unknown)

    -- Event-specific fields
    filename TEXT,                         -- For file access alerts
    dst_ip TEXT,                           -- For network alerts
    dst_port INTEGER,                      -- For network alerts

    -- Response information
    response_action TEXT,                  -- What action was taken (none, blocked, killed, etc.)

    -- Database metadata
    created_at TIMESTAMPTZ DEFAULT NOW(),  -- When inserted into database

    -- Container context
    -- Placed last to match `ALTER TABLE ... ADD COLUMN cgroup` on existing tables
    -- (Postgres appends new columns), so a fresh CREATE and a migrated table match.
    cgroup TEXT,                           -- Leaf cgroup name captured in-kernel (container id source; empty for host/net)

    -- For efficient queries
    CONSTRAINT level_check CHECK (level IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'))
);

-- Indexes for common queries
CREATE INDEX idx_alerts_timestamp ON alerts(timestamp DESC);
CREATE INDEX idx_alerts_level ON alerts(level);
CREATE INDEX idx_alerts_rule ON alerts(rule);
CREATE INDEX idx_alerts_service ON alerts(service);
CREATE INDEX idx_alerts_pod ON alerts(pod);
CREATE INDEX idx_alerts_namespace ON alerts(namespace);
CREATE INDEX idx_alerts_created_at ON alerts(created_at DESC);

-- Composite index for investigation queries (most common)
CREATE INDEX idx_alerts_service_timestamp ON alerts(service, timestamp DESC);

-- Enable Row Level Security (optional, for multi-user scenarios)
-- ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;

-- Grant access (adjust as needed)
-- GRANT SELECT, INSERT ON alerts TO anon;
-- GRANT SELECT, INSERT ON alerts TO authenticated;
