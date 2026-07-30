-- Migration: Add cgroup column to alerts table
-- Stores the leaf cgroup name captured in-kernel by the exec/file sensors
-- (container id source; empty for host processes and network events).

ALTER TABLE alerts ADD COLUMN cgroup TEXT;
