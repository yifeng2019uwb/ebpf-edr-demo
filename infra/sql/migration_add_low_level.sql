-- Migration: Add LOW level to alerts table
-- Allows telemetry alerts (EDR visibility) to be stored in database

-- Drop old constraint
ALTER TABLE alerts DROP CONSTRAINT level_check;

-- Add new constraint with LOW level
ALTER TABLE alerts ADD CONSTRAINT level_check CHECK (level IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'));
