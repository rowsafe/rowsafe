-- golang-migrate down migration
DROP TABLE IF EXISTS legacy_events CASCADE;
TRUNCATE TABLE audit_log RESTART IDENTITY;
