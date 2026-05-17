-- Migration for legacy databases created before `groups.is_admin` existed.
-- `sqlx::migrate!` runs this once; CREATE TABLE in 0001 already includes the
-- column so fresh databases skip the ALTER. We use a no-op SELECT here because
-- IF NOT EXISTS for ALTER is not portable; the database module performs a
-- PRAGMA-driven check before running this migration on older databases.
SELECT 1;
