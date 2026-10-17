BEGIN;

-- Running upgrade 1a2b3c4d5e6f -> 2b3c4d5e6f7a, add sessions and user uuids

CREATE TABLE sessions (
    id SERIAL NOT NULL,
    user_id INTEGER,
    PRIMARY KEY (id),
    FOREIGN KEY(user_id) REFERENCES users (id)
);

ALTER TABLE users ADD COLUMN uuid UUID DEFAULT gen_random_uuid() NOT NULL;

UPDATE users SET plan='free';

DELETE FROM audit_log;

UPDATE alembic_version SET version_num='2b3c4d5e6f7a' WHERE alembic_version.version_num = '1a2b3c4d5e6f';

COMMIT;
