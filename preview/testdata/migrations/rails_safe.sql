-- A migration written with strong_migrations' advice: disable_ddl_transaction!,
-- algorithm: :concurrently, a lock_timeout.
SET lock_timeout = '5s';
SET statement_timeout = 0;
CREATE INDEX CONCURRENTLY "index_orders_on_created_at" ON "orders" ("created_at");
ALTER TABLE "users" ADD "nickname" character varying;
ALTER TABLE "orders" ADD CONSTRAINT "fk_rails_0001" FOREIGN KEY ("user_id") REFERENCES "users" ("id") NOT VALID;
ALTER TABLE "orders" VALIDATE CONSTRAINT "fk_rails_0001";
