-- rails db:migrate (ActiveRecord's SQL, from the log): add_index, add_column, add_foreign_key
CREATE INDEX "index_users_on_email" ON "users" ("email");
ALTER TABLE "users" ADD "last_seen_at" timestamp(6);
ALTER TABLE "orders" ADD CONSTRAINT "fk_rails_f868b47f6a" FOREIGN KEY ("user_id")
  REFERENCES "users" ("id");
