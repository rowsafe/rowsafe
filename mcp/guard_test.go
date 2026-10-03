package mcp

import (
	"errors"
	"testing"
)

func TestDestructiveDBCommand(t *testing.T) {
	files := map[string]string{
		"migrations/001_drop.sql": "BEGIN;\nALTER TABLE users DROP COLUMN legacy;\nCOMMIT;\n",
		"seed.sql":                "INSERT INTO users (name) VALUES ('a');\n",
		"scripts/cleanup.js":      "db.getCollection('sessions').deleteMany({});\n",
		"scripts/report.js":       "printjson(db.orders.countDocuments({}));\n",
	}
	readFile := func(p string) ([]byte, error) {
		if s, ok := files[p]; ok {
			return []byte(s), nil
		}
		return nil, errors.New("no such file")
	}
	for _, tc := range []struct {
		cmd  string
		want bool
	}{
		// Migration tools.
		{"npx prisma migrate deploy", true},
		{"pnpm prisma migrate reset --force", true},
		{"DATABASE_URL=postgres://x npx prisma db push", true},
		{"cd api && npx prisma migrate dev --name add_orders", true},
		{"npx prisma migrate status", false},
		{"npx prisma generate", false},
		{"npx prisma migrate diff --from-empty --to-schema-datamodel schema.prisma", false},
		{"bin/rails db:migrate", true},
		{"bundle exec rake db:drop db:create", true},
		{"RAILS_ENV=production bundle exec rails db:rollback STEP=2", true},
		{"docker compose exec web bin/rails db:schema:load", true},
		{"bin/rails db:migrate:status", false},
		{"bin/rails db:create", false},
		{"bin/rails generate migration AddOrders", false},
		{"alembic upgrade head", true},
		{"poetry run alembic downgrade -1", true},
		{"alembic upgrade head --sql > out.sql", false},
		{"alembic revision --autogenerate -m 'add orders'", false},
		{"alembic history", false},
		{"python manage.py migrate", true},
		{"python3 manage.py flush --no-input", true},
		{"uv run manage.py migrate orders 0003", true},
		{"python manage.py makemigrations", false},
		{"python manage.py showmigrations", false},
		{"python manage.py migrate --plan", false},
		{"npx knex migrate:latest", true},
		{"npx knex migrate:make add_orders", false},
		{"npx sequelize-cli db:migrate", true},
		{"npx sequelize-cli db:migrate:status", false},
		{"npx typeorm-ts-node-commonjs migration:run -d src/data-source.ts", true},
		{"npx typeorm migration:generate src/migrations/Add", false},
		{"npx drizzle-kit push", true},
		{"npx drizzle-kit generate", false},
		{"goose -dir db/migrations postgres \"$DATABASE_URL\" up", true},
		{"goose -dir db/migrations postgres \"$DATABASE_URL\" status", false},
		{"migrate -path db/migrations -database \"$DATABASE_URL\" up", true},
		{"migrate create -ext sql -dir db/migrations add_orders", false},
		{"dbmate up", true},
		{"dbmate new add_orders", false},
		{"atlas schema apply --url $DB --to file://schema.hcl", true},
		{"sqlx migrate run", true},
		{"sqlx migrate add orders", false},
		{"diesel migration run", true},
		{"flyway clean", true},
		{"flyway info", false},
		{"liquibase update", true},
		{"mix ecto.migrate", true},
		{"mix ecto.gen.migration add_orders", false},
		{"php artisan migrate:fresh --seed", true},
		{"php artisan migrate:status", false},
		{"supabase db reset", true},
		{"supabase db diff", false},
		{"npm run db:migrate", true},
		{"yarn migrate", true},
		{"npm run migrate:status", false},
		{"npm run build", false},
		{"npm test", false},

		// psql and friends.
		{`psql "$DATABASE_URL" -c "DROP TABLE orders"`, true},
		{`psql -c 'truncate table sessions'`, true},
		{`psql -c "DELETE FROM orders"`, true},
		{`psql -c "DELETE FROM orders WHERE id = 42"`, false},
		{`psql -c "UPDATE users SET admin = true"`, true},
		{`psql -c "update users set admin = true where id = 1"`, false},
		{`psql -c "SELECT count(*) FROM orders"`, false},
		{"psql $DATABASE_URL <<'SQL'\nALTER TABLE users DROP COLUMN legacy;\nSQL", true},
		{`echo "DROP SCHEMA public CASCADE" | psql app`, true},
		{"sudo -u postgres psql -d app -f migrations/001_drop.sql", true},
		{"psql -d app -f seed.sql", false},
		{"psql -l", false},
		{"docker exec -i db psql -U postgres -c 'drop database app'", true},
		{"kubectl exec deploy/pg -- psql -c \"TRUNCATE events\"", true},
		{"dropdb app_production", true},
		{"pg_restore --clean -d app dump.pgdump", true},
		{"pg_restore -cC -d postgres dump.pgdump", true},
		{"pg_restore -l dump.pgdump", false},
		{"pg_dump app > app.sql", false},
		{`bash -c "bin/rails db:migrate"`, true},
		{`bash -lc "npx prisma migrate deploy"`, true},
		{`sh -ec 'psql -c "DROP TABLE users"'`, true},
		{`zsh -ic "npm test"`, false},
		{`grep -ic "DROP TABLE" schema.sql`, false},

		// MySQL and MariaDB.
		{`mysql -h db.internal -u app -p app -e "DROP TABLE orders"`, true},
		{`mysql app -e 'DELETE FROM ` + "`orders`" + `'`, true},
		{`mariadb -e "UPDATE users SET admin = 1 WHERE id = 7"`, false},
		{`mysql -e "ALTER TABLE users MODIFY COLUMN email VARCHAR(50)"`, true},
		{`mysql -e "ALTER TABLE users ADD COLUMN ts TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"`, false},
		{`mysql -e "RENAME TABLE users TO users_old"`, true},
		{"mysql app < migrations/001_drop.sql", true},
		{"mysql app <seed.sql", false},
		{"docker exec -i db mariadb -uroot app -e 'truncate sessions'", true},
		{"mysqladmin -u root drop app", true},
		{"mysqladmin status", false},
		{"mysql -h db -e 'SELECT 1'", false},
		{"mysqldump app > app.sql", false},
		{"myloader -d dump --overwrite-tables", true},

		// MongoDB.
		{`mongosh app --eval 'db.orders.drop()'`, true},
		{`mongosh "$MONGO_URL" --eval "db.dropDatabase()"`, true},
		{`mongosh --eval 'db.sessions.deleteMany({})'`, true},
		{`mongosh --eval 'db.sessions.deleteMany({ expired: true })'`, false},
		{`mongosh --eval 'db.users.updateMany({}, {$set: {admin: true}})'`, true},
		{`mongosh --eval 'db.users.find({}).count()'`, false},
		{`mongo app --eval 'db.runCommand({drop: "orders"})'`, true},
		{"mongosh app scripts/cleanup.js", true},
		{"mongosh app scripts/report.js", false},
		{"mongorestore --drop dump/", true},
		{"mongorestore dump/", false},

		// ClickHouse.
		{`clickhouse-client --query "DROP TABLE events"`, true},
		{`clickhouse client -q "ALTER TABLE events DELETE WHERE ts < now() - INTERVAL 1 DAY"`, true},
		{`clickhouse-client -q "ALTER TABLE events UPDATE status = 'x' WHERE 1"`, true},
		{`clickhouse-client -q "ALTER TABLE events DROP PARTITION 202401"`, true},
		{`clickhouse-client -q "ALTER TABLE events ADD COLUMN updated DateTime"`, false},
		{`clickhouse-client -q "SELECT count() FROM events"`, false},
		{"clickhouse-client --queries-file migrations/001_drop.sql", true},
		{"docker exec ch clickhouse-client -q 'TRUNCATE TABLE events'", true},

		// Mentions that don't run anything.
		{`git commit -m "run prisma migrate deploy on release"`, false},
		{`grep -rn "DROP TABLE" migrations/`, false},
		{`echo "remember: rails db:migrate"`, false},
		{`rg "alembic upgrade" docs/`, false},
		{"cat migrations/001_drop.sql", false},
		{"npx prisma migrate deploy --help", false},
		{"ls -la", false},
		{"go test ./...", false},
		{"DROP=1 make", false},
	} {
		reason, got := DestructiveDBCommand(tc.cmd, readFile)
		if got != tc.want {
			t.Errorf("DestructiveDBCommand(%q) = %v (%q), want %v", tc.cmd, got, reason, tc.want)
		}
		if got && reason == "" {
			t.Errorf("DestructiveDBCommand(%q) matched without a reason", tc.cmd)
		}
	}
}
