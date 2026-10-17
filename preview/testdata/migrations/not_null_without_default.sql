-- knex: table.bigInteger('tenant_id').notNullable()
alter table "users" add column "tenant_id" bigint not null;
