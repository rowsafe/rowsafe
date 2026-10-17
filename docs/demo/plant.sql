-- SPDX-License-Identifier: Apache-2.0
--
-- Plants the problems the demo finds: a table that is two thirds dead rows
-- (autovacuum off on it, as after a bulk delete it never caught up with) and
-- a duplicate index. record.sh adds the third: a session left idle inside a
-- transaction.

CREATE EXTENSION pg_stat_statements;

CREATE TABLE orders (
  id          bigserial PRIMARY KEY,
  customer_id int NOT NULL,
  total       numeric(10, 2) NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
) WITH (autovacuum_enabled = off);

INSERT INTO orders (customer_id, total, created_at)
SELECT (random() * 20000)::int, round((random() * 200)::numeric, 2),
       now() - random() * interval '365 days'
FROM generate_series(1, 300000);

CREATE INDEX orders_customer_idx ON orders (customer_id);
CREATE INDEX orders_customer_id_idx ON orders (customer_id);

-- 200,000 dead rows.
DELETE FROM orders WHERE id % 3 <> 0;

CREATE TABLE customers (id int PRIMARY KEY, name text NOT NULL);
INSERT INTO customers SELECT g, 'customer ' || g FROM generate_series(1, 20000) g;

-- Use the indexes once so they don't also show up as unused.
SET enable_seqscan = off;
SELECT count(*) FROM orders WHERE customer_id = 42;
