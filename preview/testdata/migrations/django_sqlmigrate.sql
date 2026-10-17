BEGIN;
--
-- Add field phone to customer
--
ALTER TABLE "shop_customer" ADD COLUMN "phone" varchar(20) DEFAULT '' NOT NULL;
ALTER TABLE "shop_customer" ALTER COLUMN "phone" DROP DEFAULT;
--
-- Alter field total on order
--
ALTER TABLE "shop_order" ALTER COLUMN "total" TYPE numeric(12, 2);
--
-- Create index shop_order_created_7b9e5c_idx on field(s) created of model order
--
CREATE INDEX "shop_order_created_7b9e5c_idx" ON "shop_order" ("created");
COMMIT;
