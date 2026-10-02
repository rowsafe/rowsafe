package mysql

import (
	"slices"
	"testing"
)

func TestParseShape(t *testing.T) {
	cases := []struct {
		q, schema string
		ok        bool
		table     string
		cand      []string
	}{
		{"SELECT * FROM `shop` . `orders` WHERE `customer_id` = ? AND `created_at` > ? ORDER BY `created_at` DESC LIMIT ?", "", true, "shop.orders", []string{"customer_id", "created_at"}},
		{"SELECT `o` . `id` FROM `orders` `o` WHERE `o` . `status` IN ( ... ) ORDER BY `o` . `created_at`", "shop", true, "shop.orders", []string{"status", "created_at"}},
		{"SELECT COUNT ( * ) FROM `orders` WHERE `customer_id` = ? AND `status` != ?", "shop", false, "", nil},
		{"UPDATE `carts` SET `items` = ? WHERE `session_id` = ?", "shop", true, "shop.carts", []string{"session_id"}},
		{"DELETE FROM `jobs` WHERE `finished_at` < ?", "shop", true, "shop.jobs", []string{"finished_at"}},
		{"SELECT * FROM `a` JOIN `b` ON `a` . `id` = `b` . `a_id` WHERE `b` . `x` = ?", "shop", false, "", nil},
		{"SELECT * FROM `a` WHERE `x` = ? OR `y` = ?", "shop", false, "", nil},
		{"SELECT * FROM `a` WHERE `x` BETWEEN ? AND ? AND `y` = ?", "shop", true, "shop.a", []string{"y", "x"}},
		{"SELECT * FROM `a` WHERE `x` = 'abc' AND `y` IS NULL", "shop", true, "shop.a", []string{"x", "y"}},
		{"SELECT * FROM `a` WHERE `id` IN ( SELECT `a_id` FROM `b` )", "shop", false, "", nil},
		{"SELECT * FROM `a`", "", false, "", nil},
	}
	for _, c := range cases {
		s, ok := parseShape(c.q, c.schema)
		if ok != c.ok {
			t.Errorf("%s: ok = %v", c.q, ok)
			continue
		}
		if !ok {
			continue
		}
		if s.Schema+"."+s.Table != c.table || !slices.Equal(s.candidate(), c.cand) {
			t.Errorf("%s: got %s.%s %v", c.q, s.Schema, s.Table, s.candidate())
		}
	}
}
