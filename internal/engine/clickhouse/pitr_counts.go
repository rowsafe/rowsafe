package clickhouse

import (
	"context"
	"fmt"
	"strings"
)

// Counts for Find the moment, worked out by the copier as parts appear
// (pitr_model.go pitPart.Change...): only kinds and row counts, read on
// this server.

// annotate fills in what made each new part and the rows it removed, and
// keeps st.Existing (the rows each part on disk holds that no lightweight
// DELETE hid) up to date.
func annotate(ctx context.Context, c *client, st *shipLocal, news []livePart, parts []livePart, tables map[string]liveTable) map[string]*pitPart {
	out := map[string]*pitPart{}
	if st.Existing == nil {
		st.Existing = map[string]int64{}
	}
	byTable := map[string][]livePart{}
	for _, p := range parts {
		byTable[p.Table] = append(byTable[p.Table], p)
	}
	var kinds map[string]string
	toCount := map[string][]string{} // table UUID -> parts to count
	for _, p := range news {
		info := parsePartName(p.Name, p.Partition)
		a := &pitPart{}
		out[p.Table+"/"+p.Name] = a
		switch {
		case info.ok && info.Mutation > 0 && p.Rows > 0 && sourceOf(byTable[p.Table], p, info) != nil:
			if kinds == nil {
				kinds = mutationKinds(ctx, c)
			}
			k := kinds[fmt.Sprintf("%s/%s/%d", p.Table, info.Partition, info.Mutation)]
			if k == "" {
				k = kinds[fmt.Sprintf("%s//%d", p.Table, info.Mutation)]
			}
			a.Mutation = fmt.Sprintf("%s/%d", p.Table, info.Mutation)
			switch k {
			case "delete", "lwdelete":
				a.Change = "delete"
				toCount[p.Table] = append(toCount[p.Table], p.Name)
			case "update":
				a.Change = "update"
			}
		case info.ok && p.Rows == 0 && info.Level > 0:
			// An empty part covering others: TRUNCATE, DROP PARTITION.
			a.Change = "clear"
			for _, q := range byTable[p.Table] {
				if q.Name != p.Name && info.contains(parsePartName(q.Name, q.Partition)) {
					if n, ok := st.Existing[q.Table+"/"+q.Name]; ok {
						a.Cleared += n
					} else {
						a.Cleared += q.Rows
					}
				}
			}
		}
	}
	counted := map[string]int64{}
	for table, names := range toCount {
		t, ok := tables[table]
		if !ok {
			continue
		}
		for name, n := range existingRows(ctx, c, t.DB, t.Name, names) {
			counted[table+"/"+name] = n
		}
	}
	for _, p := range news {
		key := p.Table + "/" + p.Name
		a := out[key]
		n := p.Rows
		if v, ok := counted[key]; ok {
			n = v
		}
		info := parsePartName(p.Name, p.Partition)
		if src := sourceOf(byTable[p.Table], p, info); src != nil && info.Mutation > 0 {
			before, ok := st.Existing[p.Table+"/"+src.Name]
			if !ok {
				before = src.Rows
			}
			if _, ok := counted[key]; !ok && a.Change != "delete" {
				n = before // an UPDATE (or a change of columns) keeps the rows
			}
			if a.Change == "delete" && before > n {
				a.Deleted = before - n
			}
		}
		st.Existing[key] = n
	}
	return out
}

// sourceOf is the part a mutated part p replaced: the same block range and
// level, the newest mutation before p's.
func sourceOf(table []livePart, p livePart, info partInfo) *livePart {
	var best *livePart
	var bestMut int64 = -1
	for i := range table {
		q := &table[i]
		qi := parsePartName(q.Name, q.Partition)
		if q.Name == p.Name || !qi.ok || qi.Partition != info.Partition || qi.Min != info.Min || qi.Max != info.Max ||
			qi.Level != info.Level || qi.Mutation >= info.Mutation {
			continue
		}
		if qi.Mutation > bestMut {
			best, bestMut = q, qi.Mutation
		}
	}
	return best
}

// tableRows is what a table's parts on disk hold (st.Existing), for a
// dropped table.
func tableRows(st *shipLocal, uuid string) int64 {
	var n int64
	for k, v := range st.Existing {
		if strings.HasPrefix(k, uuid+"/") {
			n += v
		}
	}
	return n
}
