package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/rowsafe/rowsafe/internal/indexadvisor"
	"github.com/rowsafe/rowsafe/internal/indexadvisor/sqlshape"
)

// sqlShapes is the index advisor's parser process: a JSON array of
// statements on stdin, a JSON array of their shapes on stdout. The agent
// runs it as a child so the parser's memory is released when it exits.
func sqlShapes() int {
	data, err := io.ReadAll(io.LimitReader(os.Stdin, 16<<20))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	var queries []string
	if err := json.Unmarshal(data, &queries); err != nil {
		fmt.Fprintln(os.Stderr, "error: want a JSON array of statements:", err)
		return 2
	}
	out := make([]indexadvisor.Shape, len(queries))
	for i, q := range queries {
		out[i] = sqlshape.Parse(q)
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}
