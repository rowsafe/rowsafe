package agent

import (
	"fmt"
	"io"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// printEnginePlan explains a MySQL or MariaDB adopt plan in plain words.
func printEnginePlan(w io.Writer, r protocol.AdoptResult, arrow string) {
	in := r.Inspect
	name := protocol.EngineDisplayName(in.MySQL.Engine)
	var names []string
	for _, d := range in.Databases {
		names = append(names, d.Name)
	}
	what := "no databases of your own yet"
	switch len(names) {
	case 0:
	case 1:
		what = "1 database (" + names[0] + ")"
	default:
		what = fmt.Sprintf("%d databases (%s)", len(names), strings.Join(names, ", "))
	}
	fmt.Fprintf(w, "%s %s on port %d: %s, %s.\n\n", name, in.ServerVersion, in.Port, humanBytes(in.TotalSizeBytes), what)
	if r.Applied {
		fmt.Fprintln(w, "What Rowsafe changed:")
	} else {
		fmt.Fprintln(w, "What Rowsafe will change:")
	}
	for _, c := range r.Plan {
		fmt.Fprintf(w, "  - %s\n", describeEngineChange(c, arrow))
	}
	for _, warn := range r.Warnings {
		fmt.Fprintf(w, "  ! %s\n", warn)
	}
	fmt.Fprintln(w)
	if r.RestartRequired {
		fmt.Fprintf(w, "Restart: %s needs one quick restart (a few seconds) before backups start.\n", name)
		fmt.Fprintln(w, "         It only restarts if you say so.")
	} else {
		fmt.Fprintf(w, "No downtime: %s does not need a restart.\n", name)
	}
}

func describeEngineChange(c protocol.Change, arrow string) string {
	restart := ""
	if c.Restart {
		restart = ", needs a restart"
	}
	if c.Kind != "setting" {
		return c.Description
	}
	switch c.Setting {
	case "log_bin":
		return "Turn on the binary log, the server's record of every change, so Rowsafe can restore to any second (log_bin: " +
			c.From + " " + arrow + " " + c.To + restart + ")"
	case "binlog_format":
		return "Record changed rows exactly (binlog_format: " + c.From + " " + arrow + " " + c.To + restart + ")"
	case "binlog_row_image":
		return "Record whole rows (binlog_row_image: " + c.From + " " + arrow + " " + c.To + restart + ")"
	case "server_id":
		return "Give the server an ID, which the binary log needs (server_id: " + c.From + " " + arrow + " " + c.To + restart + ")"
	}
	return fmt.Sprintf("Change %s: %s %s %s%s", c.Setting, c.From, arrow, c.To, restart)
}
