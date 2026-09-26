package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/tune"
)

// rowsafe settings and rowsafe tune: PostgreSQL's settings, what suits the
// server, and changing them. Every change goes through the control plane,
// which saves a Mark first on a backed-up database and queues a settings
// task; the agent checks the values again and runs ALTER SYSTEM + reload.
// Nothing restarts here: rowsafe restart does, when the person chooses.

// settingsCmd is rowsafe settings [NAME] [SETTING], rowsafe settings set
// and rowsafe settings undo.
func settingsCmd(ctx context.Context, c *client.Client, args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "set":
			return settingsSet(ctx, c, args[1:])
		case "undo":
			return settingsUndo(ctx, c, args[1:])
		}
	}
	fs := flag.NewFlagSet("settings", flag.ContinueOnError)
	all := fs.Bool("all", false, "also list the other settings set in a configuration file")
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	db, setting, err := settingsArgs(ctx, c, pos)
	if err != nil {
		return err
	}
	ov, err := c.Settings(ctx, db, "", "")
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(ov)
	}
	if !ov.Available {
		fmt.Println(orText(ov.Reason, "The agent hasn't reported this database's settings yet."))
		return nil
	}
	if setting != "" {
		return printSetting(db, ov, setting)
	}
	printSettings(db, ov, *all)
	return nil
}

// settingsArgs splits [NAME] [SETTING]: one argument is the database if it
// names one, else a setting of the project's database.
func settingsArgs(ctx context.Context, c *client.Client, pos []string) (db, setting string, err error) {
	switch len(pos) {
	case 0:
	case 1:
		dbs, err := c.Databases(ctx)
		if err != nil {
			return "", "", err
		}
		if slices.ContainsFunc(dbs, func(d protocol.Database) bool { return d.Name == pos[0] || d.ID == pos[0] }) {
			db = pos[0]
		} else {
			setting = pos[0]
		}
	case 2:
		db, setting = pos[0], pos[1]
	default:
		return "", "", errors.New("expected [NAME] [SETTING]")
	}
	db, err = resolveDatabase(ctx, c, db)
	return db, strings.ToLower(setting), err
}

func hostLine(h protocol.SettingsHost) string {
	var parts []string
	if h.MemoryBytes > 0 {
		parts = append(parts, tune.HumanBytes(h.MemoryBytes)+" memory")
	}
	if h.CPUs > 0 {
		parts = append(parts, fmt.Sprintf("%d %s", h.CPUs, plural(h.CPUs, "CPU", "CPUs")))
	}
	switch h.Disk {
	case protocol.DiskSSD:
		parts = append(parts, "SSD")
	case protocol.DiskHDD:
		parts = append(parts, "spinning disk")
	}
	return strings.Join(parts, ", ")
}

func settingValue(s protocol.SettingView) string {
	v := s.Value
	if s.PendingRestart && s.PendingValue != "" {
		v += " -> " + s.PendingValue + " after a restart"
	}
	return v
}

func printSettings(db string, ov protocol.SettingsOverview, all bool) {
	fmt.Printf("PostgreSQL settings of %s", db)
	if h := hostLine(ov.Host); h != "" {
		fmt.Printf(" (%s)", h)
	}
	fmt.Println()
	for _, cat := range tune.Categories {
		var rows []protocol.SettingView
		for _, s := range ov.Settings {
			if s.Category == cat.ID {
				rows = append(rows, s)
			}
		}
		if len(rows) == 0 {
			continue
		}
		fmt.Printf("\n%s\n", cat.Title)
		t := newTable("  SETTING", "VALUE", "DEFAULT", "SET IN", "CHANGE")
		for _, s := range rows {
			apply := "applies at once"
			if s.Apply == "restart" {
				apply = "needs a restart"
			}
			if s.Locked {
				apply = "managed by Rowsafe"
			}
			t.row("  "+s.Name, settingValue(s), s.Default, s.Source, apply)
		}
		t.flush()
	}
	if all && len(ov.Other) > 0 {
		fmt.Printf("\nOther settings set in a configuration file\n")
		t := newTable("  SETTING", "VALUE", "SET IN", "CHANGE")
		for _, s := range ov.Other {
			apply := "applies at once"
			if s.Apply == "restart" {
				apply = "needs a restart"
			}
			if s.Locked {
				apply = "managed by Rowsafe"
			}
			t.row("  "+s.Name, settingValue(s), s.Source, apply)
		}
		t.flush()
	} else if len(ov.Other) > 0 {
		fmt.Printf("\n%s set in a configuration file: --all lists them.\n", fmt.Sprintf("%d %s", len(ov.Other), plural(len(ov.Other), "other setting", "other settings")))
	}
	for _, e := range ov.ConfigErrors {
		fmt.Printf("\nConfiguration error: %s\n", e)
	}
	if len(ov.PendingRestart) > 0 {
		fmt.Printf("\nWaiting for a restart: %s. `rowsafe restart %s` restarts PostgreSQL (asks first).\n", strings.Join(ov.PendingRestart, ", "), db)
	}
	if n := countRequired(ov.Recommendations); n > 0 {
		fmt.Printf("\nRowsafe recommends %s for this server: `rowsafe tune %s` shows them.\n", fmt.Sprintf("%d %s", n, plural(n, "change", "changes")), db)
	}
	printChanges(db, ov.Changes, 5)
}

func countRequired(recs []protocol.Recommendation) int {
	n := 0
	for _, r := range recs {
		if !r.Optional {
			n++
		}
	}
	return n
}

func printChanges(db string, changes []protocol.SettingsChange, limit int) {
	if len(changes) == 0 {
		return
	}
	fmt.Printf("\nChanges made through Rowsafe\n")
	t := newTable("  ID", "WHEN", "BY", "STATUS", "WHAT")
	for _, ch := range changes[:min(len(changes), limit)] {
		what := ch.Summary
		if what == "" {
			var names []string
			for _, r := range ch.Requested {
				names = append(names, r.Name)
			}
			what = strings.Join(names, ", ")
		}
		status := ch.Status
		if ch.RevertedBy != "" {
			status = "undone"
		}
		t.row("  "+ch.ID, ago(&ch.CreatedAt), ch.CreatedBy, status, firstLine(what, 70))
	}
	t.flush()
	if i := slices.IndexFunc(changes, func(ch protocol.SettingsChange) bool { return ch.CanRevert }); i >= 0 {
		fmt.Printf("Undo the latest: rowsafe settings undo %s %s\n", db, changes[i].ID)
	}
}

func printSetting(db string, ov protocol.SettingsOverview, name string) error {
	i := slices.IndexFunc(append(slices.Clone(ov.Settings), ov.Other...), func(s protocol.SettingView) bool { return s.Name == name })
	if i < 0 {
		return fmt.Errorf("%s isn't among the settings Rowsafe shows for %s (the ones that matter, and those set in a configuration file)", name, db)
	}
	s := append(slices.Clone(ov.Settings), ov.Other...)[i]
	fmt.Printf("%s", s.Name)
	if s.Title != "" {
		fmt.Printf(": %s", s.Title)
	}
	fmt.Printf("\n\n")
	if s.Explanation != "" {
		fmt.Printf("%s\n\n", s.Explanation)
	}
	fmt.Printf("Value:    %s\n", settingValue(s))
	fmt.Printf("Default:  %s\n", s.Default)
	fmt.Printf("Set in:   %s\n", s.Source)
	switch {
	case s.Locked:
		fmt.Printf("Change:   never through Rowsafe. %s\n", s.LockedReason)
	case s.Apply == "restart":
		fmt.Printf("Change:   takes effect after a restart: rowsafe settings set %s %s=VALUE\n", db, s.Name)
	default:
		fmt.Printf("Change:   applies at once: rowsafe settings set %s %s=VALUE\n", db, s.Name)
	}
	for _, r := range ov.Recommendations {
		if r.Name == s.Name {
			fmt.Printf("\nRecommended: %s. %s\n", r.Display, r.Why)
		}
	}
	return nil
}

// settingsSet is rowsafe settings set [NAME] SETTING=VALUE...
func settingsSet(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("settings set", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask for confirmation")
	noWait := fs.Bool("no-wait", false, "return once the change is queued")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	name := ""
	if len(pos) > 0 && !strings.Contains(pos[0], "=") {
		name, pos = pos[0], pos[1:]
	}
	if len(pos) == 0 {
		return errors.New("expected SETTING=VALUE, e.g. rowsafe settings set mydb work_mem=64MB (VALUE default resets it)")
	}
	var changes []protocol.SettingChange
	for _, kv := range pos {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || strings.TrimSpace(k) == "" {
			return fmt.Errorf("%q: expected SETTING=VALUE", kv)
		}
		ch := protocol.SettingChange{Name: strings.ToLower(strings.TrimSpace(k)), Value: strings.TrimSpace(v)}
		if strings.EqualFold(ch.Value, "default") {
			ch = protocol.SettingChange{Name: ch.Name, Reset: true}
		}
		changes = append(changes, ch)
	}
	db, err := resolveDatabase(ctx, c, name)
	if err != nil {
		return err
	}
	ov, err := c.Settings(ctx, db, "", "")
	if err != nil {
		return err
	}
	cur := map[string]protocol.SettingView{}
	for _, s := range append(slices.Clone(ov.Settings), ov.Other...) {
		cur[s.Name] = s
	}
	fmt.Printf("Change PostgreSQL settings of %s:\n", db)
	restart := false
	for _, ch := range changes {
		s, known := cur[ch.Name]
		from := "?"
		if known {
			from = settingValue(s)
		}
		to := ch.Value
		if ch.Reset {
			to = "its default"
		}
		note := ""
		if known && s.Apply == "restart" {
			note, restart = " (after a restart)", true
		}
		fmt.Printf("  %s: %s -> %s%s\n", ch.Name, from, to, note)
	}
	return applySettings(ctx, c, db, ov, protocol.ApplySettingsRequest{Kind: protocol.SettingsKindSet, Changes: changes}, restart, *yes, *noWait)
}

// tuneCmd is rowsafe tune [NAME]: the recommendations for the server, and
// applying them.
func tuneCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("tune", flag.ContinueOnError)
	workload := fs.String("workload", "", "what the database serves: web, analytics or mixed (default: the saved choice, else mixed)")
	disk := fs.String("disk", "", "the data disk: ssd or hdd (default: what the server reports)")
	all := fs.Bool("all", false, "also apply the optional recommendations")
	yes := fs.Bool("yes", false, "don't ask for confirmation")
	noWait := fs.Bool("no-wait", false, "return once the change is queued")
	asJSON := fs.Bool("json", false, "print the recommendations as JSON; change nothing")
	db, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	if *workload != "" && !tune.ValidWorkload(*workload) {
		return errors.New("--workload must be web, analytics or mixed")
	}
	if *disk != "" && *disk != protocol.DiskSSD && *disk != protocol.DiskHDD {
		return errors.New("--disk must be ssd or hdd")
	}
	ov, err := c.Settings(ctx, db, *workload, *disk)
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(ov.Recommendations)
	}
	if !ov.Available {
		fmt.Println(orText(ov.Reason, "The agent hasn't reported this database's settings yet."))
		return nil
	}
	fmt.Printf("Tune %s for this server (%s; workload: %s)\n", db, hostLine(ov.Host), ov.Workload)
	var picked []protocol.Recommendation
	for _, r := range ov.Recommendations {
		if !r.Optional || *all {
			picked = append(picked, r)
		}
	}
	if len(ov.Recommendations) == 0 {
		fmt.Println("\nNothing to change: the settings already suit this server.")
		return nil
	}
	restart := false
	fmt.Println()
	for _, r := range ov.Recommendations {
		mark := "  "
		if !r.Optional || *all {
			mark = "* "
		}
		note := ""
		if r.Restart {
			note, restart = " (after a restart)", restart || !r.Optional || *all
		}
		if r.Optional && !*all {
			note += " (optional: --all adds it)"
		}
		fmt.Printf("%s%s: %s -> %s%s\n    %s\n", mark, r.Name, r.Current, r.Display, note, r.Why)
	}
	if len(picked) == 0 {
		fmt.Println("\nOnly optional changes: add --all to apply them.")
		return nil
	}
	req := protocol.ApplySettingsRequest{Kind: protocol.SettingsKindTune, Workload: *workload, Disk: *disk}
	for _, r := range picked {
		req.Changes = append(req.Changes, protocol.SettingChange{Name: r.Name, Value: r.Value})
	}
	return applySettings(ctx, c, db, ov, req, restart, *yes, *noWait)
}

func applySettings(ctx context.Context, c *client.Client, db string, ov protocol.SettingsOverview, req protocol.ApplySettingsRequest, restart, yes, noWait bool) error {
	if !ov.CanChange {
		return errors.New(orText(ov.ChangeReason, "Rowsafe can't change settings on this database now"))
	}
	fmt.Println()
	fmt.Println("Rowsafe changes them with ALTER SYSTEM and reloads PostgreSQL; you can undo it in one step.")
	if restart {
		fmt.Println("Some take effect only after PostgreSQL restarts; nothing restarts now.")
	}
	if !yes && !confirm(fmt.Sprintf("Apply %s?", fmt.Sprintf("%d %s", len(req.Changes), plural(len(req.Changes), "change", "changes")))) {
		return errors.New("cancelled; nothing was changed")
	}
	resp, err := c.ApplySettings(ctx, db, req)
	var ae *client.APIError
	if errors.As(err, &ae) {
		return fmt.Errorf("not changed: %s", ae.Msg)
	}
	if err != nil {
		return err
	}
	if noWait {
		fmt.Printf("Queued (change %s).\n", resp.ChangeID)
		return nil
	}
	return waitSettings(ctx, c, db, resp)
}

// waitSettings follows a change's tasks (a Mark first, then the change).
func waitSettings(ctx context.Context, c *client.Client, db string, resp protocol.ApplySettingsResponse) error {
	for _, t := range resp.Tasks {
		if t.Type == protocol.TaskRestorePoint {
			if err := waitFixTask(ctx, c, t, db); err != nil {
				return err
			}
			continue
		}
		last := ""
		done, err := c.WaitTask(ctx, t.ID, func(v protocol.TaskView) {
			if v.Status != last {
				last = v.Status
				if v.Status == protocol.StatusQueued {
					fmt.Fprintf(os.Stderr, "Waiting for the agent (task %s)...\n", v.ID)
				}
			}
		})
		if err != nil {
			return err
		}
		if done.Status != protocol.StatusSucceeded {
			fmt.Printf("Not changed: %s\n", orText(done.Error, "the task ended as "+done.Status))
			return exitError(1)
		}
		var r protocol.SettingsResult
		_ = json.Unmarshal(done.Result, &r)
		fmt.Println(orText(r.Summary, "Done."))
		if slices.ContainsFunc(r.Applied, func(a protocol.AppliedSetting) bool { return a.Restart }) {
			fmt.Printf("Restart PostgreSQL when it suits you: rowsafe restart %s (asks first).\n", db)
		}
		fmt.Printf("Undo: rowsafe settings undo %s %s\n", db, resp.ChangeID)
	}
	return nil
}

// settingsUndo is rowsafe settings undo [NAME] [CHANGE_ID]: the latest
// change that can be undone, or the one named.
func settingsUndo(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("settings undo", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask for confirmation")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	name, id := "", ""
	switch len(pos) {
	case 0:
	case 1:
		if strings.HasPrefix(pos[0], "stc_") {
			id = pos[0]
		} else {
			name = pos[0]
		}
	case 2:
		name, id = pos[0], pos[1]
	default:
		return errors.New("expected [NAME] [CHANGE_ID]")
	}
	db, err := resolveDatabase(ctx, c, name)
	if err != nil {
		return err
	}
	ov, err := c.Settings(ctx, db, "", "")
	if err != nil {
		return err
	}
	i := slices.IndexFunc(ov.Changes, func(ch protocol.SettingsChange) bool {
		return (id == "" && ch.CanRevert) || ch.ID == id
	})
	if i < 0 {
		if id != "" {
			return fmt.Errorf("no change %s on %s", id, db)
		}
		return fmt.Errorf("nothing to undo on %s", db)
	}
	ch := ov.Changes[i]
	if !ch.CanRevert {
		return fmt.Errorf("change %s can't be undone: only the latest change of a setting that succeeded and wasn't undone yet can", ch.ID)
	}
	fmt.Printf("Undo change %s on %s (%s by %s):\n", ch.ID, db, ago(&ch.CreatedAt), ch.CreatedBy)
	for _, a := range ch.Applied {
		back := "its default"
		if a.Previous != nil {
			back = *a.Previous
		}
		fmt.Printf("  %s back to %s\n", a.Name, back)
	}
	if !*yes && !confirm("Undo it?") {
		return errors.New("cancelled; nothing was changed")
	}
	resp, err := c.RevertSettings(ctx, db, ch.ID)
	var ae *client.APIError
	if errors.As(err, &ae) {
		return fmt.Errorf("not undone: %s", ae.Msg)
	}
	if err != nil {
		return err
	}
	return waitSettings(ctx, c, db, resp)
}
