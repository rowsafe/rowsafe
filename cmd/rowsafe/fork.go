package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// rowsafe fork: clone a database into a new, independent Rowsafe database
// from any moment of its recovery window, on another server or the same one
// on a new port. rowsafe forks lists a database's forks.

// forkPoll is how often the CLI checks a fork's progress (tests shorten it).
var forkPoll = 3 * time.Second

func forkCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("fork", flag.ContinueOnError)
	to := fs.String("to", "", "the server the fork goes to (its hostname; the source's own server for a new port there)")
	name := fs.String("name", "", "the fork's name in Rowsafe (default: SOURCE-fork)")
	at, mark := rewindTargetFlags(fs)
	mask := fs.Bool("mask", false, "mask personal data (emails, names, phone numbers, ...) before anyone can connect")
	port := fs.Int("port", 0, "the port of the new PostgreSQL cluster (default: a free one)")
	intoPort := fs.Int("into-port", 0, "use this existing, empty PostgreSQL cluster instead of creating one")
	fingerprint := fs.String("fingerprint", "", "the target server's key fingerprint (sudo -u postgres rowsafe-agent key, there)")
	noWait := fs.Bool("no-wait", false, "return once queued")
	asJSON := fs.Bool("json", false, "print the fork as JSON")
	source, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	info, err := c.Forks(ctx, source)
	if err != nil {
		return apiErr(err)
	}
	if !info.CanFork {
		return fmt.Errorf("%s can't be forked yet: %s", source, orText(info.Hint, "it isn't protected yet"))
	}
	target, err := pickForkTarget(info, *to)
	if err != nil {
		return err
	}
	place, err := pickForkPlace(*target, *port, *intoPort)
	if err != nil {
		return err
	}
	req := protocol.CreateForkRequest{Name: *name, HostID: target.HostID, Placement: place.Placement, Port: place.Port, Mask: *mask}
	if req.Name == "" {
		req.Name = source + "-fork"
	}
	when := "now (Rowsafe saves a Mark first)"
	if *at != "" || *mark != "" {
		t, m, desc, err := rewindTarget(*at, *mark)
		if err != nil {
			return err
		}
		req.At, req.Mark, when = t, m, desc
	}
	where := target.Hostname
	if target.SameServer {
		where += " (the same server)"
	}
	fmt.Printf("Fork %s as it was at %s onto %s: %s, as the new database %s.\n", source, when, where, place.Label, req.Name)
	if *mask {
		fmt.Println("  Personal data is masked before anyone can connect.")
	}
	if !target.SameServer {
		fmt.Printf("  The bucket settings to read %s's backups are sealed to %s's agent key: %s\n", source, target.Hostname, target.Fingerprint)
		fmt.Printf("  Check it matches what `sudo -u postgres rowsafe-agent key` prints on %s.\n", target.Hostname)
		if *fingerprint == "" {
			if !stdinIsTerminal() {
				return errors.New("pass --fingerprint with the fingerprint `rowsafe-agent key` prints on the target server")
			}
			fmt.Printf("\nType the fingerprint %s prints to go ahead: ", target.Hostname)
			*fingerprint = strings.TrimSpace(readLine())
		}
		req.Fingerprint = *fingerprint
	}
	v, err := c.CreateFork(ctx, source, req)
	if err != nil {
		return apiErr(err)
	}
	if *noWait {
		if *asJSON {
			return printForkJSON(v)
		}
		fmt.Printf("Queued (fork %s). Follow it with: rowsafe forks %s\n", v.ID, source)
		return nil
	}
	fmt.Println()
	v, err = waitFork(ctx, c, v)
	if *asJSON {
		if jerr := printForkJSON(v); jerr != nil {
			return jerr
		}
		return err
	}
	if err != nil {
		return err
	}
	fmt.Printf("\n%s\n", forkDone(v))
	return nil
}

func printForkJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// pickForkTarget finds the server named to.
func pickForkTarget(info protocol.ForkInfo, to string) (*protocol.ForkTarget, error) {
	var names []string
	for i := range info.Targets {
		t := &info.Targets[i]
		if to != "" && (t.Hostname == to || t.HostID == to) {
			if !t.Usable {
				return nil, fmt.Errorf("%s can't take the fork: %s", t.Hostname, t.Reason)
			}
			return t, nil
		}
		s := t.Hostname
		if t.SameServer {
			s += " (this database's server)"
		}
		if !t.Usable {
			s += " (" + t.Reason + ")"
		}
		names = append(names, s)
	}
	if len(names) == 0 {
		return nil, errors.New("no server can take the fork: install the Rowsafe agent on one (rowsafe hosts enroll-token)")
	}
	if to == "" {
		return nil, fmt.Errorf("where to? Pass --to with one of: %s", strings.Join(names, ", "))
	}
	return nil, fmt.Errorf("no server %q; pass --to with one of: %s", to, strings.Join(names, ", "))
}

// pickForkPlace picks where on the server the fork goes.
func pickForkPlace(t protocol.ForkTarget, port, intoPort int) (protocol.ForkPlace, error) {
	var empties []protocol.ForkPlace
	for _, p := range t.Places {
		switch {
		case intoPort != 0 && p.Placement == protocol.ForkEmptyCluster && p.Port == intoPort:
			return p, nil
		case intoPort == 0 && p.Placement == protocol.ForkNewCluster:
			if port != 0 {
				p.Port = port
				p.Label = fmt.Sprintf("a new PostgreSQL cluster on port %d", port)
			}
			return p, nil
		case intoPort == 0 && p.Placement == protocol.ForkDocker:
			return p, nil
		case p.Placement == protocol.ForkEmptyCluster:
			empties = append(empties, p)
		}
	}
	if intoPort == 0 && len(empties) == 1 && port == 0 {
		return empties[0], nil
	}
	var ports []string
	for _, p := range empties {
		ports = append(ports, fmt.Sprint(p.Port))
	}
	if intoPort != 0 {
		if len(ports) == 0 {
			return protocol.ForkPlace{}, fmt.Errorf("%s has no empty PostgreSQL cluster Rowsafe may stop and start", t.Hostname)
		}
		return protocol.ForkPlace{}, fmt.Errorf("port %d on %s isn't an empty cluster Rowsafe may use; these are: %s", intoPort, t.Hostname, strings.Join(ports, ", "))
	}
	if len(ports) > 0 {
		return protocol.ForkPlace{}, fmt.Errorf("Rowsafe may not create clusters on %s; pick one of its empty clusters with --into-port (%s)", t.Hostname, strings.Join(ports, ", "))
	}
	return protocol.ForkPlace{}, fmt.Errorf("%s has no place for the fork", t.Hostname)
}

// waitFork follows a fork until it is protected or failed, printing each
// step as it starts.
func waitFork(ctx context.Context, c *client.Client, v protocol.ForkView) (protocol.ForkView, error) {
	printed := map[string]string{}
	for {
		for _, s := range v.Steps {
			if s.State == protocol.ForkStepPending || printed[s.Key] == s.State+s.Detail {
				continue
			}
			printed[s.Key] = s.State + s.Detail
			mark := "…"
			switch s.State {
			case protocol.ForkStepDone:
				mark = "✓"
			case protocol.ForkStepFailed:
				mark = "✗"
			}
			line := fmt.Sprintf("  %s %s", mark, s.Label)
			if s.Detail != "" {
				line += ": " + s.Detail
			}
			fmt.Println(line)
		}
		switch v.Status {
		case protocol.ForkReady:
			return v, nil
		case protocol.ForkFailed:
			return v, fmt.Errorf("the fork failed: %s", orText(v.Error, "see rowsafe forks "+v.SourceName))
		}
		select {
		case <-ctx.Done():
			return v, ctx.Err()
		case <-time.After(forkPoll):
		}
		next, err := c.Fork(ctx, v.ID)
		if err != nil {
			return v, apiErr(err)
		}
		v = next
	}
}

// forkDone is a finished fork in plain words.
func forkDone(v protocol.ForkView) string {
	s := fmt.Sprintf("%s is ready on %s", v.Name, v.Hostname)
	if v.Port != 0 {
		s += fmt.Sprintf(":%d", v.Port)
	}
	if v.RecoveredTo != nil {
		s += ", restored to " + describeTime(*v.RecoveredTo)
	}
	s += fmt.Sprintf(", with its own backups. Open it with: rowsafe status %s", v.Name)
	if v.Masking != nil {
		s += fmt.Sprintf("\nMasked %d columns in %d tables (%s rows).", v.Masking.Columns, v.Masking.Tables, groupDigits(v.Masking.Rows))
	}
	for _, w := range v.Warnings {
		s += "\nNote: " + w
	}
	return s
}

func forksCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("forks", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	info, err := c.Forks(ctx, name)
	if err != nil {
		return apiErr(err)
	}
	if *asJSON {
		return printForkJSON(info)
	}
	if f := info.ForkedFrom; f != nil {
		fmt.Printf("%s is a fork of %s (%s).\n\n", name, f.SourceName, forkPoint(*f))
	}
	if len(info.Forks) == 0 {
		fmt.Printf("%s has no forks. Make one: rowsafe fork %s --to SERVER [--at TIME | --mark MARK] [--mask]\n", name, name)
		return nil
	}
	fmt.Printf("Forks of %s:\n", name)
	for _, f := range info.Forks {
		fmt.Printf("  %-24s %-11s on %s, %s", f.Name, f.Status, f.Hostname, forkPoint(f))
		if f.Masked {
			fmt.Print(", masked")
		}
		fmt.Println()
		if f.Status == protocol.ForkFailed && f.Error != "" {
			fmt.Printf("      %s\n", f.Error)
		}
	}
	return nil
}

// forkPoint is the moment a fork was taken from.
func forkPoint(f protocol.ForkView) string {
	switch {
	case f.RecoveredTo != nil:
		return "as of " + describeTime(*f.RecoveredTo)
	case f.At != nil:
		return "as of " + describeTime(*f.At)
	case f.Mark != "" && !f.Now:
		return "from the Mark " + f.Mark
	}
	return "as of " + describeTime(f.CreatedAt)
}

// groupDigits prints 1204 as "1,204".
func groupDigits(n int64) string {
	s := fmt.Sprint(n)
	if n < 0 {
		return s
	}
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	return b.String()
}
