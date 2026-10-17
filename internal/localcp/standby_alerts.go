package localcp

import (
	"fmt"
	"math"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Alert rules of a standby pair without an account (standby.go). Each
// server alerts on its half, on its own channels: the standby's server is
// the only one that sees the primary from outside.

func init() { localRules = append(localRules, standbyRules...) }

var standbyRules = []localRule{
	{name: "standby_down", title: "Standby down", severity: protocol.SeverityWarning,
		description: "The database's standby isn't following the primary: PostgreSQL there isn't running as a standby, creating it failed, or it stopped streaming.",
		forDur:      5 * time.Minute,
		eval: func(st *state, d *dbRec, _ protocol.Protection, now time.Time) ruleResult {
			v := st.standbyView(d, now)
			if v == nil || (v.Status != protocol.StandbyDown && v.Status != protocol.StandbyFailed) {
				return okResult
			}
			where := "on " + st.hostname()
			if d.Status == protocol.DBActive {
				where = "at " + v.Server.Hostname
			}
			desc := fmt.Sprintf("The standby of %s %s isn't following the primary, so it can't take over if the primary dies.", d.Name, where)
			if v.Error != "" {
				desc += " " + clip(v.Error, 400)
			} else if v.Note != "" {
				desc += " " + v.Note
			}
			return fire(fmt.Sprintf("The standby of %s %s isn't following the primary", d.Name, where), desc,
				fmt.Sprintf("See what it says on the standby's server: sudo rowsafe standby %s. If it can't catch up, remove it and create it again there.", d.Name))
		}},
	{name: "standby_behind", title: "Standby behind", severity: protocol.SeverityWarning,
		description: "The standby replays the primary's changes later than the threshold.",
		threshold:   f64(600), unit: "seconds", forDur: 5 * time.Minute,
		eval: func(st *state, d *dbRec, _ protocol.Protection, now time.Time) ruleResult {
			v := st.standbyView(d, now)
			if v == nil || v.LagSeconds == nil || v.Status == protocol.StandbyDown || v.Status == protocol.StandbyFailed {
				return okResult
			}
			lag := *v.LagSeconds
			if lag <= 600 || v.LagBytes != nil && *v.LagBytes == 0 {
				return okResult
			}
			dur := human(time.Duration(lag * float64(time.Second)))
			r := fire(fmt.Sprintf("The standby of %s is %s behind", d.Name, dur),
				fmt.Sprintf("The standby of %s is %s behind the primary. Reports on it see old data, and promoting it now would lose those changes.", d.Name, dur),
				"Check the standby server's disk, CPU and network, and long queries on it.")
			r.value, r.threshold, r.unit = f64(math.Round(lag)), f64(600), "seconds"
			return r
		}},
	{name: "standby_primary_unreachable", title: "Primary unreachable from the standby", severity: protocol.SeverityCritical,
		description: "The standby's server can't reach the primary's PostgreSQL any more: the primary may be down, or the network between them.",
		forDur:      3 * time.Minute,
		eval: func(st *state, d *dbRec, _ protocol.Protection, now time.Time) ruleResult {
			p := st.Standby[d.ID]
			if d.Status != dbStandby || p == nil || p.State == nil || p.StateAt == nil || now.Sub(*p.StateAt) > 3*time.Minute ||
				p.State.PrimaryUnreachableSince == nil {
				return okResult
			}
			name := st.standbyInfo(d, now).Primary.Hostname
			since := *p.State.PrimaryUnreachableSince
			return fire(fmt.Sprintf("%s can't reach the primary of %s (%s)", st.hostname(), d.Name, name),
				fmt.Sprintf("The standby of %s on %s can't reach the primary's PostgreSQL at %s since %s (%s). The primary may be down, or only the network between the servers.",
					d.Name, st.hostname(), orText(p.PrimaryAddress, name), since.UTC().Format("15:04 UTC"), human(now.Sub(since))),
				fmt.Sprintf("Check the primary. If it is down and won't come back soon, promote the standby here: sudo rowsafe standby promote %s --primary-down", d.Name))
		}},
	{name: "standby_promoted", title: "Standby promoted", severity: protocol.SeverityCritical,
		description: "The database moved to its standby's server (a promotion), or another server took over and Rowsafe stopped this one, and there is no standby since.",
		eval: func(st *state, d *dbRec, _ protocol.Protection, now time.Time) ruleResult {
			p := st.Standby[d.ID]
			if f := st.fenceOf(d.ID); d.Status == dbFenced && f != nil && f.Reason == fenceSuperseded {
				return fire(fmt.Sprintf("%s: %s took over as the primary; PostgreSQL here is stopped", d.Name, orText(f.By, "another server")),
					fmt.Sprintf("The pair's record in the bucket says %s was promoted to primary of %s, so Rowsafe stopped PostgreSQL on %s and keeps it stopped (read-only if started). Writes this server took since are kept here, not on the new primary.",
						orText(f.By, "another server"), d.Name, st.hostname()),
					fmt.Sprintf("Once you know why it was cut off, turn this server into the new standby: sudo rowsafe standby create %s --primary NEW-PRIMARY-ADDRESS", d.Name))
			}
			if d.Status != protocol.DBActive || p == nil || p.PromotedAt == nil || now.Sub(*p.PromotedAt) > 7*24*time.Hour || p.Link != nil {
				return okResult
			}
			return fire(fmt.Sprintf("%s: %s is the primary now", d.Name, st.hostname()),
				fmt.Sprintf("The standby of %s on %s was promoted at %s: it is the primary and backs up to the bucket. Apps must point at it. There is no standby until you make one.",
					d.Name, st.hostname(), p.PromotedAt.UTC().Format("2006-01-02 15:04 UTC")),
				fmt.Sprintf("Turn the old primary into the new standby (on it: sudo rowsafe standby create %s --primary THIS-SERVER'S-ADDRESS), then let it stream from here: sudo rowsafe standby link %s --address ITS-ADDRESS", d.Name, d.Name))
		}},
	{name: "fence_breached", title: "Fenced old primary running", severity: protocol.SeverityCritical,
		description: "PostgreSQL runs on a fenced old primary: something started it again. Rowsafe's agent stops it, and it only comes back read-only, but check who started it.",
		forDur:      time.Minute,
		eval: func(st *state, d *dbRec, _ protocol.Protection, now time.Time) ruleResult {
			f := st.fenceOf(d.ID)
			if f == nil || f.State == nil || !f.State.Running || now.Sub(f.State.At) > 5*time.Minute {
				return okResult
			}
			return fire(fmt.Sprintf("PostgreSQL is running on %s, the fenced old primary of %s", st.hostname(), d.Name),
				fmt.Sprintf("%s is no longer the primary of %s, but its PostgreSQL is running and Rowsafe couldn't stop it yet. It started read-only (standby.signal), so apps asking for a read-write server skip it; make sure nothing writes to it.",
					st.hostname(), d.Name),
				"Find out what started it (a boot script, a person). Then turn it into the standby: sudo rowsafe standby create "+d.Name+" --primary NEW-PRIMARY-ADDRESS")
		}},
}

// standbyView is the database's standby as this server sees it (nil
// without one).
func (st *state) standbyView(d *dbRec, now time.Time) *protocol.StandbyView {
	if d.Status != dbStandby && (d.Status != protocol.DBActive || st.Standby[d.ID] == nil || st.Standby[d.ID].Link == nil) {
		return nil
	}
	return st.standbyInfo(d, now).Standby
}
