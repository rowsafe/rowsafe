package mcp

import (
	"context"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/protocol"
)

// Rewind is read-only here. Guard's rule: AI agents never restore over
// production. No tool creates copies, brings rows back or rewinds a
// database; people do that in the dashboard (Rewind) or with
// `rowsafe rewind`, after confirming.

// rewindGuidance is what an assistant tells the user when something went
// wrong.
const rewindGuidance = "If data was lost or damaged, tell the user they can Rewind in the Rowsafe dashboard (Rewind tab): restore a copy as it was at any second in the recovery window (or at a Mark), compare it with production and bring the missing rows back with one click, or rewind the whole database. `rowsafe rewind` does the same from a terminal. You can't do any of it yourself: AI assistants never restore over production."

type RewindWindowView struct {
	Database string `json:"database"`
	// Earliest and Latest bound the recovery window.
	Earliest *time.Time `json:"earliest,omitempty" jsonschema:"the earliest second the database can be restored to"`
	Latest   *time.Time `json:"latest,omitempty" jsonschema:"the latest second the database can be restored to (the last change that reached the backups)"`
	Marks    []string   `json:"marks,omitempty" jsonschema:"the newest restore points (Marks), newest first"`
	// Copy is the database's restored copy, if any.
	Copy *RewindCopyView `json:"copy,omitempty"`
	// Kept lists data kept aside by rewinds of the whole database (Undo).
	Kept             []RewindKeptView `json:"kept,omitempty"`
	CanRewindInPlace bool             `json:"can_rewind_in_place" jsonschema:"whether the whole database can be rewound in place on its server (the user does it)"`
	InPlaceReason    string           `json:"in_place_reason,omitempty"`
	Guidance         string           `json:"guidance"`
}

type RewindCopyView struct {
	ID          string     `json:"id"`
	Status      string     `json:"status" jsonschema:"restoring, ready, failed or removed"`
	TargetTime  *time.Time `json:"target_time,omitempty"`
	TargetMark  string     `json:"target_mark,omitempty"`
	RecoveredTo *time.Time `json:"recovered_to,omitempty" jsonschema:"the commit time of the last change in the copy"`
	SizeBytes   int64      `json:"size_bytes"`
	Expires     time.Time  `json:"expires" jsonschema:"when Rowsafe deletes the copy by itself"`
}

type RewindKeptView struct {
	RewindID  string     `json:"rewind_id"`
	Status    string     `json:"status" jsonschema:"before_rewind (Undo is possible) or after_undo"`
	SizeBytes int64      `json:"size_bytes"`
	Expires   *time.Time `json:"expires,omitempty"`
}

func (t *tools) addRewindReadTools(s *sdk.Server) {
	sdk.AddTool(s, &sdk.Tool{
		Name: "rewind_window",
		Description: "Show how far back a database can be rewound: the recovery window (earliest and latest restorable second), the newest Marks (restore points), " +
			"a restored copy if one exists, and data kept aside by a rewind of the whole database. Read-only. " +
			"Use it to tell the user what they can go back to when something went wrong. Rewinding is theirs to do (Rewind in the dashboard, or `rowsafe rewind`): " +
			"no tool restores a copy, brings rows back or rewinds a database.",
		Annotations: readOnly("Rewind window"),
	}, t.rewindWindow)
}

func (t *tools) rewindWindow(ctx context.Context, _ *sdk.CallToolRequest, in databaseInput) (*sdk.CallToolResult, RewindWindowView, error) {
	d, err := t.c.Database(ctx, in.Database)
	if err != nil {
		return nil, RewindWindowView{}, apiError(err)
	}
	info, err := t.c.RewindInfo(ctx, d.ID)
	if err != nil {
		return nil, RewindWindowView{}, apiError(err)
	}
	out := RewindWindowView{Database: d.Name, Earliest: info.Earliest, Latest: info.Latest,
		CanRewindInPlace: info.CanRewindInPlace, InPlaceReason: info.InPlaceReason, Guidance: rewindGuidance}
	for i, m := range info.Marks {
		if i == 10 {
			break
		}
		out.Marks = append(out.Marks, m.Name)
	}
	if c := info.Copy; c != nil {
		out.Copy = &RewindCopyView{ID: c.ID, Status: c.Status, TargetTime: c.Target.Time, TargetMark: c.Target.Mark,
			RecoveredTo: c.RecoveredTo, SizeBytes: c.SizeBytes, Expires: c.Expires}
	}
	for _, k := range info.Kept {
		out.Kept = append(out.Kept, RewindKeptView{RewindID: k.RewindID, Status: k.Status, SizeBytes: k.SizeBytes, Expires: k.Expires})
	}

	var b textBuilder
	if info.Earliest != nil && info.Latest != nil {
		b.line("%s can be rewound to any second from %s to %s.", d.Name, info.Earliest.UTC().Format(time.RFC3339), info.Latest.UTC().Format(time.RFC3339))
	} else {
		b.line("%s has no recovery window yet (it starts with the first backup).", d.Name)
	}
	if len(out.Marks) > 0 {
		b.line("Newest Marks: %s.", joinNames(out.Marks))
	}
	if c := out.Copy; c != nil {
		b.line("A copy exists (%s, %s), deleted by itself at %s.", c.Status, humanBytes(c.SizeBytes), c.Expires.UTC().Format(time.RFC3339))
	}
	for _, k := range out.Kept {
		if k.Status == protocol.RewindKeptBefore {
			b.line("The database was rewound in place (%s); the data from before is kept, so the user can undo it.", k.RewindID)
		}
	}
	b.line("Next: %s", rewindGuidance)
	return text(b), out, nil
}

func joinNames(s []string) string {
	out := ""
	for i, n := range s {
		if i > 0 {
			out += ", "
		}
		out += n
	}
	return out
}
