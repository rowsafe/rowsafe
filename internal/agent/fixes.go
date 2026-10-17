package agent

import (
	"context"

	"github.com/rowsafe/rowsafe/internal/maintenance"
	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

// Maintenance tasks run package maintenance (the CLI runs it too, without
// an agent). The agent's other tasks share its catalog lookups and words.

func init() { maintenance.Version = Version }

func (a *Agent) fixTarget(db protocol.DatabaseSpec) pginspect.Target {
	t := a.target(db)
	t.AppName = maintenance.AppName
	return t
}

// maintenance runs one maintenance action.
func (a *Agent) maintenance(ctx context.Context, db protocol.DatabaseSpec, p protocol.MaintenanceParams, tl *taskLog) (*protocol.MaintenanceResult, error) {
	return maintenance.Run(ctx, a.fixTarget(db), p, tl)
}

type relation = maintenance.Relation

const ddlLockTimeout = maintenance.DDLLockTimeout

var (
	errNotFound = maintenance.ErrNotFound

	alterSystem      = maintenance.AlterSystem
	alterSystemStmt  = maintenance.AlterSystemStmt
	closeConn        = maintenance.CloseConn
	freeBytes        = maintenance.FreeBytes
	isLockTimeout    = maintenance.IsLockTimeout
	libraryInstalled = maintenance.LibraryInstalled
	lookupRelation   = maintenance.LookupRelation
	nameCandidates   = maintenance.NameCandidates
	requirePrimary   = maintenance.RequirePrimary
	serverVersionNum = maintenance.ServerVersionNum
	validDatName     = maintenance.ValidDatName

	countNoun     = maintenance.CountNoun
	humanBytes    = maintenance.HumanBytes
	isAre         = maintenance.IsAre
	itThem        = maintenance.ItThem
	plainCount    = maintenance.PlainCount
	plainDuration = maintenance.PlainDuration
	plainPGError  = maintenance.PlainPGError
	plural        = maintenance.Plural
	sentence      = maintenance.Sentence
)
