package agent

import (
	"fmt"
	"strconv"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

// DesiredArchiveTimeout bounds data loss on quiet databases: Postgres
// switches to a new WAL segment at least this often, so a segment (and the
// transactions in it) reaches the repository within about this many seconds:
// backups are at most about a minute behind. (Segments are compressed in the
// repository, so a mostly empty forced segment costs little.)
const DesiredArchiveTimeout = 60

// restartWarning is the plan's warning when PostgreSQL needs a restart.
// Rowsafe never restarts it on its own; once someone does, the control plane
// notices (the agent reports archive_mode) and verifies by itself.
func restartWarning(sidecar bool, name string) string {
	if name == "" {
		name = "NAME"
	}
	how := "restart it when it suits you (Restart PostgreSQL in the dashboard, `rowsafe restart " + name + "`, or on the server)"
	if sidecar {
		how = "restart its container when it suits you (e.g. `docker compose restart postgres`)"
	}
	return RestartWarningPrefix + " Rowsafe never restarts it on its own: " + how +
		". Rowsafe notices the restart by itself and finishes; `rowsafe verify " + name + "` checks right away."
}

// RestartWarningPrefix starts the plan's restart warning.
const RestartWarningPrefix = "PostgreSQL needs a quick restart for backups to start."

// Plan is the outcome of comparing a cluster with what Rowsafe needs.
type Plan struct {
	Changes  []protocol.Change
	Settings map[string]string // ALTER SYSTEM SET name = value
	Restart  bool
	Warnings []string
}

// PlanInput is what the planner needs besides the inspected cluster.
type PlanInput struct {
	Mode           string // ModeNative (default) or ModeDockerSidecar
	ConfigPath     string // pgBackRest config the agent writes
	ArchiveCommand string // the archive_command Rowsafe wants
	SpoolDir       string // sidecar mode: this stanza's spool directory
	Force          bool   // replace a foreign archiver
	Name           string // the database's name in Rowsafe, for hints
	// Own recognizes Rowsafe's own native archive_command for this
	// database in another form (with or without the second copy), which
	// is replaced without force.
	Own func(cmd string) bool
}

// PlanAdopt plans native-mode adoption; see PlanAdoptInput.
func PlanAdopt(in protocol.InspectResult, configPath, archiveCommand string, force bool) (Plan, error) {
	return PlanAdoptInput(in, PlanInput{Mode: ModeNative, ConfigPath: configPath, ArchiveCommand: archiveCommand, Force: force})
}

// PlanAdoptInput decides what must change for pgBackRest WAL archiving. It
// is a pure function so the rules are easy to test and review.
//
// An archive_command belonging to the other mode is refused even with
// force: in docker-sidecar mode a command that runs pgBackRest inside the
// PostgreSQL container cannot work with a stock image, and in native mode a
// spool command means a sidecar agent (not this one) pushes the WAL. Either
// way the agent's mode is probably wrong, and switching modes is a
// deliberate step (reset archive_command first).
func PlanAdoptInput(in protocol.InspectResult, pi PlanInput) (Plan, error) {
	configPath, archiveCommand, force := pi.ConfigPath, pi.ArchiveCommand, pi.Force
	sidecar := pi.Mode == ModeDockerSidecar
	p := Plan{Settings: map[string]string{}}
	if !in.IsSuperuser {
		return p, fmt.Errorf("the agent's database role is not a superuser; it must connect as the postgres role (peer authentication over the Unix socket)")
	}
	if in.InRecovery {
		return p, fmt.Errorf("this server is a standby; adopt the primary instead")
	}
	if in.VersionNum < 130000 {
		return p, fmt.Errorf("PostgreSQL %s is not supported; Rowsafe needs PostgreSQL 13 or newer", in.ServerVersion)
	}
	if in.DataDirectory == "" {
		return p, fmt.Errorf("could not determine data_directory")
	}

	p.Changes = append(p.Changes,
		protocol.Change{Kind: "file", Description: "write pgBackRest config (0600, contains repository credentials) to " + configPath})
	if sidecar {
		p.Changes = append(p.Changes, protocol.Change{Kind: "file", Description: "create the WAL spool directory " + pi.SpoolDir +
			" (0700), where archive_command hands WAL to the agent container"})
	}
	p.Changes = append(p.Changes,
		protocol.Change{Kind: "command", Description: "pgbackrest stanza-create: initialise the repository for this cluster"})

	set := func(name, from, to string, restart bool) {
		p.Settings[name] = to
		p.Changes = append(p.Changes, protocol.Change{
			Kind: "setting", Description: "ALTER SYSTEM SET " + name, Setting: name, From: from, To: to, Restart: restart,
		})
		if restart {
			p.Restart = true
		}
	}

	if in.WalLevel == "minimal" {
		set("wal_level", in.WalLevel, "replica", true)
	}
	if in.ArchiveMode != "on" && in.ArchiveMode != "always" {
		set("archive_mode", in.ArchiveMode, "on", true)
	}

	if in.ArchiveLibrary != "" {
		if !force {
			return p, fmt.Errorf("archive_library is set to %q: another archiver is active; re-run with force to replace it", in.ArchiveLibrary)
		}
		set("archive_library", in.ArchiveLibrary, "", false)
		p.Warnings = append(p.Warnings, "replacing existing archive_library "+strconv.Quote(in.ArchiveLibrary))
	}
	current := in.ArchiveCommand
	if current == "(disabled)" {
		current = ""
	}
	if current != archiveCommand {
		spoolDir, isSpool := pgbackrest.ParseSpoolArchiveCommand(current)
		ours := false // Rowsafe's own command for this cluster, from an older agent
		switch {
		case sidecar && pgbackrest.IsPushArchiveCommand(current):
			return p, fmt.Errorf("archive_command runs pgBackRest inside the PostgreSQL container (%q), but this agent runs in "+
				"docker-sidecar mode, where stock postgres images have no pgBackRest and archive_command hands WAL to the agent through "+
				"a spool. If that command is left over from a native Rowsafe install you are moving into Docker, reset it first "+
				"(ALTER SYSTEM RESET archive_command; SELECT pg_reload_conf();) and plan again. If pgBackRest really runs inside "+
				"your PostgreSQL image, run the agent with ROWSAFE_MODE=native there instead", current)
		case !sidecar && isSpool:
			return p, fmt.Errorf("archive_command hands WAL to a Rowsafe docker-sidecar spool (%s), but this agent runs in native "+
				"mode: nothing would push that WAL to the repository. If PostgreSQL runs in Docker, run the agent as its sidecar "+
				"(ROWSAFE_MODE=docker-sidecar, see https://rowsafe.sh/docs/guides/docker). If you moved PostgreSQL out of Docker, reset archive_command "+
				"first (ALTER SYSTEM RESET archive_command; SELECT pg_reload_conf();) and plan again", spoolDir)
		case sidecar && isSpool && spoolDir == pi.SpoolDir:
			ours = true
			p.Warnings = append(p.Warnings, "updating Rowsafe's spool archive_command to this agent version's")
		case sidecar && isSpool:
			if !force {
				return p, fmt.Errorf("archive_command already hands WAL to a Rowsafe spool at %s, not %s: another Rowsafe database "+
					"(or an agent with a different ROWSAFE_SPOOL_DIR) receives this cluster's WAL; re-run with force to replace it", spoolDir, pi.SpoolDir)
			}
		case !sidecar && pi.Own != nil && pi.Own(current):
			ours = true
		case current != "" && !force:
			return p, fmt.Errorf("archive_command is already set to %q: another archiver may be running; re-run with force to replace it", current)
		}
		if current != "" && !ours {
			p.Warnings = append(p.Warnings, "replacing existing archive_command "+strconv.Quote(current))
		}
		set("archive_command", in.ArchiveCommand, archiveCommand, false)
	}

	if in.ArchiveTimeoutSeconds == 0 || in.ArchiveTimeoutSeconds > DesiredArchiveTimeout {
		set("archive_timeout", strconv.Itoa(in.ArchiveTimeoutSeconds), strconv.Itoa(DesiredArchiveTimeout), false)
	}

	// Settings already changed but waiting for a restart still need one.
	for _, name := range in.PendingRestart {
		if name == "archive_mode" || name == "wal_level" {
			p.Restart = true
		}
	}
	if p.Restart {
		p.Warnings = append(p.Warnings, restartWarning(sidecar, pi.Name))
	}
	return p, nil
}
