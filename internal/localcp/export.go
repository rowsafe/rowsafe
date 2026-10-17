package localcp

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/rowsafe/rowsafe/protocol"
)

// Export is what `rowsafe login` hands over to an account from a state
// file: the databases and their history. It holds no secret: the agent's
// token for this control plane, task parameters, logs and results stay
// behind.
type Export struct {
	HostID    string
	Hostname  string
	Databases []protocol.Database
	// Open are tasks queued or running (a backup, a Proof...): connecting
	// restarts the agent, which would cut them short.
	Open    []protocol.TaskView
	History protocol.ImportRequest
}

// ReadExport reads the state file at path (StateFile in the agent's state
// directory).
func ReadExport(path string) (Export, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Export{}, err
	}
	var s state
	if err := json.Unmarshal(data, &s); err != nil {
		return Export{}, fmt.Errorf("reading %s: %w", path, err)
	}
	return s.export(), nil
}

func (s *state) export() Export {
	out := Export{HostID: s.Host.ID, Hostname: s.Host.Hostname, History: protocol.ImportRequest{Databases: []protocol.ImportDatabase{}}}
	for _, t := range s.Tasks {
		if t.open() {
			v := t.TaskView
			v.Log, v.Params, v.Result = "", nil, nil
			out.Open = append(out.Open, v)
		}
	}
	for _, d := range s.Databases {
		out.Databases = append(out.Databases, s.view(d))
		h := protocol.ImportDatabase{Name: d.Name, Backups: []protocol.Backup{}, Drills: []protocol.Drill{}, RestorePoints: []protocol.RestorePoint{}}
		for _, b := range s.Backups {
			if b.DatabaseID == d.ID {
				h.Backups = append(h.Backups, b)
			}
		}
		for _, x := range s.Drills {
			if x.DatabaseID == d.ID {
				h.Drills = append(h.Drills, x)
			}
		}
		for _, m := range s.Marks {
			// Only Marks PostgreSQL wrote: a failed or unfinished attempt
			// has nothing to restore to.
			if m.DatabaseID != d.ID || m.LSN == "" || m.CreatedAt == nil {
				continue
			}
			m.Status, m.RestoreFromBackup = "", ""
			h.RestorePoints = append(h.RestorePoints, m)
		}
		out.History.Databases = append(out.History.Databases, h)
	}
	return out
}
