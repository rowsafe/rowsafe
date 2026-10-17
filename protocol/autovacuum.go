package protocol

// AutovacuumBacklog is the tables autovacuum should be cleaning but isn't
// yet, over every database examined: their dead rows are past their
// threshold (autovacuum_vacuum_threshold + autovacuum_vacuum_scale_factor x
// rows, with each table's own settings) and no worker is on them. With
// every worker busy for long stretches (the autovacuum_all_busy_minutes
// metric), they wait for one.
type AutovacuumBacklog struct {
	Waiting  int   `json:"waiting"`
	DeadRows int64 `json:"dead_rows"`
	// Tables are up to 5 of them, most dead rows first (Database, Schema,
	// Table, LiveRows, DeadRows, LastAutovacuum set).
	Tables []TableVacuum `json:"tables,omitempty"`
}
