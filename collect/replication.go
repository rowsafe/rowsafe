package collect

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/protocol"
)

// maxReplicas bounds the standbys reported.
const maxReplicas = 50

// readReplication reads streaming replication status: the standbys of a
// primary (pg_stat_replication) or, on a standby, how far behind it is and
// its connection to the primary. The connection string (conninfo) is never
// read: it can carry a password. Errors leave the report without it.
func readReplication(ctx context.Context, conn *pgx.Conn, r *clusterReading, inRecovery bool) {
	rs := &protocol.ReplicationStatus{Role: "primary", Replicas: []protocol.Replica{}}
	if inRecovery {
		rs.Role = "replica"
	}
	replyTime := "NULL::timestamptz"
	if r.versionNum >= 120000 {
		replyTime = "reply_time"
	}
	lsnDiff := func(col string) string {
		if inRecovery {
			return "NULL::bigint"
		}
		return "pg_wal_lsn_diff(pg_current_wal_lsn(), " + col + ")::bigint"
	}
	rows, err := conn.Query(ctx, `
		SELECT coalesce(application_name, ''), coalesce(host(client_addr), ''), coalesce(state, ''), coalesce(sync_state, ''),
		       `+lsnDiff("sent_lsn")+`, `+lsnDiff("flush_lsn")+`, `+lsnDiff("replay_lsn")+`,
		       extract(epoch FROM write_lag)::float8, extract(epoch FROM flush_lag)::float8, extract(epoch FROM replay_lag)::float8,
		       `+replyTime+`
		FROM pg_stat_replication ORDER BY application_name, pid LIMIT $1`, maxReplicas)
	if err != nil {
		return
	}
	rs.Replicas, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (protocol.Replica, error) {
		var x protocol.Replica
		err := row.Scan(&x.ApplicationName, &x.ClientAddr, &x.State, &x.SyncState, &x.SentLagBytes, &x.FlushLagBytes,
			&x.ReplayLagBytes, &x.WriteLagSeconds, &x.FlushLagSeconds, &x.ReplayLagSeconds, &x.ReplyAt)
		return x, err
	})
	if err != nil {
		return
	}
	if rs.Replicas == nil {
		rs.Replicas = []protocol.Replica{}
	}
	g := r.gauges
	var streaming, lagSecs, lagBytes float64
	haveLag := false
	for _, x := range rs.Replicas {
		if x.State == "streaming" {
			streaming++
		}
		if x.ReplayLagSeconds != nil {
			haveLag = true
			lagSecs = max(lagSecs, *x.ReplayLagSeconds)
		}
		if x.ReplayLagBytes != nil {
			haveLag = true
			lagBytes = max(lagBytes, float64(*x.ReplayLagBytes))
		}
	}
	g[MReplicasConnected] = streaming
	if haveLag {
		// replay_lag is NULL while a standby is idle and caught up: no lag.
		g[MReplicationLagSeconds] = lagSecs
		g[MReplicationLagBytes] = lagBytes
	}

	if inRecovery {
		var secs *float64
		var bytes *int64
		// Behind only while something received is not replayed yet: on an
		// idle primary the last replayed transaction gets old without any
		// lag. Without streaming (archive recovery) the delay is unknown.
		if err := conn.QueryRow(ctx, `
			SELECT CASE WHEN pg_last_wal_receive_lsn() IS NULL THEN NULL
			            WHEN pg_last_wal_receive_lsn() <= pg_last_wal_replay_lsn() THEN 0
			            ELSE greatest(extract(epoch FROM clock_timestamp() - pg_last_xact_replay_timestamp()), 0) END::float8,
			       greatest(pg_wal_lsn_diff(pg_last_wal_receive_lsn(), pg_last_wal_replay_lsn()), 0)::bigint`).Scan(&secs, &bytes); err == nil {
			rs.ReplayLagSeconds, rs.ReplayLagBytes = secs, bytes
			if secs != nil {
				g[MReplicationLagSeconds] = *secs
			}
			if bytes != nil {
				g[MReplicationLagBytes] = float64(*bytes)
			}
		}
		recv := &protocol.WALReceiver{}
		var lastMsg *time.Time
		sql := `SELECT coalesce(status, ''), '', 0, coalesce(slot_name, ''), last_msg_receipt_time FROM pg_stat_wal_receiver`
		if r.versionNum >= 110000 {
			sql = `SELECT coalesce(status, ''), coalesce(sender_host, ''), coalesce(sender_port, 0), coalesce(slot_name, ''),
			              last_msg_receipt_time FROM pg_stat_wal_receiver`
		}
		err := conn.QueryRow(ctx, sql).Scan(&recv.Status, &recv.SenderHost, &recv.SenderPort, &recv.SlotName, &lastMsg)
		if err == nil || err == pgx.ErrNoRows {
			recv.LastMessageAt = lastMsg
			rs.Receiver = recv
		}
	}
	r.replication = rs
}
