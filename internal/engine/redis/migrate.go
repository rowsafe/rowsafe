package redis

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Move in (protocol.FeatureMoveIn): a Redis or Valkey database anywhere
// this server can reach (ElastiCache, MemoryDB, Upstash, Redis Cloud,
// Azure Cache for Redis, DigitalOcean or Aiven for Valkey, any Redis)
// copied into the server Rowsafe protects here, which must be empty.
//
//   - One-time copy (MigrateMethodDump): every key read from the source
//     (SCAN, then DUMP and PTTL) and written here (RESTORE, with its time
//     to live), a batch at a time: memory stays bounded and a copy that
//     stops continues where it was. Managed providers don't let anyone
//     make their database read-only, so the person stops their apps'
//     writes for the copy; the check says how long it takes.
//   - Live sync (MigrateMethodLive): where the source lets replicas in
//     (SYNC/PSYNC; managed providers don't, a self-hosted Redis does) and
//     over a plain connection, this server becomes the source's replica
//     until the switchover, which waits until it has every change, ends
//     replication and compares key counts.
//
// The source connection string reaches this server sealed to the
// migration's key and stays here (0600, next to the key). Everything
// written goes through this server's own stream, so restores to any second
// include the moved data.

var _ agent.EngineMigrate = (*Engine)(nil)

// migSource is a parsed source connection string.
type migSource struct {
	User, Password, Host string
	Port                 int
	DB                   int  // the logical database in the URL (-1: every one)
	TLS                  bool // rediss://
	SkipVerify           bool // ?skip_verify=true
}

func (s migSource) addr() string { return net.JoinHostPort(s.Host, strconv.Itoa(s.Port)) }

// parseMigSource reads redis://[user]:password@host:port[/db] (rediss://
// for TLS).
func parseMigSource(s string) (migSource, error) {
	s = strings.TrimSpace(s)
	example := "use redis://user:password@host:6379 (rediss:// for TLS; the user is \"default\" when there is only a password)"
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "redis" && u.Scheme != "rediss" && u.Scheme != "valkey" && u.Scheme != "valkeys") || u.Host == "" {
		return migSource{}, errors.New("that isn't a Redis connection string: " + example)
	}
	src := migSource{Host: u.Hostname(), Port: 6379, DB: -1, TLS: u.Scheme == "rediss" || u.Scheme == "valkeys"}
	if u.User != nil {
		src.User = u.User.Username()
		src.Password, _ = u.User.Password()
	}
	if p := u.Port(); p != "" {
		if src.Port, err = strconv.Atoi(p); err != nil || src.Port < 1 || src.Port > 65535 {
			return migSource{}, errors.New("invalid port: " + example)
		}
	}
	if path := strings.Trim(u.Path, "/"); path != "" {
		n, err := strconv.Atoi(path)
		if err != nil || n < 0 || n > 10000 {
			return migSource{}, errors.New("the path is a logical database number (/0): " + example)
		}
		src.DB = n
	}
	src.SkipVerify = u.Query().Get("skip_verify") == "true"
	for _, v := range []string{src.User, src.Password, src.Host} {
		if strings.ContainsAny(v, "\r\n\x00") {
			return migSource{}, errors.New("the connection string has a line break in it")
		}
	}
	return src, nil
}

// open connects and signs in to the source.
func (s migSource) open(ctx context.Context) (*conn, error) {
	var nc net.Conn
	var err error
	d := net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	if s.TLS {
		td := tls.Dialer{NetDialer: &d, Config: &tls.Config{ServerName: s.Host, InsecureSkipVerify: s.SkipVerify, MinVersion: tls.VersionTLS12}}
		nc, err = td.DialContext(ctx, "tcp", s.addr())
	} else {
		nc, err = d.DialContext(ctx, "tcp", s.addr())
	}
	if err != nil {
		if strings.Contains(err.Error(), "certificate") {
			return nil, fmt.Errorf("the source's TLS certificate isn't trusted here (%s): add ?skip_verify=true to the connection string if you trust the network path", firstLine(err.Error()))
		}
		return nil, fmt.Errorf("can't connect to %s: %s (does the provider let this server's address in?)", s.addr(), firstLine(plainConnError(err).Error()))
	}
	c := &conn{nc: nc, br: bufio.NewReaderSize(nc, 64<<10), bw: bufio.NewWriterSize(nc, 64<<10), timeout: defaultIOTTL}
	switch {
	case s.User != "" && s.Password != "":
		_, err = c.do(ctx, "AUTH", s.User, s.Password)
	case s.Password != "":
		_, err = c.do(ctx, "AUTH", s.Password)
	case s.User != "":
		_, err = c.do(ctx, "AUTH", s.User, "")
	}
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("the source refused the login: %s", firstLine(err.Error()))
	}
	return c, nil
}

// migProvider recognizes managed providers by host name.
func migProvider(host string) string {
	h := strings.ToLower(host)
	switch {
	case strings.HasSuffix(h, ".memorydb.amazonaws.com"):
		return "memorydb"
	case strings.HasSuffix(h, ".cache.amazonaws.com"):
		return "elasticache"
	case strings.HasSuffix(h, ".upstash.io"):
		return "upstash"
	case strings.Contains(h, "redislabs.com") || strings.Contains(h, "redis-cloud.com") || strings.HasSuffix(h, ".redis.io"):
		return "rediscloud"
	case strings.HasSuffix(h, ".redis.cache.windows.net") || strings.HasSuffix(h, ".redisenterprise.cache.azure.net") || strings.HasSuffix(h, ".redis.azure.net"):
		return "azure"
	case strings.HasSuffix(h, ".db.ondigitalocean.com"):
		return "digitalocean"
	case strings.HasSuffix(h, ".aivencloud.com"):
		return "aiven"
	}
	return "other"
}

// providerNetwork is how to let this server connect, per provider.
func providerNetwork(p string) string {
	switch p {
	case "elasticache", "memorydb":
		return "ElastiCache and MemoryDB are reachable only inside their VPC: run this from a server in that VPC (or one peered with it), with the cluster's security group letting it in."
	case "upstash":
		return "Upstash accepts connections from anywhere by default; if you set an IP allowlist, add this server's address."
	case "rediscloud":
		return "Add this server's address to the database's source IP allowlist (Configuration > Security) if you use one."
	case "azure":
		return "Add this server's address under Firewall in the cache's settings (or reach it through its private endpoint)."
	case "digitalocean":
		return "Add this server's IP address under the database's Network Access > Trusted sources."
	case "aiven":
		return "Add this server's address to the service's allowed IP addresses."
	}
	return "Let this server's address reach the source's port (firewall, bind)."
}

// migState is what this engine keeps for a migration (redis.json).
type migState struct {
	Method     string  `json:"method,omitempty"`
	Pos        copyPos `json:"pos"`
	Started    bool    `json:"started,omitempty"` // the copy wrote into the target
	Replica    bool    `json:"replica,omitempty"` // live sync: the target replicates from the source
	AppUser    string  `json:"app_user,omitempty"`
	SrcBytes   int64   `json:"source_bytes,omitempty"`
	SourceKeys int64   `json:"source_keys,omitempty"`
}

func loadMigState(dir string) migState {
	var st migState
	_ = loadJSONFile(filepath.Join(dir, "redis.json"), &st)
	return st
}

func saveMigState(dir string, st migState) error {
	return saveJSONFile(filepath.Join(dir, "redis.json"), st)
}

func savedSource(dir string) (migSource, error) {
	data, err := os.ReadFile(filepath.Join(dir, "source"))
	if errors.Is(err, os.ErrNotExist) {
		return migSource{}, errors.New("this server doesn't have the source connection string (anymore): paste it again and check")
	}
	if err != nil {
		return migSource{}, err
	}
	return parseMigSource(string(data))
}

// Migrate runs one move-in step.
func (e *Engine) Migrate(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, m agent.MigrateEnv, taskType string,
	p protocol.MigrateParams, log agent.TaskLogger) (any, error) {
	if taskType == protocol.TaskMigrateCopy {
		return nilIfNil(e.migrateCopy(ctx, env, db, m, p, log))
	}
	switch p.Action {
	case protocol.MigrateKey:
		return nilIfNil(e.migrateKey(ctx, env, db, m, log))
	case protocol.MigrateCheck:
		return nilIfNil(e.migrateCheck(ctx, env, db, m, p, log))
	case protocol.MigrateSwitchover:
		return nilIfNil(e.migrateSwitchover(ctx, env, db, m, p, log))
	case protocol.MigrateCredentials:
		st := loadMigState(m.Dir)
		if st.AppUser == "" {
			return nil, errors.New("this migration hasn't switched over yet")
		}
		c, err := connectDB(ctx, env, db)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		res := &protocol.MigrateSwitchoverResult{}
		if err := e.makeAppLogin(ctx, c, db, m, p, st.AppUser, res); err != nil {
			return nil, err
		}
		res.Summary = "New password for " + st.AppUser + "."
		return res, nil
	case protocol.MigrateSourceWritable:
		return &protocol.MigrateActionResult{Summary: "Rowsafe never made the old database read-only, so there is nothing to undo."}, nil
	case protocol.MigrateFixIdentity:
		return &protocol.MigrateActionResult{Summary: "Nothing to fix for Redis: keys need no primary key."}, nil
	case protocol.MigrateCancel:
		return nilIfNil(e.migrateCancel(ctx, env, db, m, p, log))
	}
	return nil, fmt.Errorf("unknown migrate action %q", p.Action)
}

func (e *Engine) migrateKey(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, m agent.MigrateEnv, log agent.TaskLogger) (*protocol.MigrateKeyResult, error) {
	pub, err := agent.MigratePublicKey(m.Dir)
	if err != nil {
		return nil, err
	}
	if m.Phase == "" || m.Phase == protocol.MigratePhaseNew {
		m.SetPhase(protocol.MigratePhaseReady)
	}
	res := &protocol.MigrateKeyResult{PublicKey: pub}
	if c, err := connectDB(ctx, env, db); err == nil {
		if in, err := inspect(ctx, c); err == nil {
			res.Target = e.migrateTarget(ctx, c, db, in)
		}
		c.Close()
	}
	log.Printf("made the key the source connection string is sealed to; the private key stays on this server")
	return res, nil
}

func (e *Engine) migrateTarget(ctx context.Context, c *conn, db protocol.DatabaseSpec, in serverInfo) protocol.MigrateTarget {
	t := protocol.MigrateTarget{ServerVersion: in.Version, VersionNum: in.VersionNum, Port: db.Port, Addresses: migHostAddresses(),
		Database: "db0", Exists: in.totalKeys() > 0}
	bind, _ := c.configGet(ctx, "bind")
	t.ListensRemotely = !listensLocallyOnly(bind)
	if tp, _ := c.configGet(ctx, "tls-port"); tp != "" && tp != "0" {
		t.SSL = true
	}
	if avail, ok := memAvailable(); ok {
		t.FreeBytes = avail
	}
	return t
}

// migHostAddresses are this server's addresses apps could use (public first).
func migHostAddresses() []string {
	addrs, _ := net.InterfaceAddrs()
	var pub, priv []string
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || !ipn.IP.IsGlobalUnicast() || ipn.IP.IsLinkLocalUnicast() {
			continue
		}
		if ipn.IP.IsPrivate() {
			priv = append(priv, ipn.IP.String())
		} else {
			pub = append(pub, ipn.IP.String())
		}
	}
	out := append(pub, priv...)
	if h, err := os.Hostname(); err == nil {
		out = append(out, h)
	}
	return out
}

// copySpeed is the bytes per second a key copy is assumed to move (for the
// estimate shown before it starts).
const copySpeed = 20 << 20

func (e *Engine) migrateCheck(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, m agent.MigrateEnv, p protocol.MigrateParams, log agent.TaskLogger) (*protocol.MigrateCheckResult, error) {
	var src migSource
	var err error
	if p.Source != nil {
		plain, err := agent.OpenMigrateSource(m.Dir, m.ID, p.Source)
		if err != nil {
			return nil, err
		}
		src, err = parseMigSource(string(plain))
		if err != nil {
			clear(plain)
			return nil, err
		}
		err = saveSecretFile(filepath.Join(m.Dir, "source"), plain)
		clear(plain)
		if err != nil {
			return nil, err
		}
	} else if src, err = savedSource(m.Dir); err != nil {
		return nil, err
	}
	m.SetPhase(protocol.MigratePhaseChecking)
	prov := migProvider(src.Host)
	res := &protocol.MigrateCheckResult{Source: protocol.MigrateSource{Host: src.Host, Port: src.Port, User: src.User, Provider: prov, SSL: src.TLS,
		Database: "every logical database"}}
	if src.DB >= 0 {
		res.Source.Database = "db" + strconv.Itoa(src.DB)
	}
	add := func(item protocol.MigrateCheckItem) { res.Checks = append(res.Checks, item) }
	fail := func(id, title, detail, fix, blocks string) {
		add(protocol.MigrateCheckItem{ID: id, Status: protocol.CheckFail, Title: title, Detail: detail, Fix: fix, Blocks: blocks})
	}
	sc, err := src.open(ctx)
	if err != nil {
		m.SetPhase(protocol.MigratePhaseReady)
		fail("connect", "Rowsafe can't reach the source", err.Error(), providerNetwork(prov), "")
		res.Summary = "Rowsafe can't reach the source from this server yet."
		return res, nil
	}
	defer sc.Close()
	add(protocol.MigrateCheckItem{ID: "connect", Status: protocol.CheckOK, Title: "Rowsafe reaches the source and signs in"})
	sm, err := sc.info(ctx, "server", "memory", "keyspace", "replication", "cluster")
	if err != nil {
		m.SetPhase(protocol.MigratePhaseReady)
		return nil, fmt.Errorf("reading the source's INFO: %w", err)
	}
	sin := infoFrom(sm)
	res.Source.ServerVersion, res.Source.VersionNum, res.Source.SizeBytes = sin.Version, sin.VersionNum, sin.UsedMemoryDataset
	res.Source.Tables = int(sin.totalKeys())
	tc, err := connectDB(ctx, env, db)
	if err != nil {
		m.SetPhase(protocol.MigratePhaseReady)
		return nil, err
	}
	defer tc.Close()
	tin, err := inspect(ctx, tc)
	if err != nil {
		m.SetPhase(protocol.MigratePhaseReady)
		return nil, err
	}
	res.Target = e.migrateTarget(ctx, tc, db, tin)
	ok := true
	if sm["cluster_enabled"] == "1" {
		ok = false
		fail("cluster", "The source is a Redis Cluster", "Rowsafe moves in one standalone database (cluster mode off), not a cluster's shards.",
			"Move a non-clustered database, or one shard's data at a time.", "")
	}
	switch {
	case tin.VersionNum/100 < sin.VersionNum/100:
		ok = false
		fail("version", fmt.Sprintf("%s here (%s) is older than the source (%s)", e.display(), tin.Version, sin.Version),
			"A server reads data from its own version or older only.", "Upgrade "+e.display()+" here first.", "")
	default:
		add(protocol.MigrateCheckItem{ID: "version", Status: protocol.CheckOK, Title: fmt.Sprintf("Versions fit: %s to %s", sin.Version, tin.Version)})
	}
	if missing := missingModules(ctx, sc, tc); len(missing) > 0 {
		ok = false
		fail("modules", "The source uses modules this server lacks: "+strings.Join(missing, ", "),
			"Keys of those types (JSON, search indexes, time series...) can't be written here.", "Install the same modules here (Redis 8 includes JSON, search and time series), then check again.", "")
	}
	if n := tin.totalKeys(); n > 0 {
		ok = false
		fail("empty", fmt.Sprintf("%s here isn't empty (%s keys)", e.display(), commas(n)), "Moving in fills an empty server, so nothing here is overwritten.",
			"Move into an empty server.", "")
	} else {
		add(protocol.MigrateCheckItem{ID: "empty", Status: protocol.CheckOK, Title: e.display() + " here is empty"})
	}
	maxDB := 0
	for n := range sin.Keyspace {
		maxDB = max(maxDB, n+1)
	}
	if maxDB > tin.Databases {
		ok = false
		fail("databases", fmt.Sprintf("The source uses logical database %d; this server has %d", maxDB-1, tin.Databases), "",
			"Raise the databases setting here (a restart), then check again.", "")
	}
	if mm := tin.MaxMemory; mm > 0 && sin.UsedMemoryDataset > mm*9/10 {
		ok = false
		fail("memory", fmt.Sprintf("The source's data (%s) doesn't fit this server's maxmemory (%s)", humanBytes(sin.UsedMemoryDataset), humanBytes(mm)),
			"", "Raise maxmemory here, then check again.", "")
	} else if avail, ok2 := memAvailable(); ok2 && sin.UsedMemoryDataset > avail*8/10 {
		add(protocol.MigrateCheckItem{ID: "memory", Status: protocol.CheckWarn, Title: "This server is short of free memory for the data",
			Detail: fmt.Sprintf("The source holds %s; about %s is free here.", humanBytes(sin.UsedMemoryDataset), humanBytes(avail))})
	} else {
		add(protocol.MigrateCheckItem{ID: "memory", Status: protocol.CheckOK, Title: fmt.Sprintf("The data fits (%s)", humanBytes(sin.UsedMemoryDataset))})
	}
	srcPolicy := sm["maxmemory_policy"]
	if v, err := sc.configGet(ctx, "maxmemory-policy"); err == nil && v != "" {
		srcPolicy = v
	}
	if srcPolicy != "" && tin.MaxMemoryPolicy != "" && srcPolicy != tin.MaxMemoryPolicy {
		add(protocol.MigrateCheckItem{ID: "eviction", Status: protocol.CheckWarn, Title: fmt.Sprintf("The source evicts keys with %s, this server with %s", srcPolicy, tin.MaxMemoryPolicy),
			Detail: "When memory runs out, this server would behave differently (noeviction refuses writes; the others drop keys).",
			Fix:    "Pulse offers to change the eviction policy here once the move is done."})
	}
	// Live sync: replication from the source.
	live, why := e.canReplicateFrom(ctx, sc, tc, src, prov)
	if !live {
		add(protocol.MigrateCheckItem{ID: "replication", Status: protocol.CheckWarn, Title: "Live sync isn't possible from this source", Detail: why,
			Fix: "Use the one-time copy: stop your apps' writes to the source for the copy, then point them here.", Blocks: protocol.MigrateMethodLive})
	} else {
		add(protocol.MigrateCheckItem{ID: "replication", Status: protocol.CheckOK, Title: "The source lets this server follow it: live sync works"})
	}
	res.LiveSync, res.DumpOK = ok && live, ok
	res.Method = protocol.MigrateMethodDump
	if res.LiveSync {
		res.Method = protocol.MigrateMethodLive
	}
	res.EstimatedCopySeconds = max(sin.UsedMemoryDataset/copySpeed, 5)
	res.AppUser = cmpOr(src.User, "app")
	if res.AppUser == "default" {
		res.AppUser = "app"
	}
	st := loadMigState(m.Dir)
	st.SrcBytes, st.SourceKeys = sin.UsedMemoryDataset, sin.totalKeys()
	_ = saveMigState(m.Dir, st)
	switch {
	case !ok:
		res.Summary = "Something has to change before the move (see the list)."
	case live:
		res.Summary = fmt.Sprintf("Ready: live sync follows the source until you switch; %s keys, %s.", commas(sin.totalKeys()), humanBytes(sin.UsedMemoryDataset))
	default:
		res.Summary = fmt.Sprintf("Ready for the one-time copy: %s keys, %s; writes to the source must stop for about %s.",
			commas(sin.totalKeys()), humanBytes(sin.UsedMemoryDataset), (time.Duration(res.EstimatedCopySeconds) * time.Second).String())
	}
	m.SetPhase(protocol.MigratePhaseChecked)
	log.Printf("%s", res.Summary)
	return res, nil
}

// canReplicateFrom says whether this server can follow the source as its
// replica (live sync), and why not.
func (e *Engine) canReplicateFrom(ctx context.Context, sc, tc *conn, src migSource, prov string) (bool, string) {
	switch {
	case prov != "other":
		return false, "Managed providers don't let other servers replicate from their databases, so the copy is one-time."
	case src.TLS:
		return false, "Over TLS, Rowsafe moves the data with the one-time copy (live sync uses a plain connection)."
	}
	if v, err := sc.do(ctx, "COMMAND", "INFO", "PSYNC"); err != nil || len(asArray(v)) == 0 || asArray(v)[0] == nil {
		return false, "The source has no PSYNC command (renamed or disabled), so nothing can replicate from it."
	}
	if v, err := tc.do(ctx, "ACL", "GETUSER", LoginUser); err != nil {
		return false, "Rowsafe's user here may not point this server at another one (REPLICAOF): run the Rowsafe installer on this server with --redis-standby."
	} else if s := fmt.Sprint(v); !strings.Contains(s, "+replicaof") && !strings.Contains(s, "+@all") {
		return false, "Rowsafe's user here may not point this server at another one (REPLICAOF): run the Rowsafe installer on this server with --redis-standby."
	}
	return true, ""
}

// missingModules are the source's modules this server doesn't load.
func missingModules(ctx context.Context, sc, tc *conn) []string {
	names := func(c *conn) []string {
		v, err := c.do(ctx, "MODULE", "LIST")
		if err != nil {
			return nil
		}
		var out []string
		for _, m := range asArray(v) {
			f := asArray(m)
			for i := 0; i+1 < len(f); i += 2 {
				if asString(f[i]) == "name" {
					out = append(out, strings.ToLower(asString(f[i+1])))
				}
			}
		}
		return out
	}
	have := names(tc)
	var missing []string
	for _, n := range names(sc) {
		if !slices.Contains(have, n) && n != "vectorset" {
			missing = append(missing, n)
		}
	}
	return missing
}

var appUserRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,32}$`)

func (e *Engine) migrateCopy(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, m agent.MigrateEnv, p protocol.MigrateParams, log agent.TaskLogger) (*protocol.MigrateCopyResult, error) {
	start := time.Now()
	src, err := savedSource(m.Dir)
	if err != nil {
		return nil, err
	}
	if p.AppUser != "" && (!appUserRE.MatchString(p.AppUser) || rowsafeUser(p.AppUser) || p.AppUser == "default") {
		return nil, fmt.Errorf("the login name %q isn't allowed", p.AppUser)
	}
	st := loadMigState(m.Dir)
	method := cmpOr(p.Method, protocol.MigrateMethodDump)
	st.Method = method
	sc, err := src.open(ctx)
	if err != nil {
		return nil, err
	}
	defer sc.Close()
	tc, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer tc.Close()
	tin, err := inspect(ctx, tc)
	if err != nil {
		return nil, err
	}
	if tin.totalKeys() > 0 && !st.Started {
		return nil, fmt.Errorf("%s here isn't empty (%s keys): nothing was copied", e.display(), commas(tin.totalKeys()))
	}
	res := &protocol.MigrateCopyResult{Method: method}
	if method == protocol.MigrateMethodLive {
		live, why := e.canReplicateFrom(ctx, sc, tc, src, migProvider(src.Host))
		if !live {
			return nil, errors.New(why)
		}
		m.SetPhase(protocol.MigratePhaseCopying)
		st.Started, st.Replica = true, true
		_ = saveMigState(m.Dir, st)
		sec := protocol.StandbySecrets{ReplicationUser: src.User, ReplicationPassword: src.Password, PrimaryPort: src.Port}
		if err := followSource(ctx, tc, src, sec, log); err != nil {
			_, _ = tc.do(context.WithoutCancel(ctx), "REPLICAOF", "NO", "ONE")
			st.Replica = false
			_ = saveMigState(m.Dir, st)
			m.SetPhase(protocol.MigratePhaseFailed)
			return nil, err
		}
		m.SetPhase(protocol.MigratePhaseSyncing)
		res.DurationMs = time.Since(start).Milliseconds()
		res.Summary = fmt.Sprintf("%s here has the source's data and follows every change; switch over when your apps are ready.", e.display())
		log.Printf("%s", res.Summary)
		return res, nil
	}
	// One-time copy.
	m.SetPhase(protocol.MigratePhaseDumping)
	sin, _ := inspect(ctx, sc)
	dbs := make([]int, 0, len(sin.Keyspace))
	for n := range sin.Keyspace {
		if src.DB < 0 || n == src.DB {
			dbs = append(dbs, n)
		}
	}
	slices.Sort(dbs)
	from := copyPos{DB: -1}
	if st.Started {
		from = st.Pos
		log.Printf("continuing the copy where it stopped (logical database %d)", from.DB)
	}
	st.Started = true
	_ = saveMigState(m.Dir, st)
	total := max(sin.totalKeys(), 1)
	cs, err := copyKeys(ctx, sc, tc, copyOpts{DBs: dbs, From: from, Replace: from.DB >= 0, Saved: func(pos copyPos, n int64) {
		st.Pos = pos
		_ = saveMigState(m.Dir, st)
		m.Progress(protocol.MigrationStatus{Phase: protocol.MigratePhaseDumping, TablesTotal: int(total), TablesCopied: int(n),
			BytesTotal: sin.UsedMemoryDataset, At: time.Now().UTC()})
	}})
	if err != nil {
		m.SetPhase(protocol.MigratePhaseFailed)
		return nil, fmt.Errorf("copying the keys: %w (the next attempt continues where it stopped)", err)
	}
	log.Printf("copied %s keys (%s)", commas(cs.Keys), humanBytes(cs.Bytes))
	res.TablesTotal = len(dbs)
	sw, err := e.finishMove(ctx, tc, sc, db, m, p, &st, log)
	if err != nil {
		return nil, err
	}
	res.Switchover = sw
	res.Warnings = append(res.Warnings, sw.Warnings...)
	res.DurationMs = time.Since(start).Milliseconds()
	res.Summary = fmt.Sprintf("Copied %s keys into %s here, with their times to live. %s", commas(cs.Keys), e.display(), sw.Summary)
	log.Printf("%s", res.Summary)
	return res, nil
}

// followSource makes the target the source's replica and waits until it
// has the data.
func followSource(ctx context.Context, tc *conn, src migSource, sec protocol.StandbySecrets, log agent.TaskLogger) error {
	addr := src.Host
	return startReplication(ctx, tc, addr, sec, log)
}

func (e *Engine) migrateSwitchover(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, m agent.MigrateEnv, p protocol.MigrateParams, log agent.TaskLogger) (*protocol.MigrateSwitchoverResult, error) {
	st := loadMigState(m.Dir)
	if !st.Replica {
		return nil, errors.New("this migration has no live sync to switch over")
	}
	src, err := savedSource(m.Dir)
	if err != nil {
		return nil, err
	}
	sc, err := src.open(ctx)
	if err != nil {
		return nil, err
	}
	defer sc.Close()
	tc, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer tc.Close()
	m.SetPhase(protocol.MigratePhaseSwitching)
	warn := ""
	if p.ReadOnly {
		// A self-hosted source: refuse its writes the way Rowsafe fences.
		if err := applyFence(ctx, sc); err != nil {
			warn = "Rowsafe couldn't make the source refuse writes (" + firstLine(err.Error()) + "): stop your apps' writes to it yourself."
		} else {
			endClients(ctx, sc)
		}
	}
	// Wait until this server has every change.
	deadline := time.Now().Add(2 * time.Minute)
	for {
		sm, err1 := sc.info(ctx, "replication")
		tm, err2 := tc.info(ctx, "replication")
		if err1 == nil && err2 == nil && tm["master_link_status"] == "up" && tm.int("slave_repl_offset") >= sm.int("master_repl_offset") {
			break
		}
		if time.Now().After(deadline) {
			m.SetPhase(protocol.MigratePhaseSyncing)
			return nil, errors.New("this server hasn't caught up with the source within 2 minutes: stop the writes to the source and switch again")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	if _, err := tc.do(ctx, "REPLICAOF", "NO", "ONE"); err != nil {
		return nil, fmt.Errorf("ending replication: %w", err)
	}
	_, _ = tc.do(ctx, "CONFIG", "SET", "masterauth", "")
	_, _ = tc.do(ctx, "CONFIG", "SET", "masteruser", "")
	_, _ = tc.do(ctx, "CONFIG", "REWRITE")
	st.Replica = false
	_ = saveMigState(m.Dir, st)
	res, err := e.finishMove(ctx, tc, sc, db, m, p, &st, log)
	if err != nil {
		return nil, err
	}
	res.SourceReadOnly = p.ReadOnly && warn == ""
	if warn != "" {
		res.Warnings = append(res.Warnings, warn)
	}
	return res, nil
}

// finishMove compares key counts, makes the apps' login and records the
// switch.
func (e *Engine) finishMove(ctx context.Context, tc, sc *conn, db protocol.DatabaseSpec, m agent.MigrateEnv, p protocol.MigrateParams, st *migState, log agent.TaskLogger) (*protocol.MigrateSwitchoverResult, error) {
	start := time.Now()
	res := &protocol.MigrateSwitchoverResult{}
	sk, err1 := keyCounts(ctx, sc)
	tk, err2 := keyCounts(ctx, tc)
	if err1 == nil && err2 == nil {
		dbs := map[int]bool{}
		for n := range sk {
			dbs[n] = true
		}
		for n := range tk {
			dbs[n] = true
		}
		names := make([]int, 0, len(dbs))
		for n := range dbs {
			names = append(names, n)
		}
		slices.Sort(names)
		for _, n := range names {
			c := protocol.MigrateTableCount{Table: "db" + strconv.Itoa(n), Source: sk[n].Keys, Target: tk[n].Keys}
			res.Tables = append(res.Tables, c)
			res.RowsTotal += c.Target
			if c.Source != c.Target {
				res.Mismatches++
			}
		}
	}
	if res.Mismatches > 0 {
		res.Warnings = append(res.Warnings, "Key counts differ: keys that expired during the move, or writes to the source while it ran, explain small differences.")
	}
	user := cmpOr(p.AppUser, st.AppUser)
	if user == "" {
		user = "app"
	}
	if err := e.makeAppLogin(ctx, tc, db, m, p, user, res); err != nil {
		res.Warnings = append(res.Warnings, "Rowsafe couldn't make the login for your apps ("+firstLine(err.Error())+"): sign in with this server's own users.")
	} else {
		st.AppUser = user
	}
	_ = saveMigState(m.Dir, *st)
	m.SetPhase(protocol.MigratePhaseSwitched)
	res.DurationMs = time.Since(start).Milliseconds()
	res.Summary = fmt.Sprintf("%s keys are here (%d logical databases differ from the source).", commas(res.RowsTotal), res.Mismatches)
	if res.Mismatches == 0 {
		res.Summary = fmt.Sprintf("All %s keys are here, the same count as the source.", commas(res.RowsTotal))
	}
	log.Printf("%s", res.Summary)
	return res, nil
}

// makeAppLogin creates (or gives a new password to) the login apps use,
// with every right on the data and none to administer the server.
func (e *Engine) makeAppLogin(ctx context.Context, c *conn, db protocol.DatabaseSpec, m agent.MigrateEnv, p protocol.MigrateParams, user string, res *protocol.MigrateSwitchoverResult) error {
	if !appUserRE.MatchString(user) || rowsafeUser(user) || user == "default" {
		return fmt.Errorf("the login name %q isn't allowed", user)
	}
	pw, err := randomPassword()
	if err != nil {
		return err
	}
	if _, err := c.do(ctx, "ACL", "SETUSER", user, "reset", "on", ">"+pw, "~*", "&*", "+@all", "-@admin", "-@dangerous", "+flushdb", "+keys", "+info"); err != nil {
		if isRespError(err, "NOPERM") {
			return errors.New("Rowsafe's user here may not create users (the installer's --redis-standby allows it)")
		}
		return err
	}
	persistACL(ctx, c)
	host := p.Host
	if host == "" {
		if a := migHostAddresses(); len(a) > 0 {
			host = a[0]
		}
	}
	u := url.URL{Scheme: "redis", User: url.UserPassword(user, pw), Host: net.JoinHostPort(host, strconv.Itoa(db.Port)), Path: "/0"}
	hint := url.URL{Scheme: "redis", User: url.User(user), Host: u.Host, Path: u.Path}
	res.AppUser, res.ConnectionHint = user, hint.String()
	if p.BrowserKey != "" {
		box, err := agent.SealMigrateCredentials(m.ID, p.BrowserKey, []byte(u.String()))
		if err != nil {
			return err
		}
		res.Credentials = box
	}
	return nil
}

func (e *Engine) migrateCancel(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, m agent.MigrateEnv, p protocol.MigrateParams, log agent.TaskLogger) (*protocol.MigrateActionResult, error) {
	st := loadMigState(m.Dir)
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	res := &protocol.MigrateActionResult{}
	if st.Replica {
		if _, err := c.do(ctx, "REPLICAOF", "NO", "ONE"); err != nil {
			return nil, fmt.Errorf("ending the sync: %w", err)
		}
		_, _ = c.do(ctx, "CONFIG", "SET", "masterauth", "")
		_, _ = c.do(ctx, "CONFIG", "SET", "masteruser", "")
		st.Replica = false
		res.Details = append(res.Details, "Ended the sync.")
	}
	if p.DropTarget && st.Started {
		ks, _ := keyCounts(ctx, c)
		for n := range ks {
			if _, err := c.do(ctx, "SELECT", n); err == nil {
				_, _ = c.do(ctx, "FLUSHDB")
			}
		}
		_, _ = c.do(ctx, "SELECT", 0)
		res.Details = append(res.Details, "Removed the keys the move copied (the server was empty before).")
		st.Started, st.Pos = false, copyPos{}
	}
	_ = saveMigState(m.Dir, st)
	m.SetPhase(protocol.MigratePhaseCancelled)
	res.Summary = "Stopped the move. The source wasn't changed."
	log.Printf("%s", res.Summary)
	return res, nil
}

// MigrateStatus reports a live sync's progress: how far this server is
// behind the source.
func (e *Engine) MigrateStatus(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, m agent.MigrateEnv) (protocol.MigrationStatus, bool) {
	st := loadMigState(m.Dir)
	if !st.Replica {
		return protocol.MigrationStatus{}, false
	}
	out := protocol.MigrationStatus{Phase: m.Phase, BytesTotal: st.SrcBytes, At: time.Now().UTC()}
	tc, err := connectDB(ctx, env, db)
	if err != nil {
		out.Error = err.Error()
		return out, true
	}
	defer tc.Close()
	tm, err := tc.info(ctx, "replication", "memory")
	if err != nil {
		out.Error = err.Error()
		return out, true
	}
	out.BytesCopied = tm.int("used_memory_dataset")
	if tm["master_link_status"] != "up" {
		out.Error = "this server lost its connection to the source; it reconnects by itself"
		if tm["master_sync_in_progress"] == "1" {
			out.Error = ""
			out.Phase = protocol.MigratePhaseCopying
		}
		return out, true
	}
	if src, err := savedSource(m.Dir); err == nil {
		if sc, err := src.open(ctx); err == nil {
			if sm, err := sc.info(ctx, "replication"); err == nil {
				lag := max(sm.int("master_repl_offset")-tm.int("slave_repl_offset"), 0)
				out.LagBytes = &lag
			}
			sc.Close()
		}
	}
	return out, true
}

// saveSecretFile writes a secret (0600) atomically.
func saveSecretFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
