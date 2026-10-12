package sqlite

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// The providers a SQLite database moves in from, over HTTPS. The token is
// sent in the Authorization header only (never in a URL, a log line or an
// error), and only to the provider's own host: D1's export file is fetched
// from its signed URL without it.
//
//   - Turso / libSQL (https://docs.turso.tech/sdk/http/reference):
//     GET <database URL>/dump with "Authorization: Bearer <database token>"
//     answers the whole database as SQL text (PRAGMA foreign_keys=OFF;
//     BEGIN TRANSACTION; CREATE TABLE ...; INSERT ...; COMMIT;). The check
//     reads the size and table count with one statement through
//     POST <database URL>/v2/pipeline ({"requests":[{"type":"execute",
//     "stmt":{"sql":...}},{"type":"close"}]}). libsql:// URLs are HTTPS.
//   - Cloudflare D1
//     (https://developers.cloudflare.com/api/resources/d1/subresources/database/methods/get/,
//     https://developers.cloudflare.com/api/resources/d1/subresources/database/methods/export/,
//     https://developers.cloudflare.com/d1/best-practices/import-export-data/):
//     GET /client/v4/accounts/{account_id}/d1/database/{database_id} gives
//     the name and file_size; POST .../export with {"output_format":
//     "polling"} starts the export and is posted again with
//     "current_bookmark": <at_bookmark> until result.status is "complete"
//     (result.result.signed_url, valid one hour) or "error" (result.error).
//     An export that isn't polled continually is cancelled, and D1 answers
//     no other queries while it runs. Virtual tables can't be exported.

// d1APIBase is Cloudflare's API (tests point it elsewhere).
var d1APIBase = "https://api.cloudflare.com/client/v4"

// d1PollEvery is the pause between two polls of a D1 export.
var d1PollEvery = time.Second

// moveInHTTP is the client for the providers: no overall timeout (an
// export can take long; the task's context bounds it), but bounded
// connection and header waits.
var moveInHTTP = &http.Client{Transport: &http.Transport{
	Proxy:                 http.ProxyFromEnvironment,
	DialContext:           (&net.Dialer{Timeout: 20 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	TLSHandshakeTimeout:   20 * time.Second,
	ResponseHeaderTimeout: 2 * time.Minute,
	ForceAttemptHTTP2:     true,
}}

// plainHTTPError drops the URL Go puts in transport errors (a signed URL
// carries a signature).
func plainHTTPError(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "the provider didn't answer in time"
	}
	return firstLine(err.Error())
}

// scrub removes the token from a message, as a last safety.
func scrub(msg, token string) string {
	if token != "" {
		msg = strings.ReplaceAll(msg, token, "[token]")
	}
	return msg
}

// bodySnippet is the start of an error response, for the message.
func bodySnippet(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 512))
	s := strings.TrimSpace(string(b))
	var j struct {
		Error   any    `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(b, &j) == nil {
		if m, ok := j.Error.(string); ok && m != "" {
			s = m
		} else if m, ok := j.Error.(map[string]any); ok {
			if msg, ok := m["message"].(string); ok {
				s = msg
			}
		} else if j.Message != "" {
			s = j.Message
		}
	}
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return firstLine(s)
}

// sourceStats is what the check reads from the source.
type sourceStats struct {
	Name      string
	SizeBytes int64
	Tables    int // -1 when unknown
}

// moveInSource is a provider the export comes from.
type moveInSource interface {
	// stats reads the source's size and tables (check).
	stats(ctx context.Context) (sourceStats, error)
	// export opens the SQL export; size is its length when known (-1).
	// note reports the provider's progress in plain words.
	export(ctx context.Context, note func(string)) (body io.ReadCloser, size int64, err error)
}

func newMoveInSource(s protocol.SQLiteSource) moveInSource {
	if s.Provider == protocol.SQLiteSourceD1 {
		return &d1Source{src: s}
	}
	return &libsqlSource{src: s}
}

// ---- Turso / libSQL

type libsqlSource struct{ src protocol.SQLiteSource }

func (l *libsqlSource) name() string {
	if l.src.Provider == protocol.SQLiteSourceTurso {
		return "Turso"
	}
	return "The libSQL server"
}

func (l *libsqlSource) statusError(code int, body io.Reader) error {
	switch code {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("%s refused the database token: create a new token for this database (Turso dashboard > your database > Create Token) and paste it again", l.name())
	case http.StatusNotFound:
		return fmt.Errorf("%s doesn't know the database at %s: copy its URL again (libsql://<database>-<organization>.turso.io)", l.name(), l.src.Host())
	}
	return errors.New(scrub(fmt.Sprintf("%s answered HTTP %d: %s", l.name(), code, bodySnippet(body)), l.src.Token))
}

func (l *libsqlSource) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, l.src.URL+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+l.src.Token)
	req.Header.Set("User-Agent", "rowsafe-agent")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := moveInHTTP.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("can't reach %s: %s", l.src.Host(), scrub(plainHTTPError(err), l.src.Token))
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, l.statusError(resp.StatusCode, resp.Body)
	}
	return resp, nil
}

// libsqlStatsSQL counts the app's tables (not SQLite's nor libSQL's own)
// and reads the file's size.
const libsqlStatsSQL = `SELECT (SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite\_%' ESCAPE '\' ` +
	`AND name NOT LIKE 'libsql\_%' ESCAPE '\' AND name NOT LIKE '\_cf\_%' ESCAPE '\'), ` +
	`(SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size())`

func (l *libsqlSource) stats(ctx context.Context) (sourceStats, error) {
	st := sourceStats{Name: l.src.Database(), Tables: -1}
	body, _ := json.Marshal(map[string]any{"requests": []any{
		map[string]any{"type": "execute", "stmt": map[string]any{"sql": libsqlStatsSQL}},
		map[string]any{"type": "close"},
	}})
	resp, err := l.do(ctx, http.MethodPost, "/v2/pipeline", body)
	if err != nil {
		return st, err
	}
	defer resp.Body.Close()
	var out struct {
		Results []struct {
			Type     string `json:"type"`
			Response struct {
				Result struct {
					Rows [][]struct {
						Type  string `json:"type"`
						Value any    `json:"value"`
					} `json:"rows"`
				} `json:"result"`
			} `json:"response"`
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		} `json:"results"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return st, fmt.Errorf("%s's answer couldn't be read: %w", l.name(), err)
	}
	if len(out.Results) == 0 {
		return st, fmt.Errorf("%s gave no answer to the size query", l.name())
	}
	r := out.Results[0]
	if r.Type != "ok" {
		// Reached and signed in: the size stays unknown.
		return st, nil
	}
	if len(r.Response.Result.Rows) == 1 && len(r.Response.Result.Rows[0]) == 2 {
		row := r.Response.Result.Rows[0]
		if n, err := strconv.ParseInt(fmt.Sprint(row[0].Value), 10, 64); err == nil {
			st.Tables = int(n)
		}
		if n, err := strconv.ParseInt(fmt.Sprint(row[1].Value), 10, 64); err == nil {
			st.SizeBytes = n
		}
	}
	return st, nil
}

func (l *libsqlSource) export(ctx context.Context, note func(string)) (io.ReadCloser, int64, error) {
	note("asking " + l.src.Host() + " for the database's SQL dump")
	resp, err := l.do(ctx, http.MethodGet, "/dump", nil)
	if err != nil {
		return nil, 0, err
	}
	return resp.Body, resp.ContentLength, nil
}

// ---- Cloudflare D1

type d1Source struct{ src protocol.SQLiteSource }

type d1Message struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type d1Envelope struct {
	Success bool            `json:"success"`
	Errors  []d1Message     `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

func (d *d1Source) path() string {
	return "/accounts/" + d.src.AccountID + "/d1/database/" + d.src.DatabaseID
}

// d1Error turns an answer into plain words.
func (d *d1Source) d1Error(code int, env d1Envelope) error {
	var msgs []string
	auth, missing := code == http.StatusUnauthorized || code == http.StatusForbidden, code == http.StatusNotFound
	for _, e := range env.Errors {
		msgs = append(msgs, e.Message)
		switch e.Code {
		case 10000, 9106, 9109: // authentication errors
			auth = true
		case 7003, 7404, 7500: // no such object
			missing = true
		}
	}
	switch {
	case auth:
		return errors.New("Cloudflare refused the API token: create one with the D1 Edit permission for this account (Cloudflare dashboard > My Profile > API Tokens) and paste it again")
	case missing:
		return fmt.Errorf("Cloudflare found no D1 database %s in the account %s: check both IDs (Workers & Pages > D1 > your database)", d.src.DatabaseID, d.src.AccountID)
	}
	msg := strings.Join(msgs, "; ")
	if msg == "" {
		msg = fmt.Sprintf("HTTP %d", code)
	}
	return errors.New(scrub("Cloudflare answered: "+firstLine(msg), d.src.Token))
}

func (d *d1Source) call(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, d1APIBase+d.path()+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+d.src.Token)
	req.Header.Set("User-Agent", "rowsafe-agent")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := moveInHTTP.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("can't reach Cloudflare's API: %s", scrub(plainHTTPError(err), d.src.Token))
	}
	defer resp.Body.Close()
	var env d1Envelope
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&env); err != nil {
		if resp.StatusCode != http.StatusOK {
			return d.d1Error(resp.StatusCode, env)
		}
		return fmt.Errorf("Cloudflare's answer couldn't be read: %v", err)
	}
	if resp.StatusCode != http.StatusOK || !env.Success {
		return d.d1Error(resp.StatusCode, env)
	}
	if out != nil {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return fmt.Errorf("Cloudflare's answer couldn't be read: %v", err)
		}
	}
	return nil
}

func (d *d1Source) stats(ctx context.Context) (sourceStats, error) {
	var r struct {
		Name     string `json:"name"`
		FileSize int64  `json:"file_size"`
	}
	if err := d.call(ctx, http.MethodGet, "", nil, &r); err != nil {
		return sourceStats{}, err
	}
	// num_tables is deprecated and inaccurate (Cloudflare's reference):
	// the tables are counted from the export.
	return sourceStats{Name: r.Name, SizeBytes: r.FileSize, Tables: -1}, nil
}

// d1Export is one answer of the export endpoint.
type d1Export struct {
	AtBookmark string   `json:"at_bookmark"`
	Status     string   `json:"status"`
	Error      string   `json:"error"`
	Messages   []string `json:"messages"`
	Result     struct {
		Filename  string `json:"filename"`
		SignedURL string `json:"signed_url"`
	} `json:"result"`
}

func (d *d1Source) export(ctx context.Context, note func(string)) (io.ReadCloser, int64, error) {
	note("asking Cloudflare to export the D1 database (D1 answers no other queries while it runs)")
	req := map[string]any{"output_format": "polling"}
	deadline := time.Now().Add(6 * time.Hour)
	for {
		var ex d1Export
		if err := d.call(ctx, http.MethodPost, "/export", req, &ex); err != nil {
			return nil, 0, err
		}
		for _, m := range ex.Messages {
			note("Cloudflare: " + firstLine(scrub(m, d.src.Token)))
		}
		switch ex.Status {
		case "complete":
			if ex.Result.SignedURL == "" {
				return nil, 0, errors.New("Cloudflare finished the export but gave no file to download")
			}
			return d.download(ctx, ex.Result.SignedURL)
		case "error":
			return nil, 0, errors.New(scrub("Cloudflare couldn't export the database: "+firstLine(orText(ex.Error, "no reason given")), d.src.Token))
		}
		if ex.AtBookmark == "" {
			return nil, 0, errors.New("Cloudflare's export stopped answering where it was (no bookmark): try again")
		}
		if time.Now().After(deadline) {
			return nil, 0, errors.New("Cloudflare's export didn't finish in 6 hours")
		}
		req["current_bookmark"] = ex.AtBookmark
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case <-time.After(d1PollEvery):
		}
	}
}

// download fetches the export file from its signed URL (no token: the
// URL is the permission).
func (d *d1Source) download(ctx context.Context, signed string) (io.ReadCloser, int64, error) {
	u, err := url.Parse(signed)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, 0, errors.New("Cloudflare gave an export link Rowsafe can't use")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, signed, nil)
	if err != nil {
		return nil, 0, errors.New("Cloudflare gave an export link Rowsafe can't use")
	}
	req.Header.Set("User-Agent", "rowsafe-agent")
	resp, err := moveInHTTP.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, 0, ctx.Err()
		}
		return nil, 0, fmt.Errorf("downloading the export from Cloudflare: %s", plainHTTPError(err))
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, 0, fmt.Errorf("downloading the export from Cloudflare failed (HTTP %d): the link lasts an hour, so try again", resp.StatusCode)
	}
	return resp.Body, resp.ContentLength, nil
}
