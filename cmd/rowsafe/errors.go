package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/rowsafe/rowsafe/client"
)

// Exit codes, the same for every command (rowsafe help exit-codes):
//
//	0  it worked
//	1  it didn't (the error says why and what to do next)
//	2  the command was used the wrong way (an unknown flag, a missing argument)
//	3  not healthy or not protected (status, pulse, preview --fail-on)
//
// preview --fail-on (2: the migration fails on the copy) and guard --check
// keep their own, published codes.
const exitCodes = `Exit codes, the same for every command:
  0  it worked
  1  it didn't: the error says why and what to do next
  2  the command was used the wrong way (an unknown flag, a missing or extra argument)
  3  not healthy or not protected: rowsafe status, rowsafe pulse (a score below 70),
     rowsafe preview --fail-on (the verdict reached it)
Two commands answer with their own codes, kept for the scripts and the GitHub Action that use them:
  rowsafe preview --fail-on exits 2 when the migration fails on the copy;
  rowsafe guard --check exits 0 when the command looks destructive, 1 when it doesn't.`

// agentsHelp is rowsafe help agents: the rules scripts and AI agents rely on.
const agentsHelp = `Running rowsafe from a script or an AI agent (Claude Code, Codex, CI):

--json   every command takes it. stdout is then exactly one JSON value (rowsafe logs --follow: one per
         line) and everything else, progress and messages, goes to stderr. Lists are [] when empty.
         Commands that wait for tasks print the tasks as they ended (protocol.TaskView). A command without
         a JSON form of its own prints {"output": "its text", "tasks": [the tasks it waited for]}.
--yes    confirms a change. Without a terminal, a change without --yes is refused at once with a message
         naming --yes: rowsafe never waits for an answer. Secrets (passwords, connection strings) come
         from an environment variable flag (--password-env, --source-env, --secret-env) or stdin.
NAME     pass it, or set ROWSAFE_DATABASE, or run rowsafe init NAME in the project.
Login    ROWSAFE_API_KEY (and ROWSAFE_URL) instead of rowsafe login; no account: rowsafe pulse postgres://...

` + exitCodes + `

Errors go to stderr as "error: what went wrong. What to do next".`

// usageError is a command used the wrong way: an unknown flag, a missing
// or extra argument. It exits 2, so scripts can tell it from a failure.
type usageError struct{ err error }

func (e usageError) Error() string { return e.err.Error() }
func (e usageError) Unwrap() error { return e.err }

func newUsageError(msg string) error { return usageError{errors.New(msg)} }

func usageErrorf(format string, a ...any) error { return usageError{fmt.Errorf(format, a...)} }

// flagError marks a flag parsing error as a usage error; -h stays
// flag.ErrHelp.
func flagError(err error) error {
	if err == nil || errors.Is(err, flag.ErrHelp) {
		return err
	}
	return usageError{err}
}

// explain is what the person (or the AI agent) reads when a command fails:
// what went wrong in plain words and the next step, never a bare HTTP code
// or Go error.
func explain(err error) string {
	var ae *client.APIError
	if errors.As(err, &ae) {
		return explainAPI(ae, err.Error())
	}
	var ue *url.Error
	switch {
	case errors.Is(err, context.Canceled):
		return "stopped before it finished. A change already sent goes on: see `rowsafe tasks`"
	case errors.As(err, &ue):
		host := ue.URL
		if u, perr := url.Parse(ue.URL); perr == nil && u.Host != "" {
			host = u.Scheme + "://" + u.Host
		}
		var ne net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
			return fmt.Sprintf("Rowsafe at %s didn't answer in time. Try again in a minute; check the internet connection if it keeps happening", host)
		}
		return fmt.Sprintf("can't reach Rowsafe at %s (%s). Check the internet connection, or the address: ROWSAFE_URL, or `rowsafe login --url URL`",
			host, plainCause(ue.Err))
	}
	var se *json.SyntaxError
	var te *json.UnmarshalTypeError
	if errors.As(err, &se) || errors.As(err, &te) {
		return "the control plane answered in a way this CLI doesn't understand (" + err.Error() + "). " +
			"Update the CLI: curl -fsSL https://rowsafe.sh/cli | sh"
	}
	return err.Error()
}

// explainAPI adds the next step to the control plane's answer. msg is the
// whole error, which may wrap the API error with what the CLI was doing.
func explainAPI(ae *client.APIError, msg string) string {
	bare := ae.Msg == "" || strings.HasPrefix(ae.Msg, "HTTP ")
	if bare {
		// Not a Rowsafe answer (a proxy's page, an empty body): don't show it.
		msg = strings.Replace(msg, ae.Msg, http.StatusText(ae.Status), 1)
		if msg == "" {
			msg = http.StatusText(ae.Status)
		}
	}
	lower := strings.ToLower(ae.Msg)
	switch {
	case ae.Status == http.StatusUnauthorized:
		return "Rowsafe didn't accept the API key (" + msg + "). Log in again: `rowsafe login` (or set ROWSAFE_API_KEY to a valid key)"
	case ae.Status == http.StatusForbidden && (bare || lower == "forbidden"):
		return "not allowed with this login (" + msg + "): changes need an owner or admin and a read-write key. `rowsafe whoami` shows who the key acts as"
	case bare && (ae.Status == http.StatusNotFound || ae.Status == http.StatusMethodNotAllowed):
		// Not one of Rowsafe's answers: the server doesn't know the request.
		return "the control plane at ROWSAFE_URL doesn't know this request (" + msg + "): it may be older than this CLI, " +
			"or not a Rowsafe control plane. Check `rowsafe whoami`, or update the CLI: curl -fsSL https://rowsafe.sh/cli | sh"
	case ae.Status == http.StatusNotFound && lower == "not found":
		return "not found: check the name (`rowsafe ls` lists the databases, `rowsafe cloud list` the servers, `rowsafe tasks` the tasks)"
	case ae.Status == http.StatusTooManyRequests:
		wait := "a minute"
		if ae.RetryAfter > 0 {
			wait = ae.RetryAfter.String()
		}
		return msg + ". Try again in " + wait
	case ae.Status >= 500:
		if bare {
			return fmt.Sprintf("Rowsafe had a problem answering (%d %s). Try again in a minute", ae.Status, http.StatusText(ae.Status))
		}
		return msg + ". Try again in a minute"
	}
	return msg
}

// plainCause is a network error's cause without Go's wrapping ("dial tcp
// 1.2.3.4:443: connect: connection refused" -> "connection refused").
func plainCause(err error) string {
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "no such address: " + dns.Name
	}
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 {
		s = s[i+2:]
	}
	return s
}
