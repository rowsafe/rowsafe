package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// Confirmations and task waiting shared by the commands that change
// production, so scripts and AI agents get the same rules everywhere:
// --yes confirms; on a terminal the command asks; without a terminal and
// without --yes it refuses before changing anything.

// confirmChange asks a yes/no question before a change.
func confirmChange(yes bool, question string) error {
	if yes {
		return nil
	}
	if !stdinIsTerminal() {
		return errors.New("not changed: pass --yes to confirm (no terminal to ask on)")
	}
	fmt.Fprintf(os.Stderr, "%s [y/N] ", question)
	if a := readLine(); !strings.EqualFold(a, "y") && !strings.EqualFold(a, "yes") {
		return errors.New("cancelled; nothing was changed")
	}
	return nil
}

// confirmTyped asks the person to type name (a database's or a server's)
// before a disruptive change.
func confirmTyped(yes bool, name string) error {
	if yes {
		return nil
	}
	if !stdinIsTerminal() {
		return errors.New("not changed: pass --yes to confirm (no terminal to ask on)")
	}
	fmt.Fprintf(os.Stderr, "Type %s to go ahead: ", name)
	if readLine() != name {
		return errors.New("cancelled; nothing was changed")
	}
	return nil
}

// readSecret reads a secret: from the environment variable envVar, from
// stdin when it isn't a terminal, or typed without echo after prompt. It
// never comes from the command line, where other users and shell history
// would see it.
func readSecret(envVar, prompt string) (string, error) {
	if envVar != "" {
		v := strings.TrimSpace(os.Getenv(envVar))
		if v == "" {
			return "", fmt.Errorf("$%s is empty", envVar)
		}
		return v, nil
	}
	if !stdinIsTerminal() {
		line, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		return strings.TrimSpace(line), nil
	}
	fmt.Print(prompt)
	off := exec.Command("stty", "-echo")
	off.Stdin = os.Stdin
	echoOff := off.Run() == nil
	line := readLine()
	if echoOff {
		on := exec.Command("stty", "echo")
		on.Stdin = os.Stdin
		_ = on.Run()
	}
	fmt.Println()
	return strings.TrimSpace(line), nil
}

// onOff parses on|off (and true/false, yes/no).
func onOff(flagName, v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "on", "true", "yes":
		return true, nil
	case "off", "false", "no":
		return false, nil
	}
	return false, fmt.Errorf("--%s takes on or off, not %q", flagName, v)
}

// finishTasks waits for the tasks a change queued (a Mark first, then the
// change), in order. Text: what each step did. JSON: every task as it
// ended. noWait returns the queued tasks at once. A failed task exits 1.
func finishTasks(ctx context.Context, c *client.Client, tasks []protocol.TaskView, noWait, asJSON bool) error {
	if noWait {
		if asJSON {
			return printJSON(tasks)
		}
		for _, t := range tasks {
			fmt.Printf("Task %s: %s (queued; follow it with rowsafe task %s)\n", t.ID, taskName(t.Type), t.ID)
		}
		return nil
	}
	done, err := waitTasks(ctx, c, tasks, asJSON)
	if err != nil {
		return err
	}
	if asJSON {
		if err := printJSON(done); err != nil {
			return err
		}
	} else {
		reportTasks(done)
	}
	if len(done) > 0 && done[len(done)-1].Status != protocol.StatusSucceeded {
		return exitError(1)
	}
	return nil
}

// waitTasks waits for each task in order, saying on stderr what happens
// (unless quiet), and returns them as they ended. It stops at the first
// one that didn't succeed.
func waitTasks(ctx context.Context, c *client.Client, tasks []protocol.TaskView, quiet bool) ([]protocol.TaskView, error) {
	var done []protocol.TaskView
	for _, t := range tasks {
		status := ""
		v, err := c.WaitTask(ctx, t.ID, func(v protocol.TaskView) {
			if quiet || v.Status == status {
				return
			}
			status = v.Status
			switch v.Status {
			case protocol.StatusQueued:
				fmt.Fprintf(os.Stderr, "Waiting for the agent to start the %s (task %s)...\n", taskName(v.Type), v.ID)
			case protocol.StatusRunning:
				fmt.Fprintf(os.Stderr, "Running the %s...\n", taskName(v.Type))
			}
		})
		if err != nil {
			return done, err
		}
		done = append(done, v)
		if v.Status != protocol.StatusSucceeded {
			break
		}
	}
	return done, nil
}

// reportTasks says what each finished task did, in plain words.
func reportTasks(done []protocol.TaskView) {
	for _, t := range done {
		if t.Status != protocol.StatusSucceeded {
			msg := orText(t.Error, "the task ended as "+t.Status)
			if t.Status == protocol.StatusLost {
				msg = "the agent stopped reporting while it ran (it may have restarted); see `rowsafe task " + t.ID + "`"
			}
			fmt.Printf("The %s didn't work: %s\n", taskName(t.Type), msg)
			continue
		}
		var r struct {
			Name    string   `json:"name"`
			Summary string   `json:"summary"`
			Details []string `json:"details"`
		}
		_ = json.Unmarshal(t.Result, &r)
		if t.Type == protocol.TaskRestorePoint {
			fmt.Printf("Mark saved first: %s\n", orText(r.Name, "done"))
			continue
		}
		fmt.Println(orText(r.Summary, "Done: "+taskName(t.Type)+"."))
		printDetails(r.Details)
	}
}
