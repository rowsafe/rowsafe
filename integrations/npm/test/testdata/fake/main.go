// A stand-in for the rowsafe CLI in the npm wrapper's tests: prints its
// arguments as JSON and exits with the code in ROWSAFE_FAKE_EXIT.
package main

import (
	"encoding/json"
	"os"
	"strconv"
)

func main() {
	json.NewEncoder(os.Stdout).Encode(os.Args[1:]) //nolint:errcheck
	code, _ := strconv.Atoi(os.Getenv("ROWSAFE_FAKE_EXIT"))
	os.Exit(code)
}
