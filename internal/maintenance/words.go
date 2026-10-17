package maintenance

import (
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// HumanBytes: 812 B, 1.2 KiB, 3.4 GiB.
func HumanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// AlterSystem builds an ALTER SYSTEM statement. Utility statements can't take
// bind parameters, so the value is quoted as a literal and rejected if it
// contains anything that could escape the literal.
func AlterSystem(name, value string) (string, error) {
	if strings.ContainsAny(value, "\\\n\r\x00") {
		return "", fmt.Errorf("refusing unsafe value for %s", name)
	}
	ident := pgx.Identifier{name}.Sanitize()
	if value == "" {
		return "ALTER SYSTEM RESET " + ident, nil
	}
	return fmt.Sprintf("ALTER SYSTEM SET %s = '%s'", ident, strings.ReplaceAll(value, "'", "''")), nil
}
