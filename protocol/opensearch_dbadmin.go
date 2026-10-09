package protocol

import (
	"fmt"
	"regexp"
	"strings"
)

// ---- Databases & users for OpenSearch
//
// Users are the security plugin's internal users. A "database" is an index
// (or a data stream): the inventory lists them with their documents,
// create_database makes an empty index (CreateOwner: and a user who owns
// it), drop_database deletes one (the control plane saves a Mark first,
// which is a snapshot). A new user gets a role of its own,
// rowsafe_user_<name>, with one of three presets (DBAccess*) on the
// indices and index patterns in DBAdminParams.Databases ("logs-*"):
//
//   - read_only: search and read documents and mappings;
//   - read_write: also index, update and delete documents, create those
//     indices and change their mappings;
//   - owner: every index action on them (delete, settings...).
//
// Passwords are hashed by OpenSearch (bcrypt). The users OpenSearch keeps
// for itself (OpenSearchSystemUsers), reserved or hidden ones, users from
// other authentication backends and Rowsafe's own are listed but never
// changed. Without the security plugin there are no users: the inventory
// says so (ManageBlocked).

// openSearchPatternRE: an index name or pattern Rowsafe writes into a role:
// lowercase letters, digits and - _ . +, with * for any characters; not
// starting with "_", "-", "+" or "." (system indices).
// A pattern starts with a letter or digit, so it never reaches OpenSearch's
// own (dot) indices.
var openSearchPatternRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_.*+-]{0,62}$`)

// ValidOpenSearchPattern checks an index name or pattern of a user's access.
func ValidOpenSearchPattern(p string) error {
	if strings.HasPrefix(p, "*") {
		return fmt.Errorf("%q would reach every index, OpenSearch's own included: name the indices, or a prefix with * after it (logs-*)", p)
	}
	if !openSearchPatternRE.MatchString(p) {
		return fmt.Errorf("%q can't be used as an index or pattern: use lowercase letters, digits and - _ . with * for any characters (logs-*)", p)
	}
	return nil
}

// validateOpenSearchDBAdmin checks what is OpenSearch's own.
func validateOpenSearchDBAdmin(p DBAdminParams) error {
	switch p.Action {
	case DBAdminCreateUser:
		for _, d := range p.Databases {
			if err := ValidOpenSearchPattern(d); err != nil {
				return err
			}
		}
	case DBAdminCreateDatabase:
		if p.CreateOwner && p.Owner != "" && p.Owner != p.Database && strings.HasPrefix(p.Owner, "rowsafe") {
			return fmt.Errorf("names starting with rowsafe are Rowsafe's")
		}
	case DBAdminDropDatabase:
		if strings.HasPrefix(p.Database, ".") {
			return fmt.Errorf("%s is one of OpenSearch's own indices; Rowsafe doesn't remove it", p.Database)
		}
	case DBAdminDropUser:
		if p.ReassignTo != "" {
			return fmt.Errorf("OpenSearch users own nothing, so there is nothing to hand over")
		}
	}
	return nil
}

// openSearchURL is the address apps use with a user (OpenSearch clients
// take a URL and the login): https://user:password@host:9200 (http:// when
// the server has TLS off).
func openSearchURL(c DBConnection, host, password string) string {
	scheme := "http"
	if c.SSLMode == "require" {
		scheme = "https"
	}
	u := scheme + "://" + urlEscape(c.User)
	if password != "" {
		u += ":" + urlEscape(password)
	}
	u += "@" + host
	if c.Port != 0 {
		u += fmt.Sprintf(":%d", c.Port)
	}
	return u
}
