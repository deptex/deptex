package repo

import (
	"database/sql"
	"fmt"
)

// LookupUser interpolates the id straight into SQL — classic SQLi.
func LookupUser(db *sql.DB, id string) {
	q := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", id)
	db.Query(q)
}
