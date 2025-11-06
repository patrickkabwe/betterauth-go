package sql

import (
	"strconv"
	"strings"
)

// Dialect identifies the target SQL database so the adapter can adjust
// placeholder syntax and schema DDL. The adapter is driver-agnostic: callers
// supply their own *sql.DB (e.g. lib/pq, pgx, modernc.org/sqlite, go-sql-driver/mysql)
// and the matching Dialect.
type Dialect int

const (
	// Postgres uses $1, $2 numbered placeholders.
	Postgres Dialect = iota
	// SQLite uses ? placeholders.
	SQLite
	// MySQL uses ? placeholders.
	MySQL
)

// String returns the dialect name.
func (d Dialect) String() string {
	switch d {
	case Postgres:
		return "postgres"
	case SQLite:
		return "sqlite"
	case MySQL:
		return "mysql"
	default:
		return "unknown"
	}
}

// rebind converts a query written with ? placeholders into the dialect's
// native placeholder style. Postgres becomes $1, $2, ...; SQLite and MySQL
// keep ?.
func (d Dialect) rebind(query string) string {
	if d != Postgres {
		return query
	}
	var b strings.Builder
	b.Grow(len(query) + 8)
	n := 0
	for i := 0; i < len(query); i++ {
		if query[i] == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteByte(query[i])
	}
	return b.String()
}

// All timestamps are persisted as INTEGER unix-millisecond values and all
// booleans as INTEGER 0/1 so the schema is portable across Postgres, SQLite,
// and MySQL without driver-specific time parsing or boolean handling.
func (d Dialect) textType() string {
	return "TEXT"
}

func (d Dialect) intType() string {
	return "INTEGER"
}
