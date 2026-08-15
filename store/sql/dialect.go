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

// quoteIdent quotes a database identifier for the active dialect. Better Auth
// JS defaults include the table name "user" and camelCase columns, so runtime
// SQL must not rely on unquoted identifier folding.
func (d Dialect) quoteIdent(name string) string {
	quote := `"`
	if d == MySQL {
		quote = "`"
	}
	escaped := strings.ReplaceAll(name, quote, quote+quote)
	return quote + escaped + quote
}

func (d Dialect) quoteIdents(names ...string) string {
	quoted := make([]string, 0, len(names))
	for _, name := range names {
		quoted = append(quoted, d.quoteIdent(name))
	}
	return strings.Join(quoted, ", ")
}

// All timestamps are persisted as unix-millisecond integers and all booleans as
// 0/1 so the schema is portable across Postgres, SQLite, and MySQL without
// driver-specific time parsing or boolean handling.
func (d Dialect) textType() string {
	return "TEXT"
}

// intType holds small values: booleans as 0/1, and counters. 32 bits is ample.
func (d Dialect) intType() string {
	return "INTEGER"
}

// timestampType holds unix milliseconds, which passed 2^31 in 1970 + 24 days
// and today sits around 1.8e12. Postgres INTEGER and MySQL INT are both 32-bit,
// so a timestamp column declared INTEGER there overflows on the very first
// write -- the driver rejects the value outright. SQLite's INTEGER is already
// 64-bit and is left alone so existing databases keep their declared types.
func (d Dialect) timestampType() string {
	if d == SQLite {
		return "INTEGER"
	}

	return "BIGINT"
}
