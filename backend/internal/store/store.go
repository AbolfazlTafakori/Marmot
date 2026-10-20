// Package store keeps the panel's own state in an embedded SQLite file:
// administrators, login sessions, the audit log and traffic history. The
// node configuration is not here; marmot.toml is its source of truth
// (docs/adr/0006-config-file-source-of-truth.md).
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // pure Go driver, no CGO
)

// FileName is the database file inside the data directory.
const FileName = "marmot.db"

// Errors returned by Store.
var (
	ErrNotFound  = errors.New("store: not found")
	ErrDuplicate = errors.New("store: already exists")
	ErrLastOwner = errors.New("store: cannot remove the last owner")
)

// Store is the panel database. It is safe for concurrent use.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// Open opens (creating if needed) the database in dataDir and brings its
// schema up to date.
func Open(ctx context.Context, dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("store: data dir: %w", err)
	}
	path := filepath.Join(dataDir, FileName)
	dsn := "file:" + filepath.ToSlash(path) +
		"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	// One connection: SQLite serialises writers anyway, and this avoids
	// SQLITE_BUSY between our own connections.
	db.SetMaxOpenConns(1)
	s := &Store{db: db, now: time.Now}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	_ = os.Chmod(path, 0o600)
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func ms(t time.Time) int64 { return t.UnixMilli() }

func fromMs(v int64) time.Time { return time.UnixMilli(v).UTC() }

// tx runs fn in a transaction.
func (s *Store) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}
