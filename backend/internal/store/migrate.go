package store

import (
	"context"
	"database/sql"
	"fmt"
)

// migrations are applied in order; the database's user_version records how
// many have run. Never edit a released migration, only append.
var migrations = []string{
	`CREATE TABLE admins (
		id            TEXT PRIMARY KEY,
		username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
		password_hash TEXT NOT NULL,
		role          TEXT NOT NULL CHECK (role IN ('owner', 'operator', 'viewer')),
		totp_secret   TEXT NOT NULL DEFAULT '',
		totp_pending  TEXT NOT NULL DEFAULT '',
		locale        TEXT NOT NULL DEFAULT 'fa',
		created_at    INTEGER NOT NULL,
		last_login_at INTEGER
	);
	CREATE TABLE auth_sessions (
		token_hash BLOB PRIMARY KEY,
		admin_id   TEXT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
		csrf       TEXT NOT NULL,
		source_ip  TEXT NOT NULL DEFAULT '',
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL
	);
	CREATE INDEX auth_sessions_admin ON auth_sessions(admin_id);
	CREATE TABLE audit (
		id        INTEGER PRIMARY KEY AUTOINCREMENT,
		at        INTEGER NOT NULL,
		admin     TEXT NOT NULL,
		action    TEXT NOT NULL,
		target    TEXT NOT NULL,
		source_ip TEXT NOT NULL DEFAULT ''
	);
	CREATE TABLE traffic (
		scope     TEXT NOT NULL,
		t         INTEGER NOT NULL,
		bytes_in  INTEGER NOT NULL,
		bytes_out INTEGER NOT NULL,
		PRIMARY KEY (scope, t)
	) WITHOUT ROWID;`,
}

func (s *Store) migrate(ctx context.Context) error {
	var version int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("store: read schema version: %w", err)
	}
	if version > len(migrations) {
		return fmt.Errorf("store: database schema %d is newer than this binary (%d)", version, len(migrations))
	}
	for i := version; i < len(migrations); i++ {
		err := s.tx(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, i+1))
			return err
		})
		if err != nil {
			return fmt.Errorf("store: migration %d: %w", i+1, err)
		}
	}
	return nil
}
