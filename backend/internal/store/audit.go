package store

import (
	"context"
	"time"
)

// AuditEntry records who changed what.
type AuditEntry struct {
	ID       int64
	At       time.Time
	Admin    string // username, or "-" for an unknown user (failed login)
	Action   string // e.g. peer.delete, config.update, login.fail
	Target   string
	SourceIP string
}

// AddAudit appends an entry; At defaults to now.
func (s *Store) AddAudit(ctx context.Context, e AuditEntry) error {
	if e.At.IsZero() {
		e.At = s.now()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit (at, admin, action, target, source_ip) VALUES (?, ?, ?, ?, ?)`,
		ms(e.At), e.Admin, e.Action, e.Target, e.SourceIP)
	return err
}

// ListAudit returns up to limit entries, newest first, older than cursor
// (0 = from the newest). next is the cursor for the following page, or 0
// when there are no more.
func (s *Store) ListAudit(ctx context.Context, cursor int64, limit int) (entries []AuditEntry, next int64, err error) {
	q := `SELECT id, at, admin, action, target, source_ip FROM audit`
	args := []any{}
	if cursor > 0 {
		q += ` WHERE id < ?`
		args = append(args, cursor)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit+1)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var e AuditEntry
		var at int64
		if err := rows.Scan(&e.ID, &at, &e.Admin, &e.Action, &e.Target, &e.SourceIP); err != nil {
			return nil, 0, err
		}
		e.At = fromMs(at)
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if len(entries) > limit {
		entries = entries[:limit]
		next = entries[limit-1].ID
	}
	return entries, next, nil
}
