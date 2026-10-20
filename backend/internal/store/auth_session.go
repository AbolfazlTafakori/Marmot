package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// AuthSession is a logged-in panel session. Only a hash of the cookie
// token is stored, so a copy of the database cannot be used to log in.
type AuthSession struct {
	TokenHash []byte
	AdminID   string
	CSRF      string
	SourceIP  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// CreateSession stores a new session.
func (s *Store) CreateSession(ctx context.Context, a *AuthSession) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO auth_sessions (token_hash, admin_id, csrf, source_ip, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
		a.TokenHash, a.AdminID, a.CSRF, a.SourceIP, ms(a.CreatedAt), ms(a.ExpiresAt))
	return err
}

// SessionByToken returns the unexpired session with this token hash.
func (s *Store) SessionByToken(ctx context.Context, hash []byte) (*AuthSession, error) {
	var a AuthSession
	var created, expires int64
	err := s.db.QueryRowContext(ctx,
		`SELECT token_hash, admin_id, csrf, source_ip, created_at, expires_at FROM auth_sessions WHERE token_hash = ? AND expires_at > ?`,
		hash, ms(s.now())).Scan(&a.TokenHash, &a.AdminID, &a.CSRF, &a.SourceIP, &created, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	a.CreatedAt, a.ExpiresAt = fromMs(created), fromMs(expires)
	return &a, nil
}

// ExtendSession moves a session's expiry (sliding expiration).
func (s *Store) ExtendSession(ctx context.Context, hash []byte, until time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE auth_sessions SET expires_at = ? WHERE token_hash = ?`, ms(until), hash)
	return err
}

// DeleteSession ends one session.
func (s *Store) DeleteSession(ctx context.Context, hash []byte) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM auth_sessions WHERE token_hash = ?`, hash)
	return err
}

// DeleteAdminSessions ends every session of an administrator.
func (s *Store) DeleteAdminSessions(ctx context.Context, adminID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM auth_sessions WHERE admin_id = ?`, adminID)
	return err
}

// PurgeExpired removes expired sessions.
func (s *Store) PurgeExpired(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM auth_sessions WHERE expires_at <= ?`, ms(s.now()))
	return err
}
