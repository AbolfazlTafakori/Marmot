package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Role is an administrator's permission level.
type Role string

// Roles, from most to least privileged.
const (
	RoleOwner    Role = "owner"    // everything, including administrators
	RoleOperator Role = "operator" // change configuration
	RoleViewer   Role = "viewer"   // read only
)

// Valid reports whether r is a known role.
func (r Role) Valid() bool { return r == RoleOwner || r == RoleOperator || r == RoleViewer }

// Admin is a panel administrator.
type Admin struct {
	ID           string
	Username     string
	Role         Role
	PasswordHash string
	TOTPSecret   string // base32; empty = TOTP off
	TOTPPending  string // secret awaiting confirmation
	Locale       string
	CreatedAt    time.Time
	LastLoginAt  time.Time // zero = never
}

// TOTPEnabled reports whether a second factor is required.
func (a *Admin) TOTPEnabled() bool { return a.TOTPSecret != "" }

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

const adminCols = `id, username, password_hash, role, totp_secret, totp_pending, locale, created_at, last_login_at`

func scanAdmin(row interface{ Scan(...any) error }) (*Admin, error) {
	var a Admin
	var created int64
	var last sql.NullInt64
	err := row.Scan(&a.ID, &a.Username, &a.PasswordHash, &a.Role, &a.TOTPSecret, &a.TOTPPending, &a.Locale, &created, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	a.CreatedAt = fromMs(created)
	if last.Valid {
		a.LastLoginAt = fromMs(last.Int64)
	}
	return &a, nil
}

// CreateAdmin inserts a, assigning ID and CreatedAt.
func (s *Store) CreateAdmin(ctx context.Context, a *Admin) error {
	if !a.Role.Valid() {
		return fmt.Errorf("store: invalid role %q", a.Role)
	}
	a.ID, a.CreatedAt = newID(), s.now().UTC().Truncate(time.Millisecond)
	if a.Locale == "" {
		a.Locale = "fa"
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO admins (id, username, password_hash, role, locale, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		a.ID, a.Username, a.PasswordHash, a.Role, a.Locale, ms(a.CreatedAt))
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return ErrDuplicate
	}
	return err
}

// AdminByUsername looks an administrator up, case-insensitively.
func (s *Store) AdminByUsername(ctx context.Context, username string) (*Admin, error) {
	return scanAdmin(s.db.QueryRowContext(ctx, `SELECT `+adminCols+` FROM admins WHERE username = ?`, username))
}

// AdminByID looks an administrator up by id.
func (s *Store) AdminByID(ctx context.Context, id string) (*Admin, error) {
	return scanAdmin(s.db.QueryRowContext(ctx, `SELECT `+adminCols+` FROM admins WHERE id = ?`, id))
}

// ListAdmins returns all administrators by username.
func (s *Store) ListAdmins(ctx context.Context) ([]*Admin, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+adminCols+` FROM admins ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Admin
	for rows.Next() {
		a, err := scanAdmin(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// CountAdmins returns how many administrators exist.
func (s *Store) CountAdmins(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM admins`).Scan(&n)
	return n, err
}

// DeleteAdmin removes an administrator and their sessions. The last owner
// cannot be removed, so the panel can never be left without one.
func (s *Store) DeleteAdmin(ctx context.Context, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var role Role
		err := tx.QueryRowContext(ctx, `SELECT role FROM admins WHERE id = ?`, id).Scan(&role)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if role == RoleOwner {
			var owners int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM admins WHERE role = 'owner'`).Scan(&owners); err != nil {
				return err
			}
			if owners <= 1 {
				return ErrLastOwner
			}
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM admins WHERE id = ?`, id)
		return err
	})
}

// updateAdmin runs one complete UPDATE statement whose last parameter is the
// administrator id, and reports ErrNotFound if no row matched.
func (s *Store) updateAdmin(ctx context.Context, query string, args ...any) error {
	res, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetPassword replaces an administrator's password hash and ends their
// sessions.
func (s *Store) SetPassword(ctx context.Context, id, hash string) error {
	if err := s.updateAdmin(ctx, `UPDATE admins SET password_hash = ? WHERE id = ?`, hash, id); err != nil {
		return err
	}
	return s.DeleteAdminSessions(ctx, id)
}

// SetTOTPPending stores a secret awaiting confirmation.
func (s *Store) SetTOTPPending(ctx context.Context, id, secret string) error {
	return s.updateAdmin(ctx, `UPDATE admins SET totp_pending = ? WHERE id = ?`, secret, id)
}

// EnableTOTP makes the pending secret the active one.
func (s *Store) EnableTOTP(ctx context.Context, id string) error {
	return s.updateAdmin(ctx, `UPDATE admins SET totp_secret = totp_pending, totp_pending = '' WHERE id = ?`, id)
}

// DisableTOTP removes the second factor.
func (s *Store) DisableTOTP(ctx context.Context, id string) error {
	return s.updateAdmin(ctx, `UPDATE admins SET totp_secret = '', totp_pending = '' WHERE id = ?`, id)
}

// SetLocale stores an administrator's interface language.
func (s *Store) SetLocale(ctx context.Context, id, locale string) error {
	return s.updateAdmin(ctx, `UPDATE admins SET locale = ? WHERE id = ?`, locale, id)
}

// TouchLogin records a successful login.
func (s *Store) TouchLogin(ctx context.Context, id string) error {
	return s.updateAdmin(ctx, `UPDATE admins SET last_login_at = ? WHERE id = ?`, ms(s.now()), id)
}
