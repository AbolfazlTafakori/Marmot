package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestReopenKeepsDataAndSchema(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	s, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAdmin(ctx, &Admin{Username: "root", PasswordHash: "h", Role: RoleOwner}); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s, err = Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if n, _ := s.CountAdmins(ctx); n != 1 {
		t.Fatalf("admins after reopen: %d", n)
	}
}

func TestAdmins(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	owner := &Admin{Username: "Owner", PasswordHash: "h1", Role: RoleOwner}
	if err := s.CreateAdmin(ctx, owner); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAdmin(ctx, &Admin{Username: "owner", PasswordHash: "x", Role: RoleViewer}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("case-insensitive duplicate: %v", err)
	}
	if err := s.CreateAdmin(ctx, &Admin{Username: "bad", Role: "god"}); err == nil {
		t.Fatal("invalid role accepted")
	}
	op := &Admin{Username: "op", PasswordHash: "h2", Role: RoleOperator}
	if err := s.CreateAdmin(ctx, op); err != nil {
		t.Fatal(err)
	}

	got, err := s.AdminByUsername(ctx, "OWNER")
	if err != nil || got.ID != owner.ID || got.Locale != "fa" || !got.LastLoginAt.IsZero() {
		t.Fatalf("by username: %+v %v", got, err)
	}
	if _, err := s.AdminByID(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	list, _ := s.ListAdmins(ctx)
	if len(list) != 2 || list[0].Username != "op" {
		t.Fatalf("list %+v", list)
	}

	// TOTP: pending, then enabled, then disabled.
	_ = s.SetTOTPPending(ctx, op.ID, "SECRET")
	a, _ := s.AdminByID(ctx, op.ID)
	if a.TOTPEnabled() || a.TOTPPending != "SECRET" {
		t.Fatalf("pending %+v", a)
	}
	_ = s.EnableTOTP(ctx, op.ID)
	a, _ = s.AdminByID(ctx, op.ID)
	if !a.TOTPEnabled() || a.TOTPPending != "" {
		t.Fatalf("enabled %+v", a)
	}
	_ = s.DisableTOTP(ctx, op.ID)
	_ = s.SetLocale(ctx, op.ID, "en")
	_ = s.TouchLogin(ctx, op.ID)
	a, _ = s.AdminByID(ctx, op.ID)
	if a.TOTPEnabled() || a.Locale != "en" || a.LastLoginAt.IsZero() {
		t.Fatalf("after updates %+v", a)
	}

	// The last owner stays.
	if err := s.DeleteAdmin(ctx, owner.ID); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("delete last owner: %v", err)
	}
	if err := s.DeleteAdmin(ctx, op.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAdmin(ctx, op.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
	if err := s.SetLocale(ctx, "nope", "en"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update missing: %v", err)
	}
}

func TestSessions(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	a := &Admin{Username: "u", PasswordHash: "h", Role: RoleOwner}
	_ = s.CreateAdmin(ctx, a)
	now := time.Now()
	live := &AuthSession{TokenHash: []byte("live"), AdminID: a.ID, CSRF: "c", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	old := &AuthSession{TokenHash: []byte("old"), AdminID: a.ID, CSRF: "c", CreatedAt: now, ExpiresAt: now.Add(-time.Second)}
	for _, x := range []*AuthSession{live, old} {
		if err := s.CreateSession(ctx, x); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := s.SessionByToken(ctx, []byte("live")); err != nil || got.AdminID != a.ID || got.CSRF != "c" {
		t.Fatalf("live: %+v %v", got, err)
	}
	if _, err := s.SessionByToken(ctx, []byte("old")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired session returned: %v", err)
	}
	_ = s.ExtendSession(ctx, []byte("old"), now.Add(time.Hour))
	if _, err := s.SessionByToken(ctx, []byte("old")); err != nil {
		t.Fatalf("extended: %v", err)
	}
	// A password change ends every session.
	if err := s.SetPassword(ctx, a.ID, "new"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionByToken(ctx, []byte("live")); !errors.Is(err, ErrNotFound) {
		t.Fatal("session survived password change")
	}
	_ = s.CreateSession(ctx, old)
	_ = s.PurgeExpired(ctx)
	_ = s.CreateSession(ctx, live)
	_ = s.DeleteSession(ctx, []byte("live"))
	if _, err := s.SessionByToken(ctx, []byte("live")); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted session returned")
	}
}

func TestAuditPaging(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if err := s.AddAudit(ctx, AuditEntry{Admin: "u", Action: "peer.add", Target: string(rune('a' + i)), SourceIP: "192.0.2.1"}); err != nil {
			t.Fatal(err)
		}
	}
	page1, next, err := s.ListAudit(ctx, 0, 2)
	if err != nil || len(page1) != 2 || page1[0].Target != "e" || next == 0 {
		t.Fatalf("page1 %+v next %d %v", page1, next, err)
	}
	page2, next, _ := s.ListAudit(ctx, next, 2)
	if len(page2) != 2 || page2[0].Target != "c" {
		t.Fatalf("page2 %+v", page2)
	}
	page3, next, _ := s.ListAudit(ctx, next, 2)
	if len(page3) != 1 || page3[0].Target != "a" || next != 0 {
		t.Fatalf("page3 %+v next %d", page3, next)
	}
}

func TestTraffic(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	base := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		err := s.AddTraffic(ctx, base.Add(time.Duration(i)*time.Minute), []TrafficSample{
			{Scope: ScopeNode, BytesIn: 100, BytesOut: 10},
			{Scope: ScopePort(443), BytesIn: 1, BytesOut: 2},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// Same step again accumulates.
	_ = s.AddTraffic(ctx, base, []TrafficSample{{Scope: ScopeNode, BytesIn: 5}})

	pts, err := s.QueryTraffic(ctx, ScopeNode, base, base.Add(15*time.Minute), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(pts) != 3 || pts[0].BytesIn != 505 || pts[1].BytesIn != 500 || pts[2].BytesIn != 0 || pts[1].BytesOut != 50 {
		t.Fatalf("points %+v", pts)
	}
	if !pts[1].T.Equal(base.Add(5 * time.Minute)) {
		t.Fatalf("bucket time %v", pts[1].T)
	}
	if pts, _ := s.QueryTraffic(ctx, ScopePort(443), base, base.Add(10*time.Minute), 10*time.Minute); pts[0].BytesOut != 20 {
		t.Fatalf("port points %+v", pts)
	}
	_ = s.PurgeTraffic(ctx, base.Add(5*time.Minute))
	pts, _ = s.QueryTraffic(ctx, ScopeNode, base, base.Add(10*time.Minute), 5*time.Minute)
	if pts[0].BytesIn != 0 || pts[1].BytesIn != 500 {
		t.Fatalf("after purge %+v", pts)
	}
	if ScopePeer("k") != "peer:k" {
		t.Fatal("ScopePeer")
	}
}
