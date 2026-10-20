package api

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"

	"marmot/internal/store"
)

func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ip := clientIP(r)
	userKey := strings.ToLower(strings.TrimSpace(req.Username))
	for _, lim := range []struct {
		l   *rateLimiter
		key string
	}{{s.loginIP, ip}, {s.loginUser, userKey}} {
		if blocked, wait := lim.l.blocked(lim.key); blocked {
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
			writeError(w, http.StatusTooManyRequests, "rate_limited", "too many failed logins; try again later")
			return
		}
	}

	fail := func(code, msg string) {
		s.loginIP.fail(ip)
		s.loginUser.fail(userKey)
		s.audit(r, nil, "login.fail", userKey)
		writeError(w, http.StatusUnauthorized, code, msg)
	}
	admin, err := s.cfg.Store.AdminByUsername(r.Context(), userKey)
	hash := dummyHash()
	if err == nil {
		hash = admin.PasswordHash
	} else if !errors.Is(err, store.ErrNotFound) {
		s.internal(w, err)
		return
	}
	ok, _ := VerifyPassword(hash, req.Password)
	if admin == nil || !ok {
		fail("invalid_credentials", "wrong username or password")
		return
	}
	if admin.TOTPEnabled() {
		if req.TOTP == "" {
			// Not counted as a failure: the client is asked for its code.
			writeError(w, http.StatusUnauthorized, "totp_required", "enter the code from your authenticator app")
			return
		}
		if !verifyTOTP(admin.TOTPSecret, req.TOTP, s.now()) {
			fail("invalid_totp", "wrong authenticator code")
			return
		}
	}

	token := randomToken(32)
	sess := &store.AuthSession{
		TokenHash: tokenHash(token), AdminID: admin.ID, CSRF: randomToken(24), SourceIP: ip,
		CreatedAt: s.now(), ExpiresAt: s.now().Add(sessionIdle),
	}
	if err := s.cfg.Store.CreateSession(r.Context(), sess); err != nil {
		s.internal(w, err)
		return
	}
	_ = s.cfg.Store.TouchLogin(r.Context(), admin.ID)
	s.loginIP.reset(ip)
	s.loginUser.reset(userKey)
	// Secure whenever the panel is served over TLS; a plain-HTTP panel (behind
	// a TLS proxy, or on a private network) could not get the cookie back.
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // see above
		Name: sessionCookie, Value: token, Path: "/", HttpOnly: true,
		Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode,
	})
	a := &authCtx{admin: admin, session: sess, ip: ip}
	s.audit(r, a, "login.ok", admin.Username)
	writeJSON(w, http.StatusOK, me(a))
}

func me(a *authCtx) meView {
	return meView{ID: a.admin.ID, Username: a.admin.Username, Role: string(a.admin.Role),
		TOTPEnabled: a.admin.TOTPEnabled(), CSRFToken: a.session.CSRF, Locale: a.admin.Locale}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, a *authCtx) {
	if err := s.cfg.Store.DeleteSession(r.Context(), a.session.TokenHash); err != nil {
		s.internal(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, //nolint:gosec // as at login
		Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
	s.audit(r, a, "logout", a.admin.Username)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, a *authCtx) {
	writeJSON(w, http.StatusOK, me(a))
}

// handleTOTPStart creates a pending secret; it takes effect only once a
// code from it is confirmed, so a half-finished enrolment locks no one out.
func (s *Server) handleTOTPStart(w http.ResponseWriter, r *http.Request, a *authCtx) {
	if a.admin.TOTPEnabled() {
		writeError(w, http.StatusConflict, "conflict", "TOTP is already enabled; disable it first")
		return
	}
	secret, err := newTOTPSecret()
	if err != nil {
		s.internal(w, err)
		return
	}
	if err := s.cfg.Store.SetTOTPPending(r.Context(), a.admin.ID, secret); err != nil {
		s.internal(w, err)
		return
	}
	nodeID := s.cfg.Node.Config().Node.ID
	writeJSON(w, http.StatusOK, map[string]string{"uri": totpURI(secret, a.admin.Username, nodeID)})
}

func (s *Server) handleTOTPConfirm(w http.ResponseWriter, r *http.Request, a *authCtx) {
	var req struct {
		Code string `json:"code"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if a.admin.TOTPPending == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "start enrolment first")
		return
	}
	if !verifyTOTP(a.admin.TOTPPending, req.Code, s.now()) {
		writeError(w, http.StatusBadRequest, "invalid_totp", "wrong authenticator code")
		return
	}
	if err := s.cfg.Store.EnableTOTP(r.Context(), a.admin.ID); err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r, a, "totp.enable", a.admin.Username)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request, a *authCtx) {
	if !a.admin.TOTPEnabled() {
		writeError(w, http.StatusBadRequest, "bad_request", "TOTP is not enabled")
		return
	}
	if !verifyTOTP(a.admin.TOTPSecret, r.URL.Query().Get("code"), s.now()) {
		writeError(w, http.StatusBadRequest, "invalid_totp", "wrong authenticator code")
		return
	}
	if err := s.cfg.Store.DisableTOTP(r.Context(), a.admin.ID); err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r, a, "totp.disable", a.admin.Username)
	w.WriteHeader(http.StatusNoContent)
}

// validUsername allows what fits in a URL and a log line unescaped.
func validUsername(u string) error {
	if len(u) < 3 || len(u) > 32 {
		return fmt.Errorf("username must be 3 to 32 characters")
	}
	for _, c := range u {
		if !usernameChar(c) {
			return fmt.Errorf("username may contain only letters, digits, '-', '_' and '.'")
		}
	}
	return nil
}

func usernameChar(c rune) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	default:
		return c == '-' || c == '_' || c == '.'
	}
}
