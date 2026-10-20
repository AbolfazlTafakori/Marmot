package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"time"

	"marmot/internal/store"
)

// Session cookie and lifetime: a session ends after sessionIdle without
// use; each use within the second half of that pushes the end back.
const (
	sessionCookie = "marmot_session"
	csrfHeader    = "X-CSRF-Token"
	sessionIdle   = 12 * time.Hour
	maxBodyBytes  = 1 << 20
)

// authCtx is the authenticated caller of a request.
type authCtx struct {
	admin   *store.Admin
	session *store.AuthSession
	ip      string
}

var roleRank = map[store.Role]int{store.RoleViewer: 1, store.RoleOperator: 2, store.RoleOwner: 3}

func clientIP(r *http.Request) string {
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return ap.Addr().Unmap().String()
	}
	return r.RemoteAddr
}

func tokenHash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// authenticate loads the session from its cookie, enforces the role and,
// for state-changing methods, the CSRF token.
func (s *Server) authenticate(min store.Role, h handlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil || c.Value == "" {
			writeError(w, http.StatusUnauthorized, "unauthorized", "log in first")
			return
		}
		hash := tokenHash(c.Value)
		sess, err := s.cfg.Store.SessionByToken(r.Context(), hash)
		if err != nil {
			s.internalUnless(w, err, store.ErrNotFound, http.StatusUnauthorized, "unauthorized", "session expired")
			return
		}
		admin, err := s.cfg.Store.AdminByID(r.Context(), sess.AdminID)
		if err != nil {
			s.internalUnless(w, err, store.ErrNotFound, http.StatusUnauthorized, "unauthorized", "session expired")
			return
		}
		if !safeMethod(r.Method) {
			got := r.Header.Get(csrfHeader)
			if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(sess.CSRF)) != 1 {
				writeError(w, http.StatusForbidden, "csrf", "missing or wrong "+csrfHeader+" header")
				return
			}
		}
		if roleRank[admin.Role] < roleRank[min] {
			writeError(w, http.StatusForbidden, "forbidden", "your role is not allowed to do this")
			return
		}
		if until := s.now().Add(sessionIdle); until.Sub(sess.ExpiresAt) > sessionIdle/2 {
			_ = s.cfg.Store.ExtendSession(r.Context(), hash, until)
		}
		h(w, r, &authCtx{admin: admin, session: sess, ip: clientIP(r)})
	})
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// allowIPs rejects clients outside api.allow_ips (empty = everyone). The
// list is read per request, so a reload applies at once.
func (s *Server) allowIPs(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allow := s.cfg.Node.Config().API.AllowIPs
		if len(allow) > 0 && !ipAllowed(clientIP(r), allow) {
			writeError(w, http.StatusForbidden, "forbidden", "address not allowed")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func ipAllowed(ip string, allow []string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, a := range allow {
		if p, err := netip.ParsePrefix(a); err == nil && p.Contains(addr) {
			return true
		}
		if x, err := netip.ParseAddr(a); err == nil && x.Unmap() == addr {
			return true
		}
	}
	return false
}

// securityHeaders sets headers that keep the panel from being framed,
// sniffed, or made to load foreign scripts.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data:; "+
			"style-src 'self' 'unsafe-inline'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, errorView{Code: code, Message: msg})
}

// internalUnless answers with status/code when err is want, and with 500
// otherwise (logging the cause).
func (s *Server) internalUnless(w http.ResponseWriter, err, want error, status int, code, msg string) {
	if errors.Is(err, want) {
		writeError(w, status, code, msg)
		return
	}
	s.internal(w, err)
}

func (s *Server) internal(w http.ResponseWriter, err error) {
	s.log.Error("api internal error", "err", err)
	writeError(w, http.StatusInternalServerError, "internal", "internal error")
}

// decodeJSON reads a JSON body of at most maxBodyBytes into v.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes))
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

// audit records an action; a failure to record is logged, never fatal.
func (s *Server) audit(r *http.Request, a *authCtx, action, target string) {
	admin, ip := "-", clientIP(r)
	if a != nil {
		admin = a.admin.Username
	}
	if err := s.cfg.Store.AddAudit(r.Context(), store.AuditEntry{Admin: admin, Action: action, Target: target, SourceIP: ip}); err != nil {
		s.log.Warn("audit write failed", "action", action, "err", err)
	}
}
