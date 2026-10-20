package api

import (
	"errors"
	"net/http"
	"strconv"

	"marmot/internal/store"
)

func adminViewOf(a *store.Admin) adminView {
	v := adminView{ID: a.ID, Username: a.Username, Role: string(a.Role), TOTPEnabled: a.TOTPEnabled(), CreatedAt: a.CreatedAt}
	if !a.LastLoginAt.IsZero() {
		t := a.LastLoginAt
		v.LastLoginAt = &t
	}
	return v
}

func (s *Server) handleAdminsList(w http.ResponseWriter, r *http.Request, a *authCtx) {
	list, err := s.cfg.Store.ListAdmins(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	out := make([]adminView, 0, len(list))
	for _, x := range list {
		out = append(out, adminViewOf(x))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAdminCreate(w http.ResponseWriter, r *http.Request, a *authCtx) {
	var req adminCreate
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := validUsername(req.Username); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if len(req.Password) < MinPasswordLen {
		writeError(w, http.StatusBadRequest, "bad_request", "password must be at least "+strconv.Itoa(MinPasswordLen)+" characters")
		return
	}
	role := store.Role(req.Role)
	if !role.Valid() {
		writeError(w, http.StatusBadRequest, "bad_request", "role must be owner, operator or viewer")
		return
	}
	hash, err := HashPassword(req.Password)
	if err != nil {
		s.internal(w, err)
		return
	}
	adm := &store.Admin{Username: req.Username, PasswordHash: hash, Role: role}
	if err := s.cfg.Store.CreateAdmin(r.Context(), adm); err != nil {
		s.internalUnless(w, err, store.ErrDuplicate, http.StatusConflict, "conflict", "username already taken")
		return
	}
	s.audit(r, a, "admin.create", adm.Username+" ("+string(role)+")")
	writeJSON(w, http.StatusCreated, adminViewOf(adm))
}

func (s *Server) handleAdminDelete(w http.ResponseWriter, r *http.Request, a *authCtx) {
	id := r.PathValue("adminId")
	target, err := s.cfg.Store.AdminByID(r.Context(), id)
	if err != nil {
		s.internalUnless(w, err, store.ErrNotFound, http.StatusNotFound, "not_found", "no such administrator")
		return
	}
	switch err := s.cfg.Store.DeleteAdmin(r.Context(), id); {
	case errors.Is(err, store.ErrLastOwner):
		writeError(w, http.StatusForbidden, "last_owner", "the last owner cannot be deleted")
		return
	case err != nil:
		s.internalUnless(w, err, store.ErrNotFound, http.StatusNotFound, "not_found", "no such administrator")
		return
	}
	s.audit(r, a, "admin.delete", target.Username)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, a *authCtx) {
	q := r.URL.Query()
	limit := 50
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 200 {
			writeError(w, http.StatusBadRequest, "bad_request", "limit must be 1..200")
			return
		}
		limit = n
	}
	var cursor int64
	if v := q.Get("cursor"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "bad_request", "invalid cursor")
			return
		}
		cursor = n
	}
	entries, next, err := s.cfg.Store.ListAudit(r.Context(), cursor, limit)
	if err != nil {
		s.internal(w, err)
		return
	}
	page := auditPageView{Items: make([]auditItemView, 0, len(entries))}
	for _, e := range entries {
		page.Items = append(page.Items, auditItemView{At: e.At, Admin: e.Admin, Action: e.Action, Target: e.Target, SourceIP: e.SourceIP})
	}
	if next > 0 {
		page.NextCursor = strconv.FormatInt(next, 10)
	}
	writeJSON(w, http.StatusOK, page)
}
