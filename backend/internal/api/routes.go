package api

import (
	"net/http"

	"marmot/internal/store"
)

// handlerFunc is an authenticated handler.
type handlerFunc func(w http.ResponseWriter, r *http.Request, a *authCtx)

// routes wires every endpoint of openapi.yaml with the least role it needs.
// Reading is open to every role; changing the node needs operator;
// managing administrators needs owner.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	public := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, h) }
	authed := func(pattern string, min store.Role, h handlerFunc) { mux.Handle(pattern, s.authenticate(min, h)) }
	const v1 = "/api/v1"

	public("GET /healthz", s.handleHealthz)
	public("GET /readyz", s.handleReadyz)
	public("GET "+v1+"/healthz", s.handleHealthz)
	public("GET "+v1+"/readyz", s.handleReadyz)
	public("POST "+v1+"/auth/login", s.handleLogin)

	authed("POST "+v1+"/auth/logout", store.RoleViewer, s.handleLogout)
	authed("GET "+v1+"/auth/me", store.RoleViewer, s.handleMe)
	authed("POST "+v1+"/auth/totp", store.RoleViewer, s.handleTOTPStart)
	authed("PUT "+v1+"/auth/totp", store.RoleViewer, s.handleTOTPConfirm)
	authed("DELETE "+v1+"/auth/totp", store.RoleViewer, s.handleTOTPDisable)

	authed("GET "+v1+"/node/status", store.RoleViewer, s.handleStatus)
	authed("GET "+v1+"/node/identity", store.RoleViewer, s.handleIdentity)
	authed("POST "+v1+"/node/reload", store.RoleOperator, s.handleReload)

	authed("GET "+v1+"/config", store.RoleViewer, s.handleConfigGet)
	authed("PUT "+v1+"/config", store.RoleOperator, s.handleConfigPut)
	authed("POST "+v1+"/config/validate", store.RoleViewer, s.handleConfigValidate)

	authed("GET "+v1+"/steering", store.RoleViewer, s.handleSteeringGet)
	authed("PUT "+v1+"/steering", store.RoleOperator, s.handleSteeringPut)

	authed("GET "+v1+"/peers", store.RoleViewer, s.handlePeersList)
	authed("POST "+v1+"/peers", store.RoleOperator, s.handlePeerCreate)
	authed("GET "+v1+"/peers/{peerId}", store.RoleViewer, s.handlePeerGet)
	authed("PUT "+v1+"/peers/{peerId}", store.RoleOperator, s.handlePeerUpdate)
	authed("DELETE "+v1+"/peers/{peerId}", store.RoleOperator, s.handlePeerDelete)
	authed("GET "+v1+"/peers/{peerId}/paths", store.RoleViewer, s.handlePeerPaths)

	authed("GET "+v1+"/stats/traffic", store.RoleViewer, s.handleTraffic)

	authed("GET "+v1+"/admins", store.RoleOwner, s.handleAdminsList)
	authed("POST "+v1+"/admins", store.RoleOwner, s.handleAdminCreate)
	authed("DELETE "+v1+"/admins/{adminId}", store.RoleOwner, s.handleAdminDelete)

	authed("GET "+v1+"/audit", store.RoleOperator, s.handleAudit)
	authed("GET "+v1+"/ws", store.RoleViewer, s.handleWS)

	// Anything else under the API prefix is a 404 in JSON, not the panel.
	public(v1+"/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "no such endpoint")
	})
	mux.Handle("/", s.staticHandler())

	return s.securityHeaders(s.allowIPs(mux))
}
