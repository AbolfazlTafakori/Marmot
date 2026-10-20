package api

import "time"

// JSON shapes of backend/api/openapi.yaml. Field names follow the contract;
// the frontend types are generated from the same file.

type errorView struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TOTP     string `json:"totp,omitempty"`
}

type meView struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	Role        string `json:"role"`
	TOTPEnabled bool   `json:"totpEnabled"`
	CSRFToken   string `json:"csrfToken"`
	Locale      string `json:"locale,omitempty"`
}

type adminView struct {
	ID          string     `json:"id"`
	Username    string     `json:"username"`
	Role        string     `json:"role"`
	TOTPEnabled bool       `json:"totpEnabled"`
	CreatedAt   time.Time  `json:"createdAt"`
	LastLoginAt *time.Time `json:"lastLoginAt,omitempty"`
}

type adminCreate struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type nodeStatusView struct {
	NodeID    string           `json:"nodeId"`
	Role      string           `json:"role"`
	Version   string           `json:"version"`
	UptimeSec int64            `json:"uptimeSec"`
	Sessions  int              `json:"sessions"`
	Streams   int              `json:"streams"`
	BytesIn   uint64           `json:"bytesIn"`
	BytesOut  uint64           `json:"bytesOut"`
	Peers     []peerHealthView `json:"peers"`
}

type identityView struct {
	NodeID    string `json:"nodeId"`
	PublicKey string `json:"publicKey"`
	JoinToken string `json:"joinToken"`
}

type joinRequest struct {
	JoinToken string `json:"joinToken"`
	Weight    int    `json:"weight,omitempty"`
}

type configDocument struct {
	TOML     string   `json:"toml"`
	Version  string   `json:"version"`
	Warnings []string `json:"warnings,omitempty"`
}

type validationResult struct {
	Valid  bool        `json:"valid"`
	Issues []issueView `json:"issues"`
}

type issueView struct {
	Severity string `json:"severity"`
	Path     string `json:"path"`
	Message  string `json:"message"`
}

type steeringView struct {
	Ports      []portRuleView `json:"ports"`
	BypassNote string         `json:"bypassNote,omitempty"`
	Warnings   []string       `json:"warnings,omitempty"`
}

type portRuleView struct {
	Port       int      `json:"port"`
	Class      string   `json:"class"`
	Protocols  []string `json:"protocols"`
	TargetPort int      `json:"targetPort,omitempty"`
}

type peerView struct {
	ID         string          `json:"id"`
	PublicKey  string          `json:"publicKey"`
	Weight     int             `json:"weight,omitempty"`
	IPv4Pool   []string        `json:"ipv4Pool,omitempty"`
	IPv6Pool   []string        `json:"ipv6Pool,omitempty"`
	IPv6Subnet string          `json:"ipv6Subnet,omitempty"`
	Endpoints  []endpointView  `json:"endpoints"`
	Health     *peerHealthView `json:"health,omitempty"`
	Warnings   []string        `json:"warnings,omitempty"`
}

type endpointView struct {
	Transport string         `json:"transport"`
	Ports     []int          `json:"ports,omitempty"`
	PortRange string         `json:"portRange,omitempty"`
	Direction string         `json:"direction"`
	Family    string         `json:"family,omitempty"`
	Options   map[string]any `json:"options,omitempty"`
}

type peerHealthView struct {
	ID          string  `json:"id"`
	State       string  `json:"state"`
	ActivePaths int     `json:"activePaths"`
	RTTMs       float64 `json:"rttMs"`
	LossPct     float64 `json:"lossPct"`
}

type pathView struct {
	ID            string  `json:"id"`
	Local         string  `json:"local"`
	Remote        string  `json:"remote"`
	Transport     string  `json:"transport"`
	Role          string  `json:"role"`
	RTTMs         float64 `json:"rttMs"`
	JitterMs      float64 `json:"jitterMs"`
	LossPct       float64 `json:"lossPct"`
	ThroughputBps int64   `json:"throughputBps"`
	Score         float64 `json:"score"`
}

type trafficSeriesView struct {
	StepSec int64              `json:"stepSec"`
	Points  []trafficPointView `json:"points"`
}

type trafficPointView struct {
	T        time.Time `json:"t"`
	BytesIn  int64     `json:"bytesIn"`
	BytesOut int64     `json:"bytesOut"`
}

type auditPageView struct {
	NextCursor string          `json:"nextCursor,omitempty"`
	Items      []auditItemView `json:"items"`
}

type auditItemView struct {
	At       time.Time `json:"at"`
	Admin    string    `json:"admin"`
	Action   string    `json:"action"`
	Target   string    `json:"target"`
	SourceIP string    `json:"sourceIp,omitempty"`
}

type eventView struct {
	Type string         `json:"type"`
	At   time.Time      `json:"at"`
	Data map[string]any `json:"data,omitempty"`
}
