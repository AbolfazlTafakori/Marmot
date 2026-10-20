package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"marmot/internal/config"
)

// Join tokens let one node import another as a peer in one paste
// (ADR-0009): "mt1.<payload>.<signature>", both base64url, the signature
// by the issuing node's identity key over the payload bytes.
const joinTokenPrefix = "mt1."

type joinPayload struct {
	V          int            `json:"v"`
	NodeID     string         `json:"id"`
	PublicKey  string         `json:"pk"`
	IPv4Pool   []string       `json:"ipv4,omitempty"`
	IPv6Pool   []string       `json:"ipv6pool,omitempty"`
	IPv6Subnet string         `json:"ipv6,omitempty"`
	Endpoints  []joinEndpoint `json:"endpoints,omitempty"`
	IssuedAt   int64          `json:"iat"`
}

type joinEndpoint struct {
	Transport string         `json:"transport"`
	Ports     []uint16       `json:"ports"`
	Options   map[string]any `json:"options,omitempty"`
}

var errBadToken = errors.New("join token is malformed or its signature does not match")

// exportedOptions are the listener options a dialer needs to match: the
// TLS server name, the WebSocket path, the gRPC service and whether TLS is
// on. Certificate paths stay private.
var exportedOptions = []string{"sni", "path", "service", "tls"}

// makeJoinToken describes this node from its configuration.
func makeJoinToken(c *config.Config, pub ed25519.PublicKey, sign func([]byte) []byte, now time.Time) (string, error) {
	p := joinPayload{V: 1, NodeID: c.Node.ID, PublicKey: config.FormatPublicKey(pub),
		IPv4Pool: c.Local.IPv4Pool, IPv6Pool: c.Local.IPv6Pool, IPv6Subnet: c.Local.IPv6Subnet, IssuedAt: now.Unix()}
	// Listeners of one transport with the same options become one
	// endpoint with several ports.
	byKey := map[string]int{}
	for _, tl := range c.TransportListen {
		if tl.Port == 0 {
			continue
		}
		var opts map[string]any
		for _, k := range exportedOptions {
			if v, ok := tl.Options[k]; ok && v != "" {
				if opts == nil {
					opts = map[string]any{}
				}
				opts[k] = v
			}
		}
		key, _ := json.Marshal([]any{tl.Transport, opts}) // map keys marshal sorted
		i, ok := byKey[string(key)]
		if !ok {
			i = len(p.Endpoints)
			byKey[string(key)] = i
			p.Endpoints = append(p.Endpoints, joinEndpoint{Transport: tl.Transport, Options: opts})
		}
		p.Endpoints[i].Ports = append(p.Endpoints[i].Ports, tl.Port)
	}
	body, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	return joinTokenPrefix + enc.EncodeToString(body) + "." + enc.EncodeToString(sign(body)), nil
}

// parseJoinToken verifies a token and turns it into a peer entry. The
// signature proves the token was not edited after the issuing node made
// it; trusting that node is the administrator's decision in pasting it.
func parseJoinToken(token string, weight int) (config.Peer, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(token), joinTokenPrefix)
	if !ok {
		return config.Peer{}, errBadToken
	}
	bodyB64, sigB64, ok := strings.Cut(rest, ".")
	if !ok {
		return config.Peer{}, errBadToken
	}
	enc := base64.RawURLEncoding
	body, err1 := enc.DecodeString(bodyB64)
	sig, err2 := enc.DecodeString(sigB64)
	if err1 != nil || err2 != nil {
		return config.Peer{}, errBadToken
	}
	var p joinPayload
	if err := json.Unmarshal(body, &p); err != nil || p.V != 1 {
		return config.Peer{}, errBadToken
	}
	pub, err := config.ParsePublicKey(p.PublicKey)
	if err != nil || !ed25519.Verify(pub, body, sig) {
		return config.Peer{}, errBadToken
	}
	peer := config.Peer{ID: p.NodeID, PublicKey: p.PublicKey, Weight: weight,
		IPv4Pool: p.IPv4Pool, IPv6Pool: p.IPv6Pool, IPv6Subnet: p.IPv6Subnet}
	// Without an address the endpoints cannot be dialed; the peer is then
	// inbound-only and dials us.
	if len(p.IPv4Pool) > 0 || len(p.IPv6Pool) > 0 || p.IPv6Subnet != "" {
		for _, e := range p.Endpoints {
			peer.Endpoints = append(peer.Endpoints, config.Endpoint{Transport: e.Transport, Ports: e.Ports, Options: e.Options})
		}
	}
	return peer, nil
}
