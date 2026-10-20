package core

import (
	"errors"
	"fmt"
)

// MaxNodeIDLen bounds node identifiers so they fit in one length byte on the wire.
const MaxNodeIDLen = 63

// NodeID identifies a Marmot node. It is lowercase ASCII letters, digits and
// '-', starts with a letter or digit, and is at most MaxNodeIDLen bytes.
type NodeID string

// ErrInvalidNodeID is returned for malformed node identifiers.
var ErrInvalidNodeID = errors.New("invalid node id")

// ParseNodeID validates s and returns it as a NodeID.
func ParseNodeID(s string) (NodeID, error) {
	if len(s) == 0 || len(s) > MaxNodeIDLen {
		return "", fmt.Errorf("%w: length %d not in 1..%d", ErrInvalidNodeID, len(s), MaxNodeIDLen)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c == '-' && i > 0)
		if !ok {
			return "", fmt.Errorf("%w: %q", ErrInvalidNodeID, s)
		}
	}
	return NodeID(s), nil
}

func (id NodeID) String() string { return string(id) }
