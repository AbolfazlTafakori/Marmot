package session

import (
	"crypto/ed25519"
	"fmt"

	"marmot/internal/core"
	"marmot/internal/crypto"
)

// PeerKeys maps the pinned keys of configured peers to their ids. It is
// immutable; a reload builds a new one.
type PeerKeys struct {
	byX  map[[32]byte]ed25519.PublicKey
	byID map[core.NodeID]ed25519.PublicKey
	ids  map[string]core.NodeID // keyed by string(ed25519 public key)
}

// NewPeerKeys builds the directory. Two peers may not share a key.
func NewPeerKeys(peers map[core.NodeID]ed25519.PublicKey) (*PeerKeys, error) {
	k := &PeerKeys{
		byX:  make(map[[32]byte]ed25519.PublicKey, len(peers)),
		byID: make(map[core.NodeID]ed25519.PublicKey, len(peers)),
		ids:  make(map[string]core.NodeID, len(peers)),
	}
	for id, pub := range peers {
		x, err := crypto.X25519PublicFromEd25519(pub)
		if err != nil {
			return nil, fmt.Errorf("peer %s: %w", id, err)
		}
		if prev, dup := k.ids[string(pub)]; dup {
			return nil, fmt.Errorf("peers %s and %s share a public key", prev, id)
		}
		k.byX[[32]byte(x)] = pub
		k.byID[id] = pub
		k.ids[string(pub)] = id
	}
	return k, nil
}

func (k *PeerKeys) lookupX25519(x []byte) (ed25519.PublicKey, bool) {
	if len(x) != 32 {
		return nil, false
	}
	pub, ok := k.byX[[32]byte(x)]
	return pub, ok
}

// IDOf returns the peer id pinned to pub.
func (k *PeerKeys) IDOf(pub ed25519.PublicKey) (core.NodeID, bool) {
	id, ok := k.ids[string(pub)]
	return id, ok
}

// KeyOf returns the key pinned for peer id.
func (k *PeerKeys) KeyOf(id core.NodeID) (ed25519.PublicKey, bool) {
	pub, ok := k.byID[id]
	return pub, ok
}
