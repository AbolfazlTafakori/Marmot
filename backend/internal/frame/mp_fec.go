package frame

import "encoding/binary"

// FECSource is the header of a PKT_FEC body (spec §11.2): a packet that is
// also a source symbol of FEC group Group.
type FECSource struct {
	PN    uint64
	Group uint32
	Index uint8
}

// fecSourceHeader is the size of a PKT_FEC header.
const fecSourceHeader = 8 + 4 + 1

// Append starts a PKT_FEC body.
func (h FECSource) Append(b []byte) []byte {
	b = binary.BigEndian.AppendUint64(b, h.PN)
	b = binary.BigEndian.AppendUint32(b, h.Group)
	return append(b, h.Index)
}

// ParseFECSource splits a PKT_FEC body into its header and frames.
func ParseFECSource(body []byte) (FECSource, []byte, error) {
	if len(body) < fecSourceHeader {
		return FECSource{}, nil, ErrShortBody
	}
	return FECSource{
		PN:    binary.BigEndian.Uint64(body),
		Group: binary.BigEndian.Uint32(body[8:]),
		Index: body[12],
	}, body[fecSourceHeader:], nil
}

// FECRepair is the header of a REPAIR body; the parity shard follows.
type FECRepair struct {
	PN    uint64
	Group uint32
	K, M  uint8
	Index uint8 // K..K+M-1
}

// FECRepairHeader is the size of a REPAIR header.
const FECRepairHeader = 8 + 4 + 3

// Append starts a REPAIR body.
func (h FECRepair) Append(b []byte) []byte {
	b = binary.BigEndian.AppendUint64(b, h.PN)
	b = binary.BigEndian.AppendUint32(b, h.Group)
	return append(b, h.K, h.M, h.Index)
}

// ParseFECRepair splits a REPAIR body into its header and parity shard.
func ParseFECRepair(body []byte) (FECRepair, []byte, error) {
	if len(body) <= FECRepairHeader {
		return FECRepair{}, nil, ErrShortBody
	}
	h := FECRepair{
		PN:    binary.BigEndian.Uint64(body),
		Group: binary.BigEndian.Uint32(body[8:]),
		K:     body[12], M: body[13], Index: body[14],
	}
	if h.K == 0 || h.M == 0 || h.Index < h.K || int(h.Index) >= int(h.K)+int(h.M) {
		return FECRepair{}, nil, ErrBadFrame
	}
	return h, body[FECRepairHeader:], nil
}

// FECSymbolHeader is the size of the header of a source symbol:
// path_id:u64 | pn:u64 | len:u16 (spec §11.5).
const FECSymbolHeader = 8 + 8 + 2

// AppendFECSymbol appends the source symbol of a packet, unpadded.
func AppendFECSymbol(b []byte, pathID, pn uint64, frames []byte) []byte {
	b = binary.BigEndian.AppendUint64(b, pathID)
	b = binary.BigEndian.AppendUint64(b, pn)
	b = binary.BigEndian.AppendUint16(b, uint16(len(frames)))
	return append(b, frames...)
}

// ParseFECSymbol decodes a (possibly padded) source symbol.
func ParseFECSymbol(sym []byte) (pathID, pn uint64, frames []byte, err error) {
	if len(sym) < FECSymbolHeader {
		return 0, 0, nil, ErrShortBody
	}
	n := int(binary.BigEndian.Uint16(sym[16:]))
	if FECSymbolHeader+n > len(sym) {
		return 0, 0, nil, ErrShortBody
	}
	return binary.BigEndian.Uint64(sym), binary.BigEndian.Uint64(sym[8:]), sym[FECSymbolHeader : FECSymbolHeader+n], nil
}
