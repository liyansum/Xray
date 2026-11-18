package proxy

import (
	"encoding/binary"

	"github.com/xtls/xray-core/common/buf"
)

const visionTLSProbeLimit = 128 * 1024

type visionTLSStatus struct {
	isTLS       bool
	enableXtls  bool
	stopPadding bool
	done        bool
}

// Each direction owns its record/handshake framing. Only the negotiated TLS
// properties are shared. The mutex never covers a network read or write.
type visionTLSParser struct {
	header             [5]byte
	headerUsed         int
	remaining          int
	invalid            bool
	probed             int
	handshake          [4]byte
	handshakeUsed      int
	handshakeRemaining int
	serverHello        []byte
}

func (s *TrafficState) filterTLS(mb buf.MultiBuffer, uplink bool) (visionTLSStatus, int32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := &s.tls[0]
	if !uplink {
		p = &s.tls[1]
	}
	var boundary int32 = -1
	if !s.DisableDirectCopy {
		var offset int32
		for _, b := range mb {
			if b == nil {
				continue
			}
			if end := p.feed(b.Bytes(), s); end >= 0 {
				boundary = offset + int32(end)
				break
			}
			offset += b.Len()
		}
	}
	return visionTLSStatus{
		isTLS: s.IsTLS, enableXtls: s.EnableXtls && !s.DisableDirectCopy,
		stopPadding: s.DisableDirectCopy || p.invalid,
		done:        s.tlsNegotiated || s.DisableDirectCopy || p.invalid,
	}, boundary
}

// feed returns the end of the first complete Application Data record, even if
// its header/body began in an earlier call. Ciphertext is skipped, never copied
// or searched for apparent record headers.
func (p *visionTLSParser) feed(data []byte, s *TrafficState) int {
	if p.invalid {
		return -1
	}
	pos := 0
	for pos < len(data) {
		if !s.tlsNegotiated {
			if p.probed >= visionTLSProbeLimit {
				p.invalid = true
				p.serverHello = nil
				return -1
			}
		}
		if p.headerUsed < len(p.header) {
			n := copy(p.header[p.headerUsed:], data[pos:])
			p.headerUsed += n
			pos += n
			p.probed += n
			if p.header[0] < 20 || p.header[0] > 23 || (p.headerUsed >= 2 && p.header[1] != 3) || (p.headerUsed >= 3 && (p.header[2] < 1 || p.header[2] > 3)) {
				p.invalid = true
				p.serverHello = nil
				return -1
			}
			if p.headerUsed < len(p.header) {
				break
			}
			p.remaining = int(binary.BigEndian.Uint16(p.header[3:]))
			if p.remaining > 16384+2048 || (p.header[0] == 23 && s.EnableXtls && (p.remaining < 17 || p.remaining > 16384+256)) {
				p.invalid = true
				p.serverHello = nil
				return -1
			}
		}
		n := min(p.remaining, len(data)-pos)
		if p.header[0] == 22 && !s.tlsNegotiated {
			p.feedHandshake(data[pos:pos+n], s)
		}
		pos += n
		p.probed += n
		p.remaining -= n
		if p.invalid {
			p.serverHello = nil
			return -1
		}
		if p.remaining > 0 {
			break
		}
		kind := p.header[0]
		p.headerUsed = 0
		if kind == 23 && s.IsTLS {
			return pos
		}
	}
	return -1
}

func (p *visionTLSParser) feedHandshake(data []byte, s *TrafficState) {
	for len(data) > 0 && !s.tlsNegotiated && !p.invalid {
		if p.handshakeUsed < len(p.handshake) {
			n := copy(p.handshake[p.handshakeUsed:], data)
			p.handshakeUsed += n
			data = data[n:]
			if p.handshakeUsed < len(p.handshake) {
				return
			}
			p.handshakeRemaining = int(p.handshake[1])<<16 | int(p.handshake[2])<<8 | int(p.handshake[3])
			if p.handshake[0] != 1 && p.handshake[0] != 2 {
				p.invalid = true
				return
			}
			if p.handshakeRemaining > visionTLSProbeLimit {
				p.invalid = true
				return
			}
			s.IsTLS = true
			if p.handshake[0] == 2 {
				p.serverHello = make([]byte, 0, p.handshakeRemaining)
			}
		}
		n := min(p.handshakeRemaining, len(data))
		if p.handshake[0] == 2 {
			p.serverHello = append(p.serverHello, data[:n]...)
		}
		data = data[n:]
		p.handshakeRemaining -= n
		if p.handshakeRemaining != 0 {
			return
		}
		if p.handshake[0] == 2 {
			p.parseServerHello(s)
			p.serverHello = nil
		}
		p.handshakeUsed = 0
	}
}

func (p *visionTLSParser) parseServerHello(s *TrafficState) {
	b := p.serverHello
	if len(b) < 38 || b[0] != 3 || b[1] != 3 {
		p.invalid = true
		return
	}
	sid := int(b[34])
	if sid > 32 || len(b) < 38+sid {
		p.invalid = true
		return
	}
	cipher := binary.BigEndian.Uint16(b[35+sid:])
	if b[37+sid] != 0 {
		p.invalid = true
		return
	}
	pos := 38 + sid
	tls13 := false
	if len(b) != pos {
		if len(b) < pos+2 {
			p.invalid = true
			return
		}
		extLen := int(binary.BigEndian.Uint16(b[pos:]))
		pos += 2
		if extLen != len(b)-pos {
			p.invalid = true
			return
		}
		seenVersions := false
		for pos < len(b) {
			if len(b)-pos < 4 {
				p.invalid = true
				return
			}
			typ := binary.BigEndian.Uint16(b[pos:])
			n := int(binary.BigEndian.Uint16(b[pos+2:]))
			pos += 4
			if n > len(b)-pos {
				p.invalid = true
				return
			}
			if typ == 43 {
				if seenVersions || n != 2 {
					p.invalid = true
					return
				}
				seenVersions = true
				tls13 = b[pos] == 3 && b[pos+1] == 4
			}
			pos += n
		}
	}
	s.IsTLS12orAbove = true
	s.Cipher = cipher
	s.EnableXtls = tls13 && cipher >= 0x1301 && cipher <= 0x1304
	s.NumberOfPacketToFilter = 0
	s.tlsNegotiated = true
}
