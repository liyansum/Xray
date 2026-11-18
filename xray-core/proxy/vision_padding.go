package proxy

import (
	"bytes"
	"encoding/binary"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
)

type visionUnpadding struct {
	uuidRead   int
	header     [5]byte
	headerRead int
	content    int32
	padding    int32
	command    byte
	done       bool
}

func xtlsUnpadding(b *buf.Buffer, s *TrafficState, uplink bool) (*buf.Buffer, error) {
	d := &s.Inbound.padding
	remainingCommand, remainingContent, remainingPadding, currentCommand := &s.Inbound.RemainingCommand, &s.Inbound.RemainingContent, &s.Inbound.RemainingPadding, &s.Inbound.CurrentCommand
	if !uplink {
		d = &s.Outbound.padding
		remainingCommand, remainingContent, remainingPadding, currentCommand = &s.Outbound.RemainingCommand, &s.Outbound.RemainingContent, &s.Outbound.RemainingPadding, &s.Outbound.CurrentCommand
	}
	if d.done {
		return b, nil
	}
	defer b.Release()
	var out *buf.Buffer
	if b.Len() <= buf.Size {
		out = buf.New()
	} else {
		out = buf.NewWithSize(b.Len())
	}
	data := b.Bytes()
	for len(data) > 0 {
		if d.uuidRead < len(s.UserUUID) {
			n := min(len(s.UserUUID)-d.uuidRead, len(data))
			if !bytes.Equal(data[:n], s.UserUUID[d.uuidRead:d.uuidRead+n]) {
				out.Release()
				return nil, errors.New("invalid Vision padding UUID")
			}
			d.uuidRead += n
			data = data[n:]
			if d.uuidRead < len(s.UserUUID) {
				break
			}
		}
		if d.headerRead < 5 {
			n := copy(d.header[d.headerRead:], data)
			d.headerRead += n
			data = data[n:]
			if d.headerRead < 5 {
				break
			}
			d.command = d.header[0]
			if d.command > CommandPaddingDirect {
				out.Release()
				return nil, errors.New("invalid Vision padding command")
			}
			d.content = int32(binary.BigEndian.Uint16(d.header[1:3]))
			d.padding = int32(binary.BigEndian.Uint16(d.header[3:5]))
		}
		if d.content > 0 {
			n := min(int(d.content), len(data))
			_, _ = out.Write(data[:n])
			data = data[n:]
			d.content -= int32(n)
			if d.content > 0 {
				break
			}
		}
		if d.padding > 0 {
			n := min(int(d.padding), len(data))
			data = data[n:]
			d.padding -= int32(n)
			if d.padding > 0 {
				break
			}
		}
		if d.command == CommandPaddingContinue {
			d.headerRead = 0
			continue
		}
		d.done = true
		_, _ = out.Write(data)
		break
	}
	*currentCommand = int(d.command)
	*remainingCommand = int32(5 - d.headerRead)
	*remainingContent, *remainingPadding = d.content, d.padding
	if d.done {
		*remainingCommand, *remainingContent, *remainingPadding = -1, -1, -1
	}
	return out, nil
}
