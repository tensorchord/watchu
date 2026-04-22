//go:build linux && (amd64 || arm64)

package tcpconn

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"net/netip"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/phuslu/log"

	"github.com/tensorchord/watchu/export"
	"github.com/tensorchord/watchu/internal/tool"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64,arm64 tcpconn tcpconn.bpf.c -- -I../headers

const (
	afInet  = 2
	afInet6 = 10
)

type TCPConnProbe struct {
	rb       *ringbuf.Reader
	objs     *tcpconnObjects
	links    []link.Link
	exporter *export.Exporter
}

type event struct {
	TimestampNs uint64
	PidTgid     uint64
	UidGid      uint64
	CgroupId    uint64
	Family      uint16
	Dport       uint16
	Comm        [16]int8
	Daddr       [16]uint8
}

func NewTCPConnProbe(exporter *export.Exporter) (*TCPConnProbe, error) {
	objs := tcpconnObjects{}
	var err error
	if err := loadTcpconnObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load tcpconn objects: %w", err)
	}

	programs := []struct {
		name string
		prog *ebpf.Program
	}{
		{name: "tcp_close", prog: objs.TraceTcpClose},
		{name: "tcp_v4_connect", prog: objs.TraceTcpV4Connect},
		{name: "tcp_v6_connect", prog: objs.TraceTcpV6Connect},
		{name: "tcp_set_state", prog: objs.TraceTcpSetState},
	}
	links := make([]link.Link, 0, len(programs))
	for _, program := range programs {
		l, err := link.AttachTracing(link.TracingOptions{Program: program.prog})
		if err != nil {
			for _, attached := range links {
				_ = attached.Close()
			}
			_ = objs.Close()
			return nil, fmt.Errorf("attach tcpconn tracing program %s: %w", program.name, err)
		}
		links = append(links, l)
	}

	p := &TCPConnProbe{
		objs:     &objs,
		links:    links,
		exporter: exporter,
	}
	p.rb, err = ringbuf.NewReader(objs.Events)
	if err != nil {
		p.Close()
		return nil, fmt.Errorf("open tcpconn ringbuf: %w", err)
	}

	return p, nil
}

func (tp *TCPConnProbe) Start(ctx context.Context) {
	log.Info().Msg("listening for outbound TCP connect events...")

	channel := make(chan *export.RawTCPConnect, export.ExportChannelSize)
	go tp.exporter.IngestTCPConnectEvent(ctx, channel)
	defer close(channel)

	var event event
	var record ringbuf.Record
	for {
		if err := tp.rb.ReadInto(&record); err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Info().Msg("tcpconn ringbuf closed")
				return
			}
			log.Warn().Err(err).Msg("failed to read from tcpconn ringbuf")
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Error().Err(err).Msg("failed to decode tcpconn event")
			continue
		}

		raw := toRawTCPConnect(&event)
		if raw == nil {
			continue
		}

		select {
		case channel <- raw:
		default:
			log.Warn().Msg("tcpconn event channel is full, dropping event")
		}

		if log.Debug().Enabled() {
			log.Debug().
				Uint64("timestamp", event.TimestampNs).
				Uint64("pid_tgid", event.PidTgid).
				Uint64("uid_gid", event.UidGid).
				Uint64("cgroup_id", event.CgroupId).
				Str("comm", raw.Comm).
				Str("target_addr", raw.TargetAddr).
				Uint32("target_port", uint32(raw.TargetPort)).
				Msg("tcp outbound connect event")
		}
	}
}

func toRawTCPConnect(event *event) *export.RawTCPConnect {
	targetAddr, ok := decodeTargetAddr(event.Family, event.Daddr)
	if !ok {
		return nil
	}

	return &export.RawTCPConnect{
		ElapsedNs:  event.TimestampNs,
		PidTGid:    event.PidTgid,
		UidGid:     event.UidGid,
		CgroupID:   event.CgroupId,
		Comm:       tool.CharsToString(event.Comm[:]),
		Family:     event.Family,
		TargetAddr: targetAddr,
		TargetPort: bits.ReverseBytes16(event.Dport),
	}
}

func decodeTargetAddr(family uint16, raw [16]uint8) (string, bool) {
	switch family {
	case afInet:
		var addr [4]byte
		copy(addr[:], raw[:4])
		return netip.AddrFrom4(addr).String(), true
	case afInet6:
		return netip.AddrFrom16(raw).String(), true
	default:
		return "", false
	}
}

func (tp *TCPConnProbe) Close() {
	if tp == nil {
		return
	}
	for i, l := range tp.links {
		if err := l.Close(); err != nil {
			log.Error().Err(err).Int("index", i).Msg("failed to close tcpconn link")
		}
	}
	if tp.rb != nil {
		if err := tp.rb.Close(); err != nil {
			log.Error().Err(err).Msg("failed to close tcpconn ringbuf")
		}
	}
	if tp.objs != nil {
		if err := tp.objs.Close(); err != nil {
			log.Error().Err(err).Msg("failed to close tcpconn objects")
		}
	}
}
