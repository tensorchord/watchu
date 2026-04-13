//go:build amd64 && linux

package stdio

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/phuslu/log"
	"github.com/tidwall/gjson"

	"github.com/tensorchord/watchu/export"
	"github.com/tensorchord/watchu/internal/tool"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64 stdio stdio.bpf.c -- -I../headers

const (
	stdioRead  = 4
	stdioWrite = 2
)

type MCPRequest struct {
	JSONRPC string         `json:"jsonrpc"`
	Method  string         `json:"method"`
	Params  map[string]any `json:"params"`
	ID      int            `json:"id"`
}

type MCPResponse struct {
	JSONRPC string         `json:"jsonrpc"`
	Result  map[string]any `json:"result"`
	ID      int            `json:"id"`
}

func isValidMCPMessage(event *stdioEvent) bool {
	if !gjson.GetBytes(event.Data[:event.DataLen], "jsonrpc").Exists() {
		return false
	}
	switch event.Rw {
	case stdioRead:
		return gjson.GetBytes(event.Data[:event.DataLen], "method").Exists()
	case stdioWrite:
		return gjson.GetBytes(event.Data[:event.DataLen], "result").Exists()
	default:
		log.Error().Uint8("rw", event.Rw).Msg("unknown RW type")
		return false
	}
}

func attachStdioProbes(objs stdioObjects) ([]link.Link, error) {
	probes := []struct {
		group string
		name  string
		prog  *ebpf.Program
	}{
		{"syscalls", "sys_enter_read", objs.TracepointEnterRead},
		{"syscalls", "sys_exit_read", objs.TracepointExitRead},
		{"syscalls", "sys_enter_write", objs.TracepointEnterWrite},
	}

	failed := 0
	links := []link.Link{}
	for _, probe := range probes {
		tp, err := link.Tracepoint(probe.group, probe.name, probe.prog, nil)
		if err != nil {
			log.Error().Err(err).Str("group", probe.group).Str("name", probe.name).Msg("failed to attach stdio tracepoint")
			failed++
			continue
		}
		links = append(links, tp)
	}
	if failed > 0 {
		for _, link := range links {
			_ = link.Close()
		}
		return nil, fmt.Errorf("failed to attach %d/%d stdio tracepoints", failed, len(probes))
	}
	return links, nil
}

type StdioProbe struct {
	rb       *ringbuf.Reader
	objs     *stdioObjects
	links    []link.Link
	exporter *export.Exporter
}

func NewStdioProbe(exporter *export.Exporter) (*StdioProbe, error) {
	objs := stdioObjects{}
	if err := loadStdioObjects(&objs, nil); err != nil {
		log.Error().Err(err).Msg("failed to load eBPF stdio spec")
		return nil, err
	}

	links, err := attachStdioProbes(objs)
	if err != nil {
		log.Error().Err(err).Msg("failed to attach stdio probes")
		return nil, err
	}

	p := &StdioProbe{
		objs:     &objs,
		links:    links,
		exporter: exporter,
	}

	p.rb, err = ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Error().Err(err).Msg("failed to open ringbuf reader for stdio")
		p.Close()
		return nil, err
	}

	return p, nil
}

func (sp *StdioProbe) Start(ctx context.Context) {
	log.Info().Msg("listening for stdio events...")
	channel := make(chan *export.RawStdIO, export.ExportChannelSize)
	go sp.exporter.IngestStdIOEvent(ctx, channel)
	defer close(channel)

	var event stdioEvent
	var record ringbuf.Record
	for {
		if err := sp.rb.ReadInto(&record); err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Info().Msg("stdio ringbuf closed")
				return
			}
			log.Warn().Err(err).Msg("failed to read from stdio ringbuf")
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Error().Err(err).Msg("parsing stdio ringbuf record")
			continue
		}

		if !isValidMCPMessage(&event) {
			continue
		}

		var msgType string
		switch event.Rw {
		case stdioRead:
			msgType = "request"
		case stdioWrite:
			msgType = "response"
		}
		select {
		case channel <- &export.RawStdIO{
			ElapsedNs:   event.TimestampNs,
			PidTGid:     event.PidTgid,
			UidGid:      event.UidGid,
			CgroupID:    event.CgroupId,
			MessageType: msgType,
			Data:        bytes.Clone(event.Data[:event.DataLen]),
		}:
		default:
			log.Warn().Msg("stdio channel is full, dropping event")
		}
		if log.Debug().Enabled() {
			log.Debug().
				Uint64("timestamp", event.TimestampNs).
				Uint64("pid_tgid", event.PidTgid).
				Uint64("uid_gid", event.UidGid).
				Uint64("cgroup_id", event.CgroupId).
				Uint64("fd", event.Fd).
				Uint64("req_len", event.ReqLen).
				Uint64("data_len", event.DataLen).
				Uint8("rw", event.Rw).
				Str("comm", tool.CharsToString(event.Comm[:])).
				Bytes("data", event.Data[:event.DataLen]).
				Msg("stdio event")
		}
	}
}

func (sp *StdioProbe) Close() {
	err := sp.objs.Close()
	if err != nil {
		log.Error().Err(err).Msg("failed to close stdio objects")
	}
	if sp.rb != nil {
		err = sp.rb.Close()
		if err != nil {
			log.Error().Err(err).Msg("failed to close stdio ringbuf reader")
		}
	}
	for i, l := range sp.links {
		err = l.Close()
		if err != nil {
			log.Error().Err(err).Int("index", i).Msg("failed to close stdio link")
		}
	}
}
