//go:build amd64 && linux

package fileop

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

	"github.com/tensorchord/watchu/export"
	"github.com/tensorchord/watchu/internal/tool"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64 fileop fileop.bpf.c -- -I../headers

const (
	fileOpOpen = iota + 1
	fileOpWrite
	fileOpDelete
	fileOpRename
	fileOpMmapRead
	fileOpMmapWrite
)

const (
	openAccMode = 0x3
	openRdOnly  = 0x0
	openWrOnly  = 0x1
	openRdWr    = 0x2
	openAppend  = 0x400
	openCreate  = 0x40
	openTrunc   = 0x200
)

type FileOpProbe struct {
	rb       *ringbuf.Reader
	objs     *fileopObjects
	links    []link.Link
	exporter *export.Exporter
	policy   *Policy
}

func NewFileOpProbe(exporter *export.Exporter, policy *Policy) (*FileOpProbe, error) {
	objs := fileopObjects{}
	if err := loadFileopObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load fileop objects: %w", err)
	}

	links, err := attachFileOpProbes(objs)
	if err != nil {
		_ = objs.Close()
		return nil, err
	}

	probe := &FileOpProbe{
		objs:     &objs,
		links:    links,
		exporter: exporter,
		policy:   policy,
	}

	probe.rb, err = ringbuf.NewReader(objs.Events)
	if err != nil {
		probe.Close()
		return nil, fmt.Errorf("open fileop ringbuf: %w", err)
	}

	return probe, nil
}

func attachFileOpProbes(objs fileopObjects) ([]link.Link, error) {
	probes := []struct {
		group string
		name  string
		prog  *ebpf.Program
	}{
		{group: "syscalls", name: "sys_enter_open", prog: objs.TraceEnterOpen},
		{group: "syscalls", name: "sys_enter_openat", prog: objs.TraceEnterOpenat},
		{group: "syscalls", name: "sys_enter_openat2", prog: objs.TraceEnterOpenat2},
		{group: "syscalls", name: "sys_exit_open", prog: objs.TraceExitOpen},
		{group: "syscalls", name: "sys_exit_openat", prog: objs.TraceExitOpenat},
		{group: "syscalls", name: "sys_exit_openat2", prog: objs.TraceExitOpenat2},
		{group: "syscalls", name: "sys_enter_write", prog: objs.TraceWrite},
		{group: "syscalls", name: "sys_exit_write", prog: objs.TraceExitWrite},
		{group: "syscalls", name: "sys_enter_mmap", prog: objs.TraceMmap},
		{group: "syscalls", name: "sys_enter_close", prog: objs.TraceClose},
		{group: "syscalls", name: "sys_enter_unlinkat", prog: objs.TraceDelete},
		{group: "syscalls", name: "sys_enter_rename", prog: objs.TraceRename},
		{group: "syscalls", name: "sys_enter_renameat", prog: objs.TraceRenameat},
		{group: "syscalls", name: "sys_enter_renameat2", prog: objs.TraceRenameat2},
	}

	links := make([]link.Link, 0, len(probes))
	for _, probe := range probes {
		l, err := link.Tracepoint(probe.group, probe.name, probe.prog, nil)
		if err != nil {
			for _, attached := range links {
				_ = attached.Close()
			}
			return nil, fmt.Errorf("attach fileop probe %s/%s: %w", probe.group, probe.name, err)
		}
		links = append(links, l)
	}
	return links, nil
}

func (fp *FileOpProbe) Start(ctx context.Context) {
	log.Info().Msg("listening for file operation events...")

	channel := make(chan *export.RawFileOp, export.ExportChannelSize)
	go fp.exporter.IngestFileOpEvent(ctx, channel)
	defer close(channel)

	var event fileopEvent
	var record ringbuf.Record
	for {
		if err := fp.rb.ReadInto(&record); err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Info().Msg("fileop ringbuf closed")
				return
			}
			log.Warn().Err(err).Msg("failed to read from fileop ringbuf")
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Error().Err(err).Msg("failed to decode fileop event")
			continue
		}

		raw := toRawFileOp(&event)
		if raw == nil || !fp.policy.Matches(raw) {
			continue
		}

		select {
		case channel <- raw:
		default:
			log.Warn().Msg("fileop event channel is full, dropping event")
		}

		if log.Debug().Enabled() {
			logger := log.Debug().
				Uint64("timestamp", event.TimestampNs).
				Uint64("pid_tgid", event.PidTgid).
				Uint64("uid_gid", event.UidGid).
				Uint64("cgroup_id", event.CgroupId).
				Str("comm", tool.CharsToString(event.Comm[:])).
				Str("op", raw.Op).
				Str("path", raw.Path).
				Str("new_path", raw.NewPath).
				Uint64("bytes", event.Bytes)
			if raw.Access != "" {
				logger = logger.Str("access", raw.Access)
			}
			if raw.Flags != 0 {
				logger = logger.Uint64("flags", raw.Flags)
			}
			logger.Msg("file operation event")
		}
	}
}

func toRawFileOp(event *fileopEvent) *export.RawFileOp {
	path := tool.CharsToString(event.Path[:])
	if path == "" {
		return nil
	}

	raw := &export.RawFileOp{
		ElapsedNs: event.TimestampNs,
		PidTGid:   event.PidTgid,
		UidGid:    event.UidGid,
		CgroupID:  event.CgroupId,
		Comm:      tool.CharsToString(event.Comm[:]),
		Path:      path,
		NewPath:   tool.CharsToString(event.NewPath[:]),
		Bytes:     event.Bytes,
		Flags:     event.Flags,
	}

	switch event.Op {
	case fileOpOpen:
		raw.Op = "open"
		raw.Access = decodeOpenAccess(event.Flags)
		raw.Create = event.Flags&openCreate != 0
		raw.Truncate = event.Flags&openTrunc != 0
		raw.Append = event.Flags&openAppend != 0
	case fileOpWrite:
		raw.Op = "write"
	case fileOpDelete:
		raw.Op = "delete"
	case fileOpRename:
		raw.Op = "rename"
	case fileOpMmapRead:
		raw.Op = "mmap_read"
	case fileOpMmapWrite:
		raw.Op = "mmap_write"
	default:
		return nil
	}

	return raw
}

func decodeOpenAccess(flags uint64) string {
	switch flags & openAccMode {
	case openRdOnly:
		return "read"
	case openWrOnly:
		return "write"
	case openRdWr:
		return "read_write"
	default:
		return ""
	}
}

func (fp *FileOpProbe) Close() {
	if fp == nil {
		return
	}
	if fp.objs != nil {
		if err := fp.objs.Close(); err != nil {
			log.Error().Err(err).Msg("failed to close fileop objects")
		}
	}
	if fp.rb != nil {
		if err := fp.rb.Close(); err != nil {
			log.Error().Err(err).Msg("failed to close fileop ringbuf")
		}
	}
	for i, l := range fp.links {
		if err := l.Close(); err != nil {
			log.Error().Err(err).Int("index", i).Msg("failed to close fileop link")
		}
	}
}
