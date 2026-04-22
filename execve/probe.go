//go:build linux && (amd64 || arm64)

package execve

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/phuslu/log"

	"github.com/tensorchord/watchu/export"
	"github.com/tensorchord/watchu/internal/tool"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64,arm64 exec exec.bpf.c -- -I../headers

const procChannelSize = 4096

const (
	procCmdlinePath = "/proc/%d/cmdline"
	procCWDPath     = "/proc/%d/cwd"
	maxArgsLen      = 2048
)

var (
	nodeName = export.GetHostName()
	bootTime = export.GetBootTime()
)

type DynLib struct {
	Proc     int32
	Fd       uint64
	Filepath string
}

type ExecEvent struct {
	Timestamp time.Time
	Pid       int32
	PPid      int32
	ExecID    string
	PExecID   string
	Cwd       string
	Comm      string
	Filename  string
	Args      string
	ArgsTrunc bool
}

type parsedExecEvent struct {
	proc execProc
	args string
}

func (e *ExecEvent) ToRawExec() *export.RawExec {
	if e == nil {
		return nil
	}
	return &export.RawExec{
		Timestamp: e.Timestamp,
		Pid:       uint32(e.Pid),
		PPid:      uint32(e.PPid),
		ExecId:    e.ExecID,
		PExecId:   e.PExecID,
		Cwd:       e.Cwd,
		Comm:      e.Comm,
		Args:      e.Args,
	}
}

type ProcExecProbe struct {
	rbProc     *ringbuf.Reader
	rbDynLib   *ringbuf.Reader
	objs       *execObjects
	links      []link.Link
	ProcChan   chan int32
	ExecChan   chan *ExecEvent
	DynLibChan chan *DynLib
}

func attachExecProbes(objs execObjects) ([]link.Link, error) {
	probes := []struct {
		group string
		name  string
		prog  *ebpf.Program
	}{
		{"sched", "sched_process_exec", objs.TracepointSchedProcessExec},
		{"syscalls", "sys_enter_openat", objs.TracepointSysEnterOpenat},
		{"syscalls", "sys_enter_openat2", objs.TracepointSysEnterOpenat},
		{"syscalls", "sys_exit_openat", objs.TracepointSysExitOpenat},
		{"syscalls", "sys_exit_openat2", objs.TracepointSysExitOpenat},
		{"syscalls", "sys_enter_close", objs.TracepointSysEnterClose},
		{"syscalls", "sys_enter_mmap", objs.TracepointSysEnterMmap},
	}

	failed := 0
	links := []link.Link{}
	for _, probe := range probes {
		tp, err := link.Tracepoint(probe.group, probe.name, probe.prog, nil)
		if err != nil {
			log.Error().Err(err).Str("group", probe.group).Str("name", probe.name).Msg("failed to attach exec tracepoint")
			failed++
			continue
		}
		links = append(links, tp)
	}
	if failed > 0 {
		for _, link := range links {
			_ = link.Close()
		}
		return nil, fmt.Errorf("failed to attach %d/%d exec tracepoints", failed, len(probes))
	}
	return links, nil
}

func NewProcExecProbe() (*ProcExecProbe, error) {
	objs := &execObjects{}
	if err := loadExecObjects(objs, nil); err != nil {
		log.Error().Err(err).Msg("failed to load eBPF exec spec")
		return nil, err
	}

	links, err := attachExecProbes(*objs)
	if err != nil {
		log.Error().Err(err).Msg("failed to attach exec probes")
		return nil, err
	}

	p := &ProcExecProbe{
		objs:       objs,
		links:      links,
		ProcChan:   make(chan int32, procChannelSize),
		ExecChan:   make(chan *ExecEvent, procChannelSize),
		DynLibChan: make(chan *DynLib, procChannelSize),
	}
	p.rbProc, err = ringbuf.NewReader(objs.ProcEvents)
	if err != nil {
		log.Error().Err(err).Msg("failed to open ringbuf reader for exec")
		p.Close()
		return nil, err
	}
	p.rbDynLib, err = ringbuf.NewReader(objs.DynlibEvents)
	if err != nil {
		log.Error().Err(err).Msg("failed to open ringbuf reader for dynamic library load")
		p.Close()
		return nil, err
	}
	return p, nil
}

func parseElapsedToTimestamp(elapsed uint64) time.Time {
	return bootTime.Add(time.Duration(elapsed))
}

func readProcessCWD(pid int32) string {
	cwd, err := os.Readlink(fmt.Sprintf(procCWDPath, pid))
	if err != nil {
		log.Debug().Err(err).Int32("pid", pid).Msg("failed to read proc cwd")
		return ""
	}
	return cwd
}

func readProcessArgs(pid int32) (string, bool) {
	data, err := os.ReadFile(fmt.Sprintf(procCmdlinePath, pid))
	if err != nil {
		log.Debug().Err(err).Int32("pid", pid).Msg("failed to read proc cmdline")
		return "", false
	}

	parts := strings.FieldsFunc(string(data), func(r rune) bool {
		return r == '\x00'
	})
	if len(parts) == 0 {
		return "", false
	}
	return strings.Join(parts, " "), true
}

func encodeExecID(pid int32, startTimeNs uint64) string {
	// Tetragon emits exec IDs in the shape base64("node-name:start-time-ns:pid").
	// Watchu intentionally reuses export.GetHostName() for the first component,
	// so this matches Watchu host identity, not necessarily Tetragon's exact node naming.
	// Reference implementation:
	// https://github.com/cilium/tetragon/blob/main/pkg/process/process_id_linux.go
	payload := fmt.Sprintf("%s:%d:%d", nodeName, startTimeNs, pid)
	return base64.StdEncoding.EncodeToString([]byte(payload))
}

func buildExecIDs(pid int32, ppid int32, startTimeNs uint64, parentStartTimeNs uint64) (string, string) {
	execID := encodeExecID(pid, startTimeNs)
	parentExecID := encodeExecID(ppid, parentStartTimeNs)
	if ppid <= 0 {
		parentExecID = encodeExecID(0, 0)
	}
	return execID, parentExecID
}

func decodeExecArgsBuffer(raw []byte) string {
	parts := strings.FieldsFunc(string(bytes.TrimRight(raw, "\x00")), func(r rune) bool {
		return r == '\x00'
	})
	return strings.Join(parts, " ")
}

func parseExecRecord(raw []byte) (*parsedExecEvent, error) {
	var header execProc
	headerSize := binary.Size(header)
	if len(raw) < headerSize {
		return nil, fmt.Errorf("short exec proc ringbuf record: got %d want at least %d", len(raw), headerSize)
	}
	if err := binary.Read(bytes.NewReader(raw[:headerSize]), binary.LittleEndian, &header); err != nil {
		return nil, err
	}
	if header.ArgsLen > maxArgsLen {
		return nil, fmt.Errorf("invalid exec args length: %d", header.ArgsLen)
	}
	if len(raw) != headerSize+int(header.ArgsLen) {
		return nil, fmt.Errorf("invalid exec proc ringbuf record size: got %d want %d", len(raw), headerSize+int(header.ArgsLen))
	}
	return &parsedExecEvent{
		proc: header,
		args: decodeExecArgsBuffer(raw[headerSize:]),
	}, nil
}

func buildExecEvent(event *parsedExecEvent) *ExecEvent {
	pid := event.proc.Pid
	filename := tool.CharsToString(event.proc.Filename[:])
	taskComm := tool.CharsToString(event.proc.Comm[:])
	args := event.args
	argsTrunc := event.proc.ArgsTruncated != 0
	if argsTrunc || args == "" {
		if procArgs, ok := readProcessArgs(pid); ok {
			args = procArgs
			argsTrunc = false
		}
	}
	if args == "" {
		args = filename
	}

	comm := filename
	if comm == "" {
		comm = taskComm
	}
	execID, parentExecID := buildExecIDs(pid, event.proc.Ppid, event.proc.StartTimeNs, event.proc.ParentStartTimeNs)

	return &ExecEvent{
		Timestamp: parseElapsedToTimestamp(event.proc.TimestampNs),
		Pid:       pid,
		PPid:      event.proc.Ppid,
		ExecID:    execID,
		PExecID:   parentExecID,
		Cwd:       readProcessCWD(pid),
		Comm:      comm,
		Filename:  filename,
		Args:      args,
		ArgsTrunc: argsTrunc,
	}
}

func (pep *ProcExecProbe) IngestExecEvents(ctx context.Context, exporter *export.Exporter) {
	channel := make(chan *export.RawExec, export.ExportChannelSize)
	go exporter.IngestExecEvent(ctx, channel)
	defer close(channel)

	for {
		select {
		case event, ok := <-pep.ExecChan:
			if !ok {
				return
			}
			raw := event.ToRawExec()
			if raw == nil {
				continue
			}
			select {
			case channel <- raw:
			case <-ctx.Done():
				return
			default:
				log.Warn().Int32("pid", event.Pid).Msg("exec export channel is full, dropping event")
			}
		case <-ctx.Done():
			return
		}
	}
}

func (pep *ProcExecProbe) Start(ctx context.Context) {
	log.Info().Msg("listen to proc exec events...")
	var wg sync.WaitGroup

	wg.Go(func() {
		var record ringbuf.Record
		for {
			if err := pep.rbProc.ReadInto(&record); err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Info().Msg("exec proc ringbuf reader closed")
					return
				}
				log.Warn().Err(err).Msg("failed to read from exec proc ringbuf")
				continue
			}
			event, err := parseExecRecord(record.RawSample)
			if err != nil {
				log.Error().Err(err).Msg("parsing exec proc ringbuf record")
				continue
			}
			if log.Debug().Enabled() {
				log.Debug().
					Int32("pid", event.proc.Pid).
					Int32("ppid", event.proc.Ppid).
					Bool("args_truncated", event.proc.ArgsTruncated != 0).
					Str("comm", tool.CharsToString(event.proc.Comm[:])).
					Str("filepath", tool.CharsToString(event.proc.Filename[:])).
					Str("args", event.args).
					Msg("proc exec event")
			}
			select {
			case pep.ProcChan <- event.proc.Pid:
			case <-ctx.Done():
				return
			default:
				log.Warn().Int32("pid", event.proc.Pid).Msg("failed to push to proc exec channel")
			}
			execEvent := buildExecEvent(event)
			select {
			case pep.ExecChan <- execEvent:
			case <-ctx.Done():
				return
			default:
				log.Warn().Int32("pid", event.proc.Pid).Msg("failed to push to exec event channel")
			}
		}
	})

	wg.Go(func() {
		var event execDynlib
		var record ringbuf.Record
		for {
			if err := pep.rbDynLib.ReadInto(&record); err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Info().Msg("exec dynlib ringbuf reader closed")
					return
				}
				log.Warn().Err(err).Msg("failed to read from exec dynlib ringbuf")
				continue
			}
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Error().Err(err).Msg("parsing exec dynlib ringbuf record")
				continue
			}
			if log.Debug().Enabled() {
				log.Debug().
					Uint64("pid_tgid", event.PidTgid).
					Uint64("fd", event.Fd).
					Str("comm", tool.CharsToString(event.Comm[:])).
					Str("libpath", tool.CharsToString(event.Filename[:])).
					Msg("proc load dynamic library event")
			}
			select {
			case pep.DynLibChan <- &DynLib{
				Proc:     int32(event.PidTgid >> 32),
				Fd:       event.Fd,
				Filepath: tool.CharsToString(event.Filename[:]),
			}:
			case <-ctx.Done():
				return
			default:
				log.Warn().Uint64("pid_tgid", event.PidTgid).Msg("failed to push to exec dynlib channel")
			}
		}
	})
	wg.Wait()
}

func (pep *ProcExecProbe) Close() {
	err := pep.objs.Close()
	if err != nil {
		log.Error().Err(err).Msg("failed to close exec eBPF objects")
	}
	if pep.rbProc != nil {
		err = pep.rbProc.Close()
		if err != nil {
			log.Error().Err(err).Msg("failed to close exec ringbuf proc reader")
		}
	}
	if pep.rbDynLib != nil {
		err = pep.rbDynLib.Close()
		if err != nil {
			log.Error().Err(err).Msg("failed to close exec ringbuf dynlib reader")
		}
	}
	for i, l := range pep.links {
		if err := l.Close(); err != nil {
			log.Error().Int("index", i).Err(err).Msgf("failed to close exec link")
		}
	}
	close(pep.ProcChan)
	close(pep.ExecChan)
	close(pep.DynLibChan)
}
