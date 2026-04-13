//go:build amd64 && linux

package tls

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"sync"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/phuslu/log"

	"github.com/tensorchord/watchu/execve"
	"github.com/tensorchord/watchu/export"
	"github.com/tensorchord/watchu/internal/proc"
	"github.com/tensorchord/watchu/internal/tool"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64 ssl ssl.bpf.c -- -I../headers
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64 boring boring.bpf.c -- -I../headers

type TLSPlaintextProbe interface {
	ReadBuffer(*ringbuf.Record) error
	Close() error
}

type TLSProbe struct {
	mu        sync.Mutex // lock the probes
	probes    map[proc.LibKey]TLSPlaintextProbe
	procProbe *execve.ProcExecProbe
	exporter  *export.Exporter
}

func NewTLSProbe(procProbe *execve.ProcExecProbe, sslPath *string, exporter *export.Exporter) *TLSProbe {
	probes := make(map[proc.LibKey]TLSPlaintextProbe)

	// OpenSSL
	libsslPaths := []string{}
	commonLibsslPath, err := findLibOpenSSLPath()
	if err != nil {
		log.Warn().Err(err).Msg("failed to detect the common libssl paths")
	} else {
		libsslPaths = append(libsslPaths, commonLibsslPath)
	}
	if sslPath != nil && len(*sslPath) > 0 {
		if ok, err := tool.IsFilePath(*sslPath); err != nil || !ok {
			log.Panic().Str("path", *sslPath).Err(err).Msg("invalid SSL library path")
		}
		libsslPaths = append(libsslPaths, *sslPath)
	}
	for i, path := range libsslPaths {
		key, err := proc.FindLibKey(path)
		if err != nil {
			log.Error().Err(err).Str("path", path).Msg("failed to find lib key")
			continue
		}
		if _, exist := probes[*key]; exist {
			continue
		}
		probe, err := NewOpenSSLProbe(path)
		if err != nil {
			log.Error().Err(err).Str("path", path).Msg("failed to create OpenSSL probe")
			continue
		}
		if probe != nil {
			log.Info().Any("key", key).Int("index", i).Str("path", path).Msg("attached OpenSSL library")
			probes[*key] = probe
		}
	}

	return &TLSProbe{
		probes:    probes,
		procProbe: procProbe,
		exporter:  exporter,
	}
}

func handle(key *proc.LibKey, probe TLSPlaintextProbe, store *SSLStore) {
	logger := log.DefaultLogger
	logger.Context = log.NewContext(nil).Uint64("inode", key.INode).Uint64("device", key.DeviceID).Value()
	var event sslEvent
	var record ringbuf.Record

	for {
		if err := probe.ReadBuffer(&record); err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				logger.Info().Msg("SSL ringbuf closed")
				return
			}
			logger.Warn().Err(err).Msg("read from ringbuffer error")
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			logger.Error().Err(err).Msg("parsing ssl ringbuf record")
			continue
		}

		store.Add(&event)
		if logger.Debug().Enabled() {
			data := event.Data[:event.DataLen]
			logger.Debug().
				Uint64("timestamp", event.TimestampNs).
				Uint64("req_len", event.ReqLen).
				Uint64("pid_tgid", event.PidTgid).
				Uint64("uid_gid", event.UidGid).
				Uint64("cgroup_id", event.CgroupId).
				Uint64("*SSL", event.SslPtr).
				Uint64("data_len", event.DataLen).
				Uint8("rw", event.Rw).
				Str("comm", tool.CharsToString(event.Comm[:])).
				Bytes("data", data).
				Msg("TLS event")
		}
	}
}

func (sp *TLSProbe) Start(ctx context.Context) {
	log.Info().Msg("listening for SSL read/write events...")
	reqChan := make(chan *export.RawRequest, export.ExportChannelSize)
	respChan := make(chan *export.RawResponse, export.ExportChannelSize)
	postgresChan := make(chan *export.RawPostgres, export.ExportChannelSize)
	defer func() {
		close(reqChan)
		close(respChan)
		close(postgresChan)
	}()

	go sp.exporter.IngestRequestEvent(ctx, reqChan)
	go sp.exporter.IngestResponseEvent(ctx, respChan)
	go sp.exporter.IngestPostgresEvent(ctx, postgresChan)
	store := NewSSLStore()
	go store.Parse(ctx, reqChan, respChan, postgresChan)

	var wg sync.WaitGroup
	for key, probe := range sp.probes {
		// avoid loopvar bug before go 1.22 https://go.dev/blog/loopvar-preview
		k, p := key, probe
		wg.Go(func() { handle(&k, p, store) })
	}

	// dynamic probe
	procChan := sp.procProbe.ProcChan
	dynLibChan := sp.procProbe.DynLibChan
Loop:
	for {
		var libs []proc.ProcTLSLib
		var err error
		select {
		case pid, ok := <-procChan:
			if !ok {
				procChan = nil
				continue Loop
			}
			libs, err = proc.DetectTLSLibType(pid)
			if err != nil {
				log.Debug().Err(err).Int32("pid", pid).Msg("failed to detect TLS library type for the process")
				continue Loop
			}
		case dynLib, ok := <-dynLibChan:
			if !ok {
				dynLibChan = nil
				continue Loop
			}
			libs, err = proc.DetectDynTLSLib(dynLib)
			if err != nil {
				log.Debug().Err(err).Int32("pid", dynLib.Proc).Msg("failed to detect TLS library type from dynamic library load event")
				continue Loop
			}
		case <-ctx.Done():
			break Loop
		}
		for _, lib := range libs {
			key, err := proc.FindLibKey(lib.Path)
			if err != nil {
				log.Error().Err(err).Str("path", lib.Path).Msg("failed to find lib key for dynamic probe")
				continue
			}
			// there is no Time-of-Check to Time-of-Use (TOCTOU) here
			sp.mu.Lock()
			_, exist := sp.probes[*key]
			sp.mu.Unlock()
			if exist {
				continue
			}

			var typeStr string
			var probe TLSPlaintextProbe
			switch lib.Type {
			case proc.TLSLibOpenSSL:
				probe, err = NewOpenSSLProbe(lib.Path)
				typeStr = "OpenSSL"
			case proc.TLSLibBoringSSL:
				probe, err = NewBoringSSLProbe(lib.Path)
				typeStr = "BoringSSL"
			}
			if err != nil {
				log.Error().Err(err).Str("path", lib.Path).Str("type", typeStr).Msg("failed to create TLS probe")
				continue
			}
			log.Debug().Str("lib_path", lib.Path).Str("type", typeStr).Msg("detected TLS library")
			sp.mu.Lock()
			index := len(sp.probes)
			wg.Go(func() { handle(key, probe, store) })
			sp.probes[*key] = probe
			sp.mu.Unlock()
			log.Info().Int("index", index).Str("path", lib.Path).Str("type", typeStr).Uint64("device", key.DeviceID).Uint64("inode", key.INode).Msg("attached dynamic TLS library")
		}
	}

	wg.Wait()
	log.Info().Msg("SSLProbe closed")
}

func (sp *TLSProbe) Close() {
	sp.mu.Lock()
	for key, probe := range sp.probes {
		if err := probe.Close(); err != nil {
			log.Error().Err(err).Any("key", key).Msg("failed to close TLS probe")
		}
		log.Info().Any("key", key).Msg("SSL probe closed successfully")
	}
	sp.mu.Unlock()
}
