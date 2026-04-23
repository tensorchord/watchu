package tls

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/phuslu/log"

	"github.com/tensorchord/watchu/internal/arch"
	"github.com/tensorchord/watchu/internal/tool"
)

func attachSSLProbes(ex *link.Executable, objs *sslObjects, target string) ([]link.Link, error) {
	probes := []struct {
		symbol string
		prog   *ebpf.Program
		inject func(string, *ebpf.Program, *link.UprobeOptions) (link.Link, error)
	}{
		{"SSL_read", objs.ProbeSslReadEntry, ex.Uprobe},
		{"SSL_read", objs.ProbeSslReadExit, ex.Uretprobe},
		{"SSL_read_ex", objs.ProbeSslReadExEntry, ex.Uprobe},
		{"SSL_read_ex", objs.ProbeSslReadExExit, ex.Uretprobe},
		{"SSL_write", objs.ProbeSslReadEntry, ex.Uprobe},
		{"SSL_write", objs.ProbeSslWriteExit, ex.Uretprobe},
		{"SSL_write_ex", objs.ProbeSslReadExEntry, ex.Uprobe},
		{"SSL_write_ex", objs.ProbeSslWriteExExit, ex.Uretprobe},
	}

	failedProbes := 0
	links := []link.Link{}
	for _, probe := range probes {
		up, err := probe.inject(probe.symbol, probe.prog, nil)
		if err != nil {
			log.Warn().Str("target", target).Err(err).Msgf("failed to attach probe %s", probe.symbol)
			failedProbes++
			continue
		}
		links = append(links, up)
	}
	if failedProbes > 0 {
		for _, link := range links {
			_ = link.Close()
		}
		return nil, fmt.Errorf("failed to inject the prog %d/%d", failedProbes, len(probes))
	}
	return links, nil
}

var libSDirs = []string{
	"/lib",
	"/lib64",
	"/usr/lib",
	"/usr/lib64",
	"/usr/local/lib",
	"/usr/local/lib64",
}

func findLibOpenSSLPath() (string, error) {
	for _, path := range arch.LibSSLCandidates {
		if ok, err := tool.IsFilePath(path); err == nil && ok {
			return path, nil
		}
	}

	for _, dir := range libSDirs {
		matches, _ := filepath.Glob(filepath.Join(dir, "libssl.so*"))
		if len(matches) > 0 {
			log.Info().Str("path", matches[0]).Msg("found potential libssl, consider add this to the env")
			for _, path := range matches {
				if ok, err := tool.IsFilePath(path); err == nil && ok {
					return path, nil
				}
			}
		}
	}
	return "", fmt.Errorf("libssl not found, please set the path via args `--ssl-path`")
}

func addSSLProbe(sslPath string) ([]link.Link, *sslObjects, error) {
	sslObjs := sslObjects{}
	if err := loadSslObjects(&sslObjs, nil); err != nil {
		return nil, nil, fmt.Errorf("failed to load/assign eBPF objects: %w", err)
	}

	exec, err := link.OpenExecutable(sslPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open OpenSSL file %s: %w", sslPath, err)
	}
	links, err := attachSSLProbes(exec, &sslObjs, sslPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to inject OpenSSL probes to %s: %w", sslPath, err)
	}

	return links, &sslObjs, nil
}

type OpenSSLProbe struct {
	links []link.Link
	obj   *sslObjects
	rb    *ringbuf.Reader
}

func NewOpenSSLProbe(sslPath string) (*OpenSSLProbe, error) {
	links, obj, err := addSSLProbe(sslPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenSSL probe: %w", err)
	}
	rb, err := ringbuf.NewReader(obj.Events)
	if err != nil {
		return nil, fmt.Errorf("failed to open OpenSSL ringbuf reader: %w", err)
	}
	return &OpenSSLProbe{
		links: links,
		obj:   obj,
		rb:    rb,
	}, nil
}

func (op *OpenSSLProbe) ReadBuffer(record *ringbuf.Record) error {
	return op.rb.ReadInto(record)
}

func (op *OpenSSLProbe) Close() error {
	var final error
	if err := op.obj.Close(); err != nil {
		final = errors.Join(final, fmt.Errorf("failed to close OpenSSL eBPF objects: %w", err))
	}
	if err := op.rb.Close(); err != nil {
		final = errors.Join(final, fmt.Errorf("failed to close OpenSSL ringbuf reader: %w", err))
	}
	for i, l := range op.links {
		if err := l.Close(); err != nil {
			final = errors.Join(final, fmt.Errorf("failed to close %d-OpenSSL link: %w", i, err))
		}
	}
	return final
}
