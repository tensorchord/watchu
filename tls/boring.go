package tls

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/phuslu/log"
	"golang.org/x/sys/unix"
)

var (
	// The current bun BoringSSL SSL_read/SSL_write function bytes.
	// This may change in the future if bun updates the BoringSSL code.
	BoringSSLReadPattern = []byte{
		0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56,
		0x53, 0x50, 0x48, 0x83, 0xbf, 0x98, 0x00, 0x00,
	}
	BoringSSLWritePattern = []byte{
		0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56,
		0x41, 0x55, 0x41, 0x54, 0x53, 0x48, 0x83, 0xec,
		0x18, 0x41, 0x89, 0xd7, 0x49, 0x89, 0xf6, 0x48,
		0x89, 0xfb, 0x48, 0x8b, 0x47, 0x30, 0xc7, 0x80,
	}

	// errors
	errUprobeNotFound = errors.New("cannot find the pattern")
)

type BoringSSLProbe struct {
	links []link.Link
	obj   *boringObjects
	rb    *ringbuf.Reader
}

func NewBoringSSLProbe(path string) (*BoringSSLProbe, error) {
	links, obj, err := addBoringProbe(path)
	if err != nil {
		return nil, fmt.Errorf("failed to create BoringSSL probe: %w", err)
	}
	p := &BoringSSLProbe{
		links: links,
		obj:   obj,
	}
	p.rb, err = ringbuf.NewReader(obj.Events)
	if err != nil {
		p.Close()
		return nil, fmt.Errorf("failed to open BoringSSL ringbuf reader: %w", err)
	}
	return p, nil
}

func (bp *BoringSSLProbe) ReadBuffer(record *ringbuf.Record) error {
	return bp.rb.ReadInto(record)
}

func (bp *BoringSSLProbe) Close() error {
	var final error
	if err := bp.obj.Close(); err != nil {
		final = errors.Join(final, fmt.Errorf("failed to close BoringSSL eBPF objects: %w", err))
	}
	if bp.rb != nil {
		if err := bp.rb.Close(); err != nil {
			final = errors.Join(final, fmt.Errorf("failed to close BoringSSL ringbuf reader: %w", err))
		}
	}
	for i, l := range bp.links {
		if err := l.Close(); err != nil {
			final = errors.Join(final, fmt.Errorf("failed to close %d-BoringSSL link: %w", i, err))
		}
	}
	return final
}

func addBoringProbe(path string) ([]link.Link, *boringObjects, error) {
	objs := boringObjects{}
	if err := loadBoringObjects(&objs, nil); err != nil {
		return nil, nil, fmt.Errorf("failed to load/assign eBPF BoringSSL objects: %w", err)
	}
	exec, err := link.OpenExecutable(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open BoringSSL file %s: %w", path, err)
	}
	links, err := attachBoringProbes(exec, &objs, path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to inject BoringSSL probes to %s: %w", path, err)
	}
	return links, &objs, nil
}

func attachBoringProbes(ex *link.Executable, objs *boringObjects, target string) ([]link.Link, error) {
	read, write, err := searchUprobeAddresses(target)
	if err != nil {
		log.Warn().Err(err).Msg("cannot find the BoringSSL uprobe address")
		return nil, err
	}
	probes := []struct {
		address uint64
		prog    *ebpf.Program
		inject  func(string, *ebpf.Program, *link.UprobeOptions) (link.Link, error)
	}{
		{uint64(read), objs.ProbeBoringSslReadEntry, ex.Uprobe},
		{uint64(read), objs.ProbeBoringSslReadExit, ex.Uretprobe},
		{uint64(write), objs.ProbeBoringSslReadEntry, ex.Uprobe},
		{uint64(write), objs.ProbeBoringSslWriteExit, ex.Uretprobe},
	}

	failed := 0
	links := []link.Link{}
	for _, probe := range probes {
		up, err := probe.inject("BoringSSL", probe.prog, &link.UprobeOptions{Address: probe.address})
		if err != nil {
			log.Warn().Str("target", target).Err(err).Uint64("addr", probe.address).Msg("failed to attach BoringSSL probe")
			failed++
			continue
		}
		links = append(links, up)
	}
	if failed > 0 {
		for _, link := range links {
			_ = link.Close()
		}
		return nil, fmt.Errorf("failed to inject %d/%d BoringSSL probe", failed, len(probes))
	}
	return links, nil
}

func searchUprobeAddresses(path string) (read int, write int, err error) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return
	}

	buf, err := unix.Mmap(int(file.Fd()), 0, int(fileInfo.Size()), unix.PROT_READ, unix.MAP_PRIVATE)
	if err != nil {
		return
	}
	defer func() {
		if err := unix.Munmap(buf); err != nil {
			log.Warn().Err(err).Msg("failed to un-mmap the file")
		}
	}()

	read = bytes.Index(buf, BoringSSLReadPattern)
	write = bytes.Index(buf, BoringSSLWritePattern)
	if read < 0 || write < 0 {
		err = fmt.Errorf("failed to find read(%d) write(%d): %w", read, write, errUprobeNotFound)
	}
	return
}
