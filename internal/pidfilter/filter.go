package pidfilter

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
)

const (
	sentinelKey = uint32(0)
	mapName     = "tracked_pids"
	maxEntries  = 65536
)

type Filter struct {
	mu      sync.RWMutex
	rootPID uint32
	pids    map[uint32]struct{}
	m       *ebpf.Map
}

func New(rootPID int) (*Filter, error) {
	if rootPID <= 0 {
		return nil, fmt.Errorf("pid must be greater than 0")
	}

	pid := uint32(rootPID)
	if _, err := os.Stat(procPath(pid)); err != nil {
		return nil, fmt.Errorf("pid %d is not visible in /proc: %w", pid, err)
	}

	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       mapName,
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  1,
		MaxEntries: maxEntries,
	})
	if err != nil {
		return nil, fmt.Errorf("create pid filter map: %w", err)
	}

	f := &Filter{
		rootPID: pid,
		pids:    make(map[uint32]struct{}),
		m:       m,
	}
	if err := f.addToMap(sentinelKey); err != nil {
		_ = m.Close()
		return nil, fmt.Errorf("enable pid filter map: %w", err)
	}
	if err := f.seed(pid); err != nil {
		_ = m.Close()
		return nil, err
	}
	return f, nil
}

// Reconcile discovers descendants that may have forked while the lifecycle
// tracepoints were being attached. It only adds entries: the eBPF lifecycle
// tracker remains the source of truth for removing exited processes.
func (f *Filter) Reconcile() error {
	if f == nil {
		return nil
	}
	return f.seed(f.rootPID)
}

func (f *Filter) Enabled() bool {
	return f != nil
}

func (f *Filter) CollectionOptions() *ebpf.CollectionOptions {
	if f == nil {
		return nil
	}
	return &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			mapName: f.m,
		},
	}
}

func (f *Filter) Add(pid uint32) error {
	if f == nil || pid == sentinelKey {
		return nil
	}
	if err := f.addToMap(pid); err != nil {
		return err
	}

	f.mu.Lock()
	f.pids[pid] = struct{}{}
	f.mu.Unlock()
	return nil
}

func (f *Filter) Delete(pid uint32) {
	if f == nil || pid == sentinelKey {
		return
	}

	if err := f.m.Delete(pid); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return
	}
	f.mu.Lock()
	delete(f.pids, pid)
	f.mu.Unlock()
}

func (f *Filter) Count() int {
	if f == nil {
		return 0
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.pids)
}

func (f *Filter) Close() error {
	if f == nil || f.m == nil {
		return nil
	}
	return f.m.Close()
}

func (f *Filter) seed(rootPID uint32) error {
	descendants, err := currentDescendants(rootPID)
	if err != nil {
		return err
	}
	for _, pid := range descendants {
		if err := f.Add(pid); err != nil {
			return fmt.Errorf("seed tracked pid %d: %w", pid, err)
		}
	}
	return nil
}

func (f *Filter) addToMap(pid uint32) error {
	value := uint8(1)
	if err := f.m.Update(pid, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update pid filter map for pid %d: %w", pid, err)
	}
	return nil
}

func currentDescendants(rootPID uint32) ([]uint32, error) {
	parents, err := readProcParents()
	if err != nil {
		return nil, err
	}

	return descendants(rootPID, parents), nil
}

func descendants(rootPID uint32, parents map[uint32]uint32) []uint32 {
	children := make(map[uint32][]uint32)
	for pid, ppid := range parents {
		children[ppid] = append(children[ppid], pid)
	}

	result := []uint32{rootPID}
	queue := []uint32{rootPID}
	seen := map[uint32]struct{}{rootPID: {}}
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		for _, child := range children[pid] {
			if _, ok := seen[child]; ok {
				continue
			}
			seen[child] = struct{}{}
			result = append(result, child)
			queue = append(queue, child)
		}
	}
	return result
}

func readProcParents() (map[uint32]uint32, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}

	parents := make(map[uint32]uint32)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid64, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}
		pid := uint32(pid64)
		ppid, ok := readProcPPID(pid)
		if !ok {
			continue
		}
		parents[pid] = ppid
	}
	return parents, nil
}

func readProcPPID(pid uint32) (uint32, bool) {
	data, err := os.ReadFile(filepath.Join(procPath(pid), "status"))
	if err != nil {
		return 0, false
	}
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		key, value, ok := bytes.Cut(line, []byte{':'})
		if !ok || string(key) != "PPid" {
			continue
		}
		ppid64, err := strconv.ParseUint(strings.TrimSpace(string(value)), 10, 32)
		if err != nil {
			return 0, false
		}
		return uint32(ppid64), true
	}
	return 0, false
}

func procPath(pid uint32) string {
	return filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10))
}
