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
	noPrealloc  = 1 // BPF_F_NO_PREALLOC
)

type processIdentity struct {
	ppid      uint32
	startTime uint64
}

type Filter struct {
	mu           sync.RWMutex
	rootPID      uint32
	rootIdentity processIdentity
	pids         map[uint32]struct{}
	m            *ebpf.Map
}

func New(rootPID int) (*Filter, error) {
	if rootPID <= 0 {
		return nil, fmt.Errorf("pid must be greater than 0")
	}
	if uint64(rootPID) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("pid %d exceeds the supported maximum", rootPID)
	}

	pid := uint32(rootPID)
	rootIdentity, ok := readProcessIdentity(pid)
	if !ok {
		return nil, fmt.Errorf("pid %d is not visible in /proc", pid)
	}

	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       mapName,
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  1,
		MaxEntries: maxEntries,
		Flags:      noPrealloc,
	})
	if err != nil {
		return nil, fmt.Errorf("create pid filter map: %w", err)
	}

	f := &Filter{
		rootPID:      pid,
		rootIdentity: rootIdentity,
		pids:         make(map[uint32]struct{}),
		m:            m,
	}
	if err := f.addToMap(sentinelKey); err != nil {
		_ = m.Close()
		return nil, fmt.Errorf("enable pid filter map: %w", err)
	}
	return f, nil
}

// Reconcile seeds the root and its current descendants after the lifecycle
// tracepoints are attached. Identity checks on both sides of each map update
// prevent an exit or PID reuse during the /proc scan from leaving a stale PID.
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

// RecordAdd mirrors an update already performed by the eBPF lifecycle hook.
func (f *Filter) RecordAdd(pid uint32) {
	if f == nil || pid == sentinelKey {
		return
	}
	f.mu.Lock()
	f.pids[pid] = struct{}{}
	f.mu.Unlock()
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

// RecordDelete mirrors an update already performed by the eBPF lifecycle hook.
func (f *Filter) RecordDelete(pid uint32) {
	if f == nil || pid == sentinelKey {
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
	processes, err := readProcesses()
	if err != nil {
		return err
	}
	if rootIdentity, ok := processes[rootPID]; !ok || rootIdentity != f.rootIdentity {
		return fmt.Errorf("root pid %d exited before pid tracking started", rootPID)
	}

	for _, pid := range descendants(rootPID, processes) {
		identity := processes[pid]
		if current, ok := readProcessIdentity(pid); !ok || current != identity {
			continue
		}
		if err := f.Add(pid); err != nil {
			return fmt.Errorf("seed tracked pid %d: %w", pid, err)
		}
		if current, ok := readProcessIdentity(pid); !ok || current != identity {
			f.Delete(pid)
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

func descendants(rootPID uint32, processes map[uint32]processIdentity) []uint32 {
	children := make(map[uint32][]uint32)
	for pid, identity := range processes {
		children[identity.ppid] = append(children[identity.ppid], pid)
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

func readProcesses() (map[uint32]processIdentity, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}

	processes := make(map[uint32]processIdentity)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid64, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}
		pid := uint32(pid64)
		identity, ok := readProcessIdentity(pid)
		if !ok {
			continue
		}
		processes[pid] = identity
	}
	return processes, nil
}

func readProcessIdentity(pid uint32) (processIdentity, bool) {
	data, err := os.ReadFile(filepath.Join(procPath(pid), "stat"))
	if err != nil {
		return processIdentity{}, false
	}
	return parseProcessIdentity(data)
}

func parseProcessIdentity(data []byte) (processIdentity, bool) {
	commEnd := bytes.LastIndexByte(data, ')')
	if commEnd < 0 {
		return processIdentity{}, false
	}
	fields := strings.Fields(string(data[commEnd+1:]))
	// fields starts at proc(5) field 3 (state); ppid is field 4 and
	// starttime is field 22.
	if len(fields) <= 19 {
		return processIdentity{}, false
	}
	ppid, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil {
		return processIdentity{}, false
	}
	startTime, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return processIdentity{}, false
	}
	return processIdentity{ppid: uint32(ppid), startTime: startTime}, true
}

func procPath(pid uint32) string {
	return filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10))
}
