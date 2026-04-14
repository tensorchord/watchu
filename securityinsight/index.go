package securityinsight

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/tensorchord/watchu/export"
)

// ProcessNode is one node in the reconstructed process tree.
type ProcessNode struct {
	ExecID   string
	PExecID  string
	Pid      int32
	Comm     string
	Args     string
	Host     string
	Children []string
}

// ProcessTree provides O(1) lookup for process lineage.
type ProcessTree struct {
	nodes    map[string]*ProcessNode // exec_id → node
	pidToIDs map[int32][]string      // pid → exec_ids
}

// BuildProcessTree constructs a process tree from exec events.
func BuildProcessTree(execs []export.RecordExec) *ProcessTree {
	tree := &ProcessTree{
		nodes:    make(map[string]*ProcessNode, len(execs)),
		pidToIDs: make(map[int32][]string, len(execs)),
	}
	for i := range execs {
		rec := &execs[i]
		node := &ProcessNode{
			ExecID:  rec.ExecId,
			PExecID: rec.PExecId,
			Pid:     rec.Pid,
			Comm:    rec.Comm,
			Args:    rec.Args,
			Host:    rec.Host,
		}
		tree.nodes[rec.ExecId] = node
		tree.pidToIDs[rec.Pid] = append(tree.pidToIDs[rec.Pid], rec.ExecId)
	}
	// wire children
	for _, node := range tree.nodes {
		if parent, ok := tree.nodes[node.PExecID]; ok {
			parent.Children = append(parent.Children, node.ExecID)
		}
	}
	return tree
}

// RootExecID walks up the parent chain from the given exec_id.
func (t *ProcessTree) RootExecID(execID string) string {
	visited := make(map[string]struct{})
	cur := execID
	for {
		node, ok := t.nodes[cur]
		if !ok {
			return cur
		}
		if node.PExecID == "" || node.PExecID == cur {
			return cur
		}
		if _, seen := visited[cur]; seen {
			return cur // cycle guard
		}
		visited[cur] = struct{}{}
		cur = node.PExecID
	}
}

// Descendants returns all exec_ids in the subtree rooted at rootExecID
// (including rootExecID itself).
func (t *ProcessTree) Descendants(rootExecID string) []string {
	var result []string
	queue := []string{rootExecID}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		result = append(result, id)
		if node, ok := t.nodes[id]; ok {
			queue = append(queue, node.Children...)
		}
	}
	return result
}

// DescendantPIDs returns the set of PIDs for all descendants.
func (t *ProcessTree) DescendantPIDs(rootExecID string) map[int32]struct{} {
	pids := make(map[int32]struct{})
	for _, id := range t.Descendants(rootExecID) {
		if node, ok := t.nodes[id]; ok {
			pids[node.Pid] = struct{}{}
		}
	}
	return pids
}

// EventFilter controls which events are returned by query methods.
type EventFilter struct {
	RootExecID string
	Host       string
	Since      time.Time
	Until      time.Time
}

// FilteredEvents returns events matching the filter from the store.
// Process tree association is resolved via PID matching.
type FilteredEvents struct {
	ExecEvents []export.RecordExec
	Requests   []export.RecordRequest
	Responses  []export.RecordResponse
	StdIO      []export.RecordStdIO
	FileOps    []export.RecordFileOp
	TCPConns   []export.RecordTCPConnect
	AgentEvts  []export.RecordAgentEvent
}

// QueryEvents filters the EventStore by the given filter criteria.
func QueryEvents(store *EventStore, tree *ProcessTree, filter EventFilter) *FilteredEvents {
	result := &FilteredEvents{}

	var pids map[int32]struct{}
	if filter.RootExecID != "" {
		pids = tree.DescendantPIDs(filter.RootExecID)
	}

	for i := range store.ExecEvents {
		rec := &store.ExecEvents[i]
		if !matchExec(rec, filter, pids) {
			continue
		}
		result.ExecEvents = append(result.ExecEvents, *rec)
	}
	for i := range store.Requests {
		rec := &store.Requests[i]
		if !matchCommon(rec.Host, rec.Pid, rec.Timestamp, filter, pids) {
			continue
		}
		result.Requests = append(result.Requests, *rec)
	}
	for i := range store.Responses {
		rec := &store.Responses[i]
		if !matchCommon(rec.Host, rec.Pid, rec.Timestamp, filter, pids) {
			continue
		}
		result.Responses = append(result.Responses, *rec)
	}
	for i := range store.StdIO {
		rec := &store.StdIO[i]
		if !matchCommon(rec.Host, rec.Pid, rec.Timestamp, filter, pids) {
			continue
		}
		result.StdIO = append(result.StdIO, *rec)
	}
	for i := range store.FileOps {
		rec := &store.FileOps[i]
		if !matchCommon(rec.Host, rec.Pid, rec.Timestamp, filter, pids) {
			continue
		}
		result.FileOps = append(result.FileOps, *rec)
	}
	for i := range store.TCPConns {
		rec := &store.TCPConns[i]
		if !matchCommon(rec.Host, rec.Pid, rec.Timestamp, filter, pids) {
			continue
		}
		result.TCPConns = append(result.TCPConns, *rec)
	}
	for i := range store.AgentEvts {
		rec := &store.AgentEvts[i]
		if !matchCommon(rec.Host, 0, rec.Timestamp, filter, pids) {
			continue
		}
		result.AgentEvts = append(result.AgentEvts, *rec)
	}
	return result
}

func matchExec(rec *export.RecordExec, f EventFilter, pids map[int32]struct{}) bool {
	if f.Host != "" && !hostMatches(rec.Host, f.Host) {
		return false
	}
	if !f.Since.IsZero() && rec.Timestamp.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && rec.Timestamp.After(f.Until) {
		return false
	}
	if pids != nil {
		if _, ok := pids[rec.Pid]; !ok {
			return false
		}
	}
	return true
}

func matchCommon(host string, pid int32, ts time.Time, f EventFilter, pids map[int32]struct{}) bool {
	if f.Host != "" && !hostMatches(host, f.Host) {
		return false
	}
	if !f.Since.IsZero() && ts.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && ts.After(f.Until) {
		return false
	}
	if pids != nil && pid != 0 {
		if _, ok := pids[pid]; !ok {
			return false
		}
	}
	return true
}

func hostMatches(eventHost, filterHost string) bool {
	if eventHost == filterHost {
		return true
	}
	// support "host:xxx" prefix variant
	return eventHost == "host:"+filterHost || "host:"+eventHost == filterHost
}

// ResolveLatestRootExecID finds the most recent root_exec_id from exec events,
// optionally filtered by host.
func ResolveLatestRootExecID(store *EventStore, tree *ProcessTree, host string) (string, map[string]any, error) {
	if len(store.ExecEvents) == 0 {
		return "", nil, fmt.Errorf("no exec events found")
	}

	// find all unique root_exec_ids with their latest timestamp
	type candidate struct {
		RootExecID string
		Timestamp  time.Time
		Host       string
	}
	rootMap := make(map[string]*candidate)
	for i := range store.ExecEvents {
		rec := &store.ExecEvents[i]
		if host != "" && !hostMatches(rec.Host, host) {
			continue
		}
		rootID := tree.RootExecID(rec.ExecId)
		if rootID == "" {
			continue
		}
		if existing, ok := rootMap[rootID]; ok {
			if rec.Timestamp.After(existing.Timestamp) {
				existing.Timestamp = rec.Timestamp
			}
		} else {
			rootMap[rootID] = &candidate{
				RootExecID: rootID,
				Timestamp:  rec.Timestamp,
				Host:       rec.Host,
			}
		}
	}

	if len(rootMap) == 0 {
		return "", nil, fmt.Errorf("no root executions found")
	}

	var best *candidate
	for _, c := range rootMap {
		if best == nil || c.Timestamp.After(best.Timestamp) {
			best = c
		}
	}

	meta := map[string]any{
		"selection_mode": "latest",
		"requested_mode": "latest",
		"matched_runs":   len(rootMap),
		"selected_at":    best.Timestamp.Format(time.RFC3339),
		"host":           best.Host,
	}
	return best.RootExecID, meta, nil
}

// ResolveThreatRootExecID selects a root_exec_id based on the ThreatSelector.
func ResolveThreatRootExecID(store *EventStore, tree *ProcessTree, selector ThreatSelector) (string, map[string]any, error) {
	if selector.Latest {
		return ResolveLatestRootExecID(store, tree, "")
	}

	// time-window based selection
	if selector.Since.IsZero() && selector.Until.IsZero() {
		return "", nil, fmt.Errorf("either --latest or --since/--until is required")
	}

	type candidate struct {
		RootExecID string
		Timestamp  time.Time
		Host       string
	}
	rootMap := make(map[string]*candidate)
	for i := range store.ExecEvents {
		rec := &store.ExecEvents[i]
		if !selector.Since.IsZero() && rec.Timestamp.Before(selector.Since) {
			continue
		}
		if !selector.Until.IsZero() && rec.Timestamp.After(selector.Until) {
			continue
		}
		rootID := tree.RootExecID(rec.ExecId)
		if rootID == "" {
			continue
		}
		if existing, ok := rootMap[rootID]; ok {
			if rec.Timestamp.After(existing.Timestamp) {
				existing.Timestamp = rec.Timestamp
			}
		} else {
			rootMap[rootID] = &candidate{
				RootExecID: rootID,
				Timestamp:  rec.Timestamp,
				Host:       rec.Host,
			}
		}
	}

	if len(rootMap) == 0 {
		return "", nil, fmt.Errorf("no root executions matched the provided time window")
	}

	var best *candidate
	for _, c := range rootMap {
		if best == nil || c.Timestamp.After(best.Timestamp) {
			best = c
		}
	}

	meta := map[string]any{
		"selection_mode": "time_window",
		"requested_mode": "time_window",
		"matched_runs":   len(rootMap),
		"selected_at":    best.Timestamp.Format(time.RFC3339),
		"host":           best.Host,
	}
	if !selector.Since.IsZero() {
		meta["since"] = selector.Since.Format(time.RFC3339)
	}
	if !selector.Until.IsZero() {
		meta["until"] = selector.Until.Format(time.RFC3339)
	}
	return best.RootExecID, meta, nil
}

// DetectHosts returns host names found in exec events,
// including the "host:" prefixed variant.
func DetectHosts(store *EventStore) []string {
	hosts := make(map[string]struct{})
	for i := range store.ExecEvents {
		h := store.ExecEvents[i].Host
		if h != "" {
			hosts[h] = struct{}{}
		}
	}
	if len(hosts) == 0 {
		if h, err := os.Hostname(); err == nil && h != "" {
			hosts[h] = struct{}{}
		}
	}
	out := make([]string, 0, len(hosts))
	for h := range hosts {
		out = append(out, h)
	}
	slices.Sort(out)
	return out
}

// PromptWindowFromRootExecID derives the host list, since, and until from
// the exec events associated with the given root_exec_id.
func PromptWindowFromRootExecID(store *EventStore, tree *ProcessTree, rootExecID string) ([]string, time.Time, time.Time, error) {
	pids := tree.DescendantPIDs(rootExecID)
	if len(pids) == 0 {
		return nil, time.Time{}, time.Time{}, fmt.Errorf("no execution events found for root_exec_id %s", rootExecID)
	}

	hosts := make(map[string]struct{})
	var since, until time.Time
	for i := range store.ExecEvents {
		rec := &store.ExecEvents[i]
		if _, ok := pids[rec.Pid]; !ok {
			continue
		}
		if rec.Host != "" {
			hosts[rec.Host] = struct{}{}
		}
		if since.IsZero() || rec.Timestamp.Before(since) {
			since = rec.Timestamp
		}
		if until.IsZero() || rec.Timestamp.After(until) {
			until = rec.Timestamp
		}
	}

	if len(hosts) == 0 {
		return nil, time.Time{}, time.Time{}, fmt.Errorf("no host found for root_exec_id %s", rootExecID)
	}
	if since.IsZero() || until.IsZero() {
		return nil, time.Time{}, time.Time{}, fmt.Errorf("no event timestamps found for root_exec_id %s", rootExecID)
	}

	hostList := make([]string, 0, len(hosts))
	for h := range hosts {
		hostList = append(hostList, h)
	}
	slices.Sort(hostList)
	return hostList, since.Add(-1 * time.Second), until.Add(1 * time.Second), nil
}

// ExecEventWindow computes the time bounds over the given exec events.
func ExecEventWindow(execs []export.RecordExec) (time.Time, time.Time) {
	var since, until time.Time
	for i := range execs {
		ts := execs[i].Timestamp
		if since.IsZero() || ts.Before(since) {
			since = ts
		}
		if until.IsZero() || ts.After(until) {
			until = ts
		}
	}
	return since, until
}

// ComputeRootExecIDs computes root_exec_id → latest timestamp map.
func ComputeRootExecIDs(execs []export.RecordExec, tree *ProcessTree) map[string]time.Time {
	roots := make(map[string]time.Time)
	for i := range execs {
		rootID := tree.RootExecID(execs[i].ExecId)
		if rootID == "" {
			continue
		}
		if ts, ok := roots[rootID]; !ok || execs[i].Timestamp.After(ts) {
			roots[rootID] = execs[i].Timestamp
		}
	}
	return roots
}

// emptyDash returns "-" for empty strings.
func emptyDash(v string) string {
	if strings.TrimSpace(v) == "" {
		return "-"
	}
	return v
}

// sortedKeys sorts the keys of a string set.
func sortedKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for v := range values {
		out = append(out, v)
	}
	slices.Sort(out)
	return out
}
