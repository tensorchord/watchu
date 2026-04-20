package securityinsight

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/tensorchord/watchu/export"
)

// CollectScan produces a compact overview of one agent run (phase 1).
// Red-flag rules and suspicious-sequence detection are applied to surface
// signals upfront; the output is intended for an LLM agent to decide
// which areas deserve deeper inspection with CollectDetail.
func CollectScan(store *EventStore, tree *ProcessTree, rootExecID string, opts CollectOptions) (*ScanPackage, error) {
	rootExecID = strings.TrimSpace(rootExecID)
	if rootExecID == "" {
		return nil, fmt.Errorf("root_exec_id is required")
	}

	opts = opts.normalize()
	events := QueryEvents(store, tree, EventFilter{RootExecID: rootExecID})

	pkg := &ScanPackage{
		AnalysisType:        AnalysisTypeScan,
		RootExecID:          rootExecID,
		Goal:                "Provide a compact overview of this agent run so you can decide which areas to inspect in detail.",
		TelemetrySummary:    buildThreatTelemetryFromEvents(events),
		EventOverview:       buildEventOverview(events),
		ProcessTree:         buildProcessTreeSkeleton(tree, rootExecID, 3),
		RedFlags:            DetectRedFlags(events),
		SuspiciousSequences: DetectSuspiciousSequences(events, 30*time.Second),
		RunnerExcerpts:      collectRunnerExcerptsFromAgentEvents(events.AgentEvts, opts.MaxAgentOutput),
		Notes: []string{
			"This is a scan overview. Use 'collect threat --mode=detail --focus=<category>' to retrieve raw events for any suspicious area.",
		},
	}

	return pkg, nil
}

// buildEventOverview produces per-category counts and top items using
// diversity sampling (unique values, frequency-ranked).
func buildEventOverview(events *FilteredEvents) map[string]*CategoryOverview {
	overview := make(map[string]*CategoryOverview)

	// exec: unique commands
	if len(events.ExecEvents) > 0 {
		comms := countStrings(len(events.ExecEvents), func(i int) string {
			return events.ExecEvents[i].Comm
		})
		overview["exec"] = &CategoryOverview{
			Count:    len(events.ExecEvents),
			TopItems: topN(comms, 15),
		}
	}

	// file reads
	reads, writes := splitFileOps(events.FileOps)
	if len(reads) > 0 {
		paths := countStrings(len(reads), func(i int) string {
			return reads[i].Path
		})
		overview["file_read"] = &CategoryOverview{
			Count:    len(reads),
			TopItems: topN(paths, 15),
		}
	}
	if len(writes) > 0 {
		paths := countStrings(len(writes), func(i int) string {
			return writes[i].Path
		})
		overview["file_write"] = &CategoryOverview{
			Count:    len(writes),
			TopItems: topN(paths, 15),
		}
	}

	// tcp: unique destinations
	if len(events.TCPConns) > 0 {
		dsts := countStrings(len(events.TCPConns), func(i int) string {
			return fmt.Sprintf("%s:%d", events.TCPConns[i].TargetAddr, events.TCPConns[i].TargetPort)
		})
		overview["tcp_connect"] = &CategoryOverview{
			Count:    len(events.TCPConns),
			TopItems: topN(dsts, 15),
		}
	}

	// http: unique hosts
	if len(events.Requests) > 0 {
		hosts := countStrings(len(events.Requests), func(i int) string {
			return extractHost(events.Requests[i].URL)
		})
		overview["http_request"] = &CategoryOverview{
			Count:    len(events.Requests),
			TopItems: topN(hosts, 15),
		}
	}

	// http responses
	if len(events.Responses) > 0 {
		statuses := countStrings(len(events.Responses), func(i int) string {
			return fmt.Sprintf("HTTP %d", events.Responses[i].StatusCode)
		})
		overview["http_response"] = &CategoryOverview{
			Count:    len(events.Responses),
			TopItems: topN(statuses, 10),
		}
	}

	// mcp stdio
	if len(events.StdIO) > 0 {
		methods := countStrings(len(events.StdIO), func(i int) string {
			if events.StdIO[i].Method != "" {
				return events.StdIO[i].Method
			}
			return fmt.Sprintf("response(corr_id=%s)", events.StdIO[i].CorrID)
		})
		overview["mcp_stdio"] = &CategoryOverview{
			Count:    len(events.StdIO),
			TopItems: topN(methods, 10),
		}
	}

	return overview
}

// buildProcessTreeSkeleton returns a simplified tree up to maxDepth levels.
func buildProcessTreeSkeleton(tree *ProcessTree, rootExecID string, maxDepth int) []ProcessTreeNode {
	node, ok := tree.nodes[rootExecID]
	if !ok {
		return []ProcessTreeNode{}
	}
	root := buildTreeNode(tree, node, 0, maxDepth)
	return []ProcessTreeNode{root}
}

func buildTreeNode(tree *ProcessTree, node *ProcessNode, depth, maxDepth int) ProcessTreeNode {
	ptn := ProcessTreeNode{
		ExecID:        node.ExecID,
		Pid:           node.Pid,
		Comm:          node.Comm,
		Args:          node.Args,
		ChildCount:    len(node.Children),
		AgentProvider: detectAgentProvider(node.Comm, node.Args),
	}
	if depth < maxDepth && len(node.Children) > 0 {
		children := make([]ProcessTreeNode, 0, len(node.Children))
		for _, childID := range node.Children {
			if childNode, ok := tree.nodes[childID]; ok {
				children = append(children, buildTreeNode(tree, childNode, depth+1, maxDepth))
			}
		}
		ptn.Children = children
	}
	return ptn
}

// splitFileOps separates file operations into reads and writes.
func splitFileOps(ops []export.RecordFileOp) (reads, writes []export.RecordFileOp) {
	for i := range ops {
		op := strings.ToLower(ops[i].Op)
		switch {
		case op == "write" || op == "rename" || op == "unlink" || ops[i].Create:
			writes = append(writes, ops[i])
		default:
			reads = append(reads, ops[i])
		}
	}
	return
}

// countStrings tallies string values using an accessor function.
type stringCount struct {
	Value string
	Count int
}

func countStrings(n int, accessor func(i int) string) []stringCount {
	m := make(map[string]int, n)
	for i := range n {
		v := accessor(i)
		if v != "" {
			m[v]++
		}
	}
	counts := make([]stringCount, 0, len(m))
	for v, c := range m {
		counts = append(counts, stringCount{v, c})
	}
	slices.SortFunc(counts, func(a, b stringCount) int {
		if a.Count != b.Count {
			return b.Count - a.Count // desc
		}
		return strings.Compare(a.Value, b.Value)
	})
	return counts
}

func topN(counts []stringCount, n int) []string {
	if len(counts) > n {
		counts = counts[:n]
	}
	out := make([]string, len(counts))
	for i, c := range counts {
		if c.Count > 1 {
			out[i] = fmt.Sprintf("%s (×%d)", c.Value, c.Count)
		} else {
			out[i] = c.Value
		}
	}
	return out
}

// extractHost pulls the hostname portion from a URL.
func extractHost(rawURL string) string {
	// fast path: avoid net/url for simple cases
	s := rawURL
	if idx := strings.Index(s, "://"); idx >= 0 {
		s = s[idx+3:]
	}
	if idx := strings.IndexByte(s, '/'); idx >= 0 {
		s = s[:idx]
	}
	if idx := strings.IndexByte(s, '?'); idx >= 0 {
		s = s[:idx]
	}
	return s
}
