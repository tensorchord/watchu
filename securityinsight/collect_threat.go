package securityinsight

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"

	"github.com/tensorchord/watchu/export"
)

// CollectThreatEvidence gathers bounded threat evidence from an EventStore
// for the given root_exec_id. In the two-phase architecture this is only
// used as a low-level building block; the main workflow uses CollectScan
// and CollectDetail instead.
func CollectThreatEvidence(store *EventStore, tree *ProcessTree, rootExecID string, opts CollectOptions) (*ThreatEvidencePackage, error) {
	rootExecID = strings.TrimSpace(rootExecID)
	if rootExecID == "" {
		return nil, fmt.Errorf("root_exec_id is required")
	}

	opts = opts.normalize()
	pkg := &ThreatEvidencePackage{
		AnalysisType: AnalysisTypeThreat,
		RootExecID:   rootExecID,
		Goal:         "Determine whether this execution shows meaningful security threats.",
		Budget:       opts.budget(),
		Notes: []string{
			"Runner output excerpts keep security-relevant lines and truncate low-signal noise.",
		},
	}

	events := QueryEvents(store, tree, EventFilter{RootExecID: rootExecID})

	// build telemetry summary
	pkg.TelemetrySummary = buildThreatTelemetryFromEvents(events)

	// collect runner excerpts from agent events
	pkg.RunnerExcerpts = collectRunnerExcerptsFromAgentEvents(events.AgentEvts, opts.MaxAgentOutput)

	// collect representative event samples for evidence context
	pkg.EventSamples = collectEventSamples(events, opts.MaxEvents)

	return pkg, nil
}

// collectEventSamples extracts representative raw events as evidence context.
// Events are sampled proportionally per category using reservoir sampling (to
// avoid head-of-list bias), then merged and sorted by timestamp so the LLM
// sees a coherent timeline rather than category-grouped blocks.
func collectEventSamples(events *FilteredEvents, maxSamples int) []EventSample {
	if maxSamples <= 0 {
		maxSamples = defaultMaxEvents
	}

	// Build per-category pools — each pool contains ALL eligible events of
	// that category converted to EventSample.
	type catPool struct {
		name  string
		items []EventSample
	}

	pools := []catPool{
		{"http_request", buildHTTPRequestSamples(events.Requests)},
		{"exec", buildExecSamples(events.ExecEvents)},
		{"mcp_stdio", buildMCPStdIOSamples(events.StdIO)},
		{"file_op", buildFileOpSamples(events.FileOps)},
		{"tcp_connect", buildTCPConnectSamples(events.TCPConns)},
		{"http_response", buildHTTPResponseSamples(events.Responses)},
	}

	// Count non-empty categories and total available events.
	nonEmpty := 0
	totalAvailable := 0
	for i := range pools {
		if len(pools[i].items) > 0 {
			nonEmpty++
			totalAvailable += len(pools[i].items)
		}
	}
	if nonEmpty == 0 || totalAvailable == 0 {
		return []EventSample{}
	}

	// Budget allocation: proportional to pool size, each non-empty category
	// gets at least 1 slot. Two rounds to redistribute unused slots.
	budgets := make([]int, len(pools))
	remaining := maxSamples
	if maxSamples < nonEmpty {
		// Not enough slots for every category to get at least 1;
		// give 1 slot to the first maxSamples non-empty pools only.
		given := 0
		for i := range pools {
			if given >= maxSamples {
				break
			}
			if len(pools[i].items) > 0 {
				budgets[i] = 1
				given++
			}
		}
		remaining = 0
	} else {
		for i := range pools {
			if len(pools[i].items) == 0 {
				continue
			}
			share := max(1, maxSamples*len(pools[i].items)/totalAvailable)
			if share > len(pools[i].items) {
				share = len(pools[i].items)
			}
			budgets[i] = share
			remaining -= share
		}
	}
	// Redistribute remaining budget to categories that still have headroom.
	for remaining > 0 {
		distributed := false
		for i := range pools {
			if remaining <= 0 {
				break
			}
			if budgets[i] < len(pools[i].items) {
				budgets[i]++
				remaining--
				distributed = true
			}
		}
		if !distributed {
			break
		}
	}

	// Reservoir sample within each category, then merge.
	samples := make([]EventSample, 0, maxSamples)
	for i := range pools {
		if budgets[i] <= 0 {
			continue
		}
		samples = append(samples, reservoirSample(pools[i].items, budgets[i])...)
	}

	// Sort by timestamp so the output reads as a coherent timeline.
	slices.SortFunc(samples, func(a, b EventSample) int {
		if a.Timestamp < b.Timestamp {
			return -1
		}
		if a.Timestamp > b.Timestamp {
			return 1
		}
		return 0
	})
	return samples
}

// reservoirSample performs Algorithm R (Knuth) to uniformly sample k items
// from pool without replacement. Returns up to k items.
func reservoirSample(pool []EventSample, k int) []EventSample {
	if k >= len(pool) {
		out := make([]EventSample, len(pool))
		copy(out, pool)
		return out
	}
	reservoir := make([]EventSample, k)
	copy(reservoir, pool[:k])
	for i := k; i < len(pool); i++ {
		j := rand.IntN(i + 1)
		if j < k {
			reservoir[j] = pool[i]
		}
	}
	return reservoir
}

// --- per-category event sample builders ---

func buildHTTPRequestSamples(requests []export.RecordRequest) []EventSample {
	out := make([]EventSample, 0, len(requests))
	for i := range requests {
		rec := &requests[i]
		summary := fmt.Sprintf("%s %s", rec.Method, trimForBudget(rec.URL, 200))
		if rec.ContentLength > 0 {
			summary += fmt.Sprintf(" (%d bytes)", rec.ContentLength)
		}
		out = append(out, EventSample{
			Category:  "http_request",
			Timestamp: rec.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
			Summary:   summary,
			Pid:       rec.Pid,
			Comm:      rec.Comm,
		})
	}
	return out
}

func buildExecSamples(execs []export.RecordExec) []EventSample {
	out := make([]EventSample, 0, len(execs))
	for i := range execs {
		rec := &execs[i]
		summary := trimForBudget(rec.Args, 200)
		if summary == "" {
			summary = rec.Comm
		}
		out = append(out, EventSample{
			Category:  "exec",
			Timestamp: rec.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
			Summary:   summary,
			Pid:       rec.Pid,
			Comm:      rec.Comm,
		})
	}
	return out
}

func buildMCPStdIOSamples(stdio []export.RecordStdIO) []EventSample {
	out := make([]EventSample, 0, len(stdio))
	for i := range stdio {
		rec := &stdio[i]
		summary := fmt.Sprintf("[%s] %s", rec.MessageType, rec.Method)
		if rec.Method == "" {
			summary = fmt.Sprintf("[%s] (response corr_id=%s)", rec.MessageType, rec.CorrID)
		}
		out = append(out, EventSample{
			Category:  "mcp_stdio",
			Timestamp: rec.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
			Summary:   summary,
			Pid:       rec.Pid,
		})
	}
	return out
}

func buildFileOpSamples(fileOps []export.RecordFileOp) []EventSample {
	out := make([]EventSample, 0, len(fileOps))
	for i := range fileOps {
		rec := &fileOps[i]
		if strings.HasPrefix(rec.Path, "/proc/") && !strings.Contains(rec.Path, "/environ") {
			continue
		}
		summary := fmt.Sprintf("%s %s", rec.Op, rec.Path)
		if rec.NewPath != "" {
			summary += fmt.Sprintf(" -> %s", rec.NewPath)
		}
		if rec.Create {
			summary += " [create]"
		}
		out = append(out, EventSample{
			Category:  "file_op",
			Timestamp: rec.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
			Summary:   trimForBudget(summary, 200),
			Pid:       rec.Pid,
			Comm:      rec.Comm,
		})
	}
	return out
}

func buildTCPConnectSamples(conns []export.RecordTCPConnect) []EventSample {
	out := make([]EventSample, 0, len(conns))
	seenDst := make(map[string]struct{})
	for i := range conns {
		rec := &conns[i]
		dst := fmt.Sprintf("%s:%d", rec.TargetAddr, rec.TargetPort)
		if _, ok := seenDst[dst]; ok {
			continue
		}
		seenDst[dst] = struct{}{}
		out = append(out, EventSample{
			Category:  "tcp_connect",
			Timestamp: rec.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
			Summary:   fmt.Sprintf("-> %s", dst),
			Pid:       rec.Pid,
			Comm:      rec.Comm,
		})
	}
	return out
}

func buildHTTPResponseSamples(responses []export.RecordResponse) []EventSample {
	out := make([]EventSample, 0, len(responses))
	for i := range responses {
		rec := &responses[i]
		summary := fmt.Sprintf("HTTP %d (%s, %d bytes)", rec.StatusCode, rec.Protocol, rec.ContentLength)
		out = append(out, EventSample{
			Category:  "http_response",
			Timestamp: rec.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
			Summary:   summary,
			Pid:       rec.Pid,
			Comm:      rec.Comm,
		})
	}
	return out
}

func buildThreatTelemetryFromEvents(events *FilteredEvents) map[string]any {
	total := len(events.ExecEvents) + len(events.Requests) + len(events.Responses) +
		len(events.StdIO) + len(events.FileOps) + len(events.TCPConns) + len(events.AgentEvts)

	byType := map[string]int{
		"exec":        len(events.ExecEvents),
		"http_req":    len(events.Requests),
		"http_resp":   len(events.Responses),
		"mcp_stdio":   len(events.StdIO),
		"file_op":     len(events.FileOps),
		"tcp_connect": len(events.TCPConns),
		"agent_event": len(events.AgentEvts),
	}

	hosts := make(map[string]struct{})
	commands := 0

	for i := range events.ExecEvents {
		if events.ExecEvents[i].Host != "" {
			hosts[events.ExecEvents[i].Host] = struct{}{}
		}
		if strings.TrimSpace(events.ExecEvents[i].Args) != "" {
			commands++
		}
	}
	for i := range events.Requests {
		if events.Requests[i].Host != "" {
			hosts[events.Requests[i].Host] = struct{}{}
		}
	}

	return map[string]any{
		"event_count":         total,
		"event_types":         byType,
		"host_count":          len(hosts),
		"command_event_count": commands,
		"http_event_count":    len(events.Requests),
	}
}

// runnerExcerptKeywords are the security-relevant keywords used to filter
// agent output lines for runner excerpts.
var runnerExcerptKeywords = []string{
	"threat", "security", "refus", "malicious", "suspicious",
	"inject", "exfil", "danger", "blocked", "deny",
}

func collectRunnerExcerptsFromAgentEvents(agentEvts []export.RecordAgentEvent, maxChars int) []RunnerExcerpt {
	excerpts := make([]RunnerExcerpt, 0, 8)
	seen := make(map[string]struct{})
	total := 0

	for i := range agentEvts {
		evt := &agentEvts[i]
		// check output and prompt fields
		for _, text := range []string{evt.Output, evt.Prompt, evt.ErrorMsg} {
			if strings.TrimSpace(text) == "" {
				continue
			}
			for _, line := range strings.Split(text, "\n") {
				trimmed := strings.TrimSpace(line)
				if trimmed == "" {
					continue
				}
				lower := strings.ToLower(trimmed)
				reason := ""
				for _, kw := range runnerExcerptKeywords {
					if strings.Contains(lower, kw) {
						reason = kw
						break
					}
				}
				if reason == "" {
					continue
				}
				trimmed = trimForBudget(trimmed, 320)
				if _, ok := seen[trimmed]; ok {
					continue
				}
				seen[trimmed] = struct{}{}
				if total+len(trimmed) > maxChars {
					return excerpts
				}
				total += len(trimmed)
				excerpts = append(excerpts, RunnerExcerpt{Reason: reason, Content: trimmed})
			}
		}
	}
	return excerpts
}
