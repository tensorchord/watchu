package securityinsight

import (
	"fmt"
	"strings"

	"github.com/tensorchord/watchu/export"
)

// CollectThreatEvidence gathers bounded threat evidence from an EventStore
// for the given root_exec_id. This is the JSONL equivalent of the gateway's
// Service.CollectThreatEvidence.
func CollectThreatEvidence(store *EventStore, tree *ProcessTree, rootExecID string, opts CollectOptions) (*ThreatEvidencePackage, error) {
	rootExecID = strings.TrimSpace(rootExecID)
	if rootExecID == "" {
		return nil, fmt.Errorf("root_exec_id is required")
	}

	opts = opts.normalize()
	pkg := &ThreatEvidencePackage{
		AnalysisType: "threat",
		RootExecID:   rootExecID,
		Goal:         "Determine whether this execution shows meaningful security threats.",
		Budget:       opts.budget(),
		Notes: []string{
			"Security events are severity-ranked and deduplicated by source, severity, title, and file path.",
			"Runner output excerpts keep security-relevant lines and truncate low-signal noise.",
		},
	}

	// gather events associated with this root_exec_id
	events := QueryEvents(store, tree, EventFilter{RootExecID: rootExecID})

	// build telemetry summary
	pkg.TelemetrySummary = buildThreatTelemetryFromEvents(events)

	// run heuristic analysis
	alerts := RunHeuristics(events)
	pkg.HeuristicAlerts = HeuristicAlertsToItems(alerts)
	sortEvidenceItems(pkg.HeuristicAlerts)

	// collect runner excerpts from agent events
	pkg.RunnerExcerpts = collectRunnerExcerptsFromAgentEvents(events.AgentEvts, opts.MaxRunnerChars)

	return pkg, nil
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
	httpRequests := 0

	for i := range events.ExecEvents {
		if events.ExecEvents[i].Host != "" {
			hosts[events.ExecEvents[i].Host] = struct{}{}
		}
		if strings.TrimSpace(events.ExecEvents[i].Args) != "" {
			commands++
		}
	}
	for i := range events.Requests {
		httpRequests++
		if events.Requests[i].Host != "" {
			hosts[events.Requests[i].Host] = struct{}{}
		}
	}

	return map[string]any{
		"event_count":         total,
		"event_types":         byType,
		"host_count":          len(hosts),
		"command_event_count": commands,
		"http_event_count":    httpRequests,
	}
}

func collectRunnerExcerptsFromAgentEvents(agentEvts []export.RecordAgentEvent, maxChars int) []RunnerExcerpt {
	keywords := []string{"threat", "security", "refus", "malicious", "suspicious", "inject", "exfil", "danger", "blocked", "deny"}
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
				for _, kw := range keywords {
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
