package securityinsight

import (
	"fmt"
	"slices"
	"strings"

	"github.com/tensorchord/watchu/export"
)

// CollectDetail produces raw events for a focused category (phase 2).
// The agent decides which category to inspect based on the scan overview.
func CollectDetail(store *EventStore, tree *ProcessTree, rootExecID string, focus DetailFocus, filter string, opts CollectOptions) (*DetailPackage, error) {
	rootExecID = strings.TrimSpace(rootExecID)
	if rootExecID == "" {
		return nil, fmt.Errorf("root_exec_id is required")
	}

	opts = opts.normalize()
	events := QueryEvents(store, tree, EventFilter{RootExecID: rootExecID})
	filterTrimmed := strings.TrimSpace(filter)

	pkg := &DetailPackage{
		AnalysisType: AnalysisTypeThreatDetail,
		RootExecID:   rootExecID,
		Focus:        string(focus),
		Filter:       filter,
	}

	var allSamples []EventSample

	switch focus {
	case DetailFocusExec:
		allSamples = detailExec(events.ExecEvents, filterTrimmed)
	case DetailFocusFileRead:
		reads, _ := splitFileOps(events.FileOps)
		allSamples = detailFileOps(reads, filterTrimmed)
	case DetailFocusFileWrite:
		_, writes := splitFileOps(events.FileOps)
		allSamples = detailFileOps(writes, filterTrimmed)
	case DetailFocusNetwork:
		allSamples = detailNetwork(events.TCPConns, filterTrimmed)
	case DetailFocusHTTP:
		allSamples = detailHTTP(events.Requests, filterTrimmed)
	case DetailFocusMCP:
		allSamples = detailMCP(events.StdIO, filterTrimmed)
	case DetailFocusAll:
		totalHint := len(events.ExecEvents) + len(events.FileOps) + len(events.TCPConns) + len(events.Requests) + len(events.StdIO)
		allSamples = make([]EventSample, 0, totalHint)
		allSamples = append(allSamples, detailExec(events.ExecEvents, filterTrimmed)...)
		reads, writes := splitFileOps(events.FileOps)
		allSamples = append(allSamples, detailFileOps(reads, filterTrimmed)...)
		allSamples = append(allSamples, detailFileOps(writes, filterTrimmed)...)
		allSamples = append(allSamples, detailNetwork(events.TCPConns, filterTrimmed)...)
		allSamples = append(allSamples, detailHTTP(events.Requests, filterTrimmed)...)
		allSamples = append(allSamples, detailMCP(events.StdIO, filterTrimmed)...)
	default:
		return nil, fmt.Errorf("unknown focus %q; valid: exec, file_read, file_write, network, http, mcp, all", focus)
	}

	// Sort by timestamp for coherent timeline.
	slices.SortFunc(allSamples, func(a, b EventSample) int {
		return strings.Compare(a.Timestamp, b.Timestamp)
	})

	pkg.TotalEvents = len(allSamples)
	maxEvents := opts.MaxEvents
	if maxEvents <= 0 {
		maxEvents = defaultMaxEvents
	}
	if len(allSamples) > maxEvents {
		pkg.Events = allSamples[:maxEvents]
		pkg.Notes = append(pkg.Notes, fmt.Sprintf("Showing %d of %d events (budget=%d). Use --filter to narrow.", maxEvents, len(allSamples), maxEvents))
	} else {
		pkg.Events = allSamples
	}
	pkg.ShownEvents = len(pkg.Events)

	return pkg, nil
}

func detailExec(execs []export.RecordExec, filter string) []EventSample {
	out := make([]EventSample, 0, len(execs))
	for i := range execs {
		rec := &execs[i]
		text := rec.Comm + " " + rec.Args
		if filter != "" && !matchesFilter(text, filter) {
			continue
		}
		summary := trimForBudget(rec.Args, 300)
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

func detailFileOps(ops []export.RecordFileOp, filter string) []EventSample {
	out := make([]EventSample, 0, len(ops))
	for i := range ops {
		rec := &ops[i]
		text := rec.Path + " " + rec.Op
		if filter != "" && !matchesFilter(text, filter) {
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
			Category:  "file_" + strings.ToLower(rec.Op),
			Timestamp: rec.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
			Summary:   trimForBudget(summary, 300),
			Pid:       rec.Pid,
			Comm:      rec.Comm,
		})
	}
	return out
}

func detailNetwork(conns []export.RecordTCPConnect, filter string) []EventSample {
	out := make([]EventSample, 0, len(conns))
	for i := range conns {
		rec := &conns[i]
		dst := fmt.Sprintf("%s:%d", rec.TargetAddr, rec.TargetPort)
		text := dst + " " + rec.Comm
		if filter != "" && !matchesFilter(text, filter) {
			continue
		}
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

func detailHTTP(requests []export.RecordRequest, filter string) []EventSample {
	out := make([]EventSample, 0, len(requests))
	for i := range requests {
		rec := &requests[i]
		text := rec.URL + " " + rec.Method + " " + rec.Comm
		if filter != "" && !matchesFilter(text, filter) {
			continue
		}
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

func detailMCP(stdio []export.RecordStdIO, filter string) []EventSample {
	out := make([]EventSample, 0, len(stdio))
	for i := range stdio {
		rec := &stdio[i]
		summary := fmt.Sprintf("[%s] %s", rec.MessageType, rec.Method)
		if rec.Method == "" {
			summary = fmt.Sprintf("[%s] (response corr_id=%s)", rec.MessageType, rec.CorrID)
		}
		text := summary + " " + rec.Method
		if filter != "" && !matchesFilter(text, filter) {
			continue
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

// matchesFilter checks if text matches any of the pipe-separated filter terms.
// e.g. filter="curl|wget|chmod" matches if text contains any of them.
func matchesFilter(text, filter string) bool {
	if filter == "" {
		return true
	}
	lower := strings.ToLower(text)
	for _, term := range strings.Split(strings.ToLower(filter), "|") {
		term = strings.TrimSpace(term)
		if term != "" && strings.Contains(lower, term) {
			return true
		}
	}
	return false
}
