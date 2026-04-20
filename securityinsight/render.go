package securityinsight

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// RenderThreatEvidencePrompt renders a ThreatEvidencePackage as human-readable text.
// Kept for backward compatibility but the new workflow uses RenderScanPrompt/RenderDetailPrompt.
func RenderThreatEvidencePrompt(pkg *ThreatEvidencePackage) string {
	var b strings.Builder
	b.WriteString("SECURITYINSIGHT EVIDENCE PACKAGE\n\n")
	b.WriteString("Analysis type: threat\n")
	b.WriteString("Root exec ID: ")
	b.WriteString(pkg.RootExecID)
	b.WriteString("\n")
	if len(pkg.Selection) > 0 {
		b.WriteString("Selection:\n")
		renderMap(&b, pkg.Selection)
		b.WriteString("\n")
	}
	b.WriteString("Goal: ")
	b.WriteString(pkg.Goal)
	b.WriteString("\n\nTelemetry summary:\n")
	renderMap(&b, pkg.TelemetrySummary)

	if len(pkg.EventSamples) > 0 {
		b.WriteString("\nEvent samples:\n")
		for i, s := range pkg.EventSamples {
			fmt.Fprintf(&b, "%d. [%s] %s", i+1, s.Category, s.Summary)
			if s.Comm != "" {
				fmt.Fprintf(&b, " (comm=%s pid=%d)", s.Comm, s.Pid)
			}
			fmt.Fprintf(&b, " @ %s\n", s.Timestamp)
		}
	}
	if len(pkg.RunnerExcerpts) > 0 {
		b.WriteString("\nRunner output excerpts:\n")
		for i, excerpt := range pkg.RunnerExcerpts {
			fmt.Fprintf(&b, "%d. [%s] %s\n", i+1, excerpt.Reason, excerpt.Content)
		}
	}
	if len(pkg.EnvironmentContext) > 0 {
		b.WriteString("\nEnvironment context:\n")
		renderMap(&b, pkg.EnvironmentContext)
	}
	if len(pkg.Notes) > 0 {
		b.WriteString("\nBudget notes:\n")
		for _, note := range pkg.Notes {
			b.WriteString("- ")
			b.WriteString(note)
			b.WriteString("\n")
		}
	}

	return strings.TrimSpace(b.String())
}

// RenderPromptEvidencePrompt renders a PromptEvidencePackage as human-readable text.
func RenderPromptEvidencePrompt(pkg *PromptEvidencePackage) string {
	var b strings.Builder
	b.WriteString("SECURITYINSIGHT EVIDENCE PACKAGE\n\n")
	b.WriteString("Analysis type: prompt\n")
	if pkg.RootExecID != "" {
		b.WriteString("Root exec ID: ")
		b.WriteString(pkg.RootExecID)
		b.WriteString("\n")
	}
	b.WriteString("Host: ")
	b.WriteString(pkg.Host)
	b.WriteString("\n")
	b.WriteString("Since: ")
	b.WriteString(pkg.Since)
	b.WriteString("\n")
	b.WriteString("Until: ")
	b.WriteString(pkg.Until)
	b.WriteString("\n")
	if len(pkg.Selection) > 0 {
		b.WriteString("Selection:\n")
		renderMap(&b, pkg.Selection)
		b.WriteString("\n")
	}
	b.WriteString("Goal: ")
	b.WriteString(pkg.Goal)
	b.WriteString("\n\nTelemetry summary:\n")
	renderMap(&b, pkg.TelemetrySummary)

	if len(pkg.Candidates) > 0 {
		b.WriteString("\nPrompt candidates:\n")
		for i, candidate := range pkg.Candidates {
			fmt.Fprintf(&b, "%d. observed_at=%s provider=%s model=%s root_exec_id=%s\n",
				i+1, candidate.ObservedAt,
				emptyDash(candidate.Provider),
				emptyDash(candidate.Model),
				emptyDash(candidate.RootExecID))
			if candidate.PromptSnippet != "" {
				fmt.Fprintf(&b, "   prompt: %s\n", candidate.PromptSnippet)
			}
			if candidate.RequestBody != "" {
				fmt.Fprintf(&b, "   request: %s\n", candidate.RequestBody)
			}
			if candidate.ResponseBody != "" {
				fmt.Fprintf(&b, "   response: %s\n", candidate.ResponseBody)
			}
		}
	}
	if len(pkg.Notes) > 0 {
		b.WriteString("\nBudget notes:\n")
		for _, note := range pkg.Notes {
			b.WriteString("- ")
			b.WriteString(note)
			b.WriteString("\n")
		}
	}

	return strings.TrimSpace(b.String())
}

// MarshalCollectedJSON serializes the evidence package as pretty-printed JSON.
func MarshalCollectedJSON(v any) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

func renderMap(b *strings.Builder, m map[string]any) {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		fmt.Fprintf(b, "- %s: %v\n", key, m[key])
	}
}

func trimForBudget(input string, maxChars int) string {
	cleaned := strings.TrimSpace(input)
	if cleaned == "" {
		return ""
	}
	cleaned = strings.Join(strings.Fields(cleaned), " ")
	runes := []rune(cleaned)
	if len(runes) <= maxChars {
		return cleaned
	}
	if maxChars <= 3 {
		return string(runes[:maxChars])
	}
	return string(runes[:maxChars-3]) + "..."
}

// RenderScanPrompt renders a ScanPackage as agent-readable text.
func RenderScanPrompt(pkg *ScanPackage) string {
	var b strings.Builder
	b.WriteString("SECURITYINSIGHT SCAN OVERVIEW\n\n")
	fmt.Fprintf(&b, "Analysis type: %s\n", pkg.AnalysisType)
	b.WriteString("Root exec ID: ")
	b.WriteString(pkg.RootExecID)
	b.WriteString("\n")
	if len(pkg.Selection) > 0 {
		b.WriteString("Selection:\n")
		renderMap(&b, pkg.Selection)
		b.WriteString("\n")
	}
	b.WriteString("Goal: ")
	b.WriteString(pkg.Goal)
	b.WriteString("\n\nTelemetry summary:\n")
	renderMap(&b, pkg.TelemetrySummary)

	if len(pkg.EventOverview) > 0 {
		b.WriteString("\nEvent overview:\n")
		// Stable ordering of categories.
		catOrder := []string{"exec", "file_read", "file_write", "tcp_connect", "http_request", "http_response", "mcp_stdio"}
		for _, cat := range catOrder {
			ov, ok := pkg.EventOverview[cat]
			if !ok {
				continue
			}
			fmt.Fprintf(&b, "  %s: %d events\n", cat, ov.Count)
			for _, item := range ov.TopItems {
				fmt.Fprintf(&b, "    - %s\n", item)
			}
		}
	}

	if len(pkg.ProcessTree) > 0 {
		b.WriteString("\nProcess tree:\n")
		for _, root := range pkg.ProcessTree {
			renderTreeNode(&b, root, 1)
		}
	}

	if len(pkg.RedFlags) > 0 {
		fmt.Fprintf(&b, "\nRed flags (%d):\n", len(pkg.RedFlags))
		for i, rf := range pkg.RedFlags {
			fmt.Fprintf(&b, "  %d. [%s] %s — comm=%s pid=%d @ %s\n",
				i+1, rf.Severity, rf.PatternID, rf.Comm, rf.Pid, rf.Timestamp)
			fmt.Fprintf(&b, "     evidence: %s\n", rf.Evidence)
			fmt.Fprintf(&b, "     reason: %s\n", rf.Reason)
		}
	}

	if len(pkg.SuspiciousSequences) > 0 {
		fmt.Fprintf(&b, "\nSuspicious sequences (%d):\n", len(pkg.SuspiciousSequences))
		for i, seq := range pkg.SuspiciousSequences {
			fmt.Fprintf(&b, "  %d. [%s] %s +%dms\n", i+1, seq.Severity, seq.PatternID, seq.DeltaMs)
			fmt.Fprintf(&b, "     trigger:  [%s] %s (comm=%s pid=%d) @ %s\n",
				seq.Trigger.Category, seq.Trigger.Summary, seq.Trigger.Comm, seq.Trigger.Pid, seq.Trigger.Timestamp)
			fmt.Fprintf(&b, "     follower: [%s] %s (comm=%s pid=%d) @ %s\n",
				seq.Follower.Category, seq.Follower.Summary, seq.Follower.Comm, seq.Follower.Pid, seq.Follower.Timestamp)
			fmt.Fprintf(&b, "     reason: %s\n", seq.Reason)
		}
	}

	if len(pkg.RunnerExcerpts) > 0 {
		b.WriteString("\nRunner output excerpts:\n")
		for i, excerpt := range pkg.RunnerExcerpts {
			fmt.Fprintf(&b, "%d. [%s] %s\n", i+1, excerpt.Reason, excerpt.Content)
		}
	}

	if len(pkg.Notes) > 0 {
		b.WriteString("\nNotes:\n")
		for _, note := range pkg.Notes {
			b.WriteString("- ")
			b.WriteString(note)
			b.WriteString("\n")
		}
	}

	return strings.TrimSpace(b.String())
}

func renderTreeNode(b *strings.Builder, node ProcessTreeNode, depth int) {
	indent := strings.Repeat("  ", depth)
	label := node.Comm
	if node.AgentProvider != "" {
		label += fmt.Sprintf(" [%s]", node.AgentProvider)
	}
	if node.ChildCount > 0 {
		label += fmt.Sprintf(" → %d children", node.ChildCount)
	}
	fmt.Fprintf(b, "%s%s (pid=%d)\n", indent, label, node.Pid)
	if node.Args != "" {
		args := node.Args
		const maxArgLen = 120
		if len(args) > maxArgLen {
			args = args[:maxArgLen] + "..."
		}
		fmt.Fprintf(b, "%s  args: %s\n", indent, args)
	}
	for _, child := range node.Children {
		renderTreeNode(b, child, depth+1)
	}
}

// RenderDetailPrompt renders a DetailPackage as agent-readable text.
func RenderDetailPrompt(pkg *DetailPackage) string {
	var b strings.Builder
	fmt.Fprintf(&b, "SECURITYINSIGHT DETAIL: %s\n\n", strings.ToUpper(pkg.Focus))
	b.WriteString("Root exec ID: ")
	b.WriteString(pkg.RootExecID)
	b.WriteString("\n")
	if pkg.Filter != "" {
		fmt.Fprintf(&b, "Filter: %s\n", pkg.Filter)
	}
	fmt.Fprintf(&b, "Events: %d shown / %d total\n\n", pkg.ShownEvents, pkg.TotalEvents)

	for i, ev := range pkg.Events {
		fmt.Fprintf(&b, "%d. [%s] %s", i+1, ev.Category, ev.Summary)
		if ev.Comm != "" {
			fmt.Fprintf(&b, " (comm=%s pid=%d)", ev.Comm, ev.Pid)
		}
		fmt.Fprintf(&b, " @ %s\n", ev.Timestamp)
	}

	if len(pkg.Notes) > 0 {
		b.WriteString("\nNotes:\n")
		for _, note := range pkg.Notes {
			b.WriteString("- ")
			b.WriteString(note)
			b.WriteString("\n")
		}
	}

	return strings.TrimSpace(b.String())
}
