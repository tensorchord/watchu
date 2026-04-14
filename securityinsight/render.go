package securityinsight

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// RenderThreatEvidencePrompt renders a ThreatEvidencePackage as human-readable text.
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

	if len(pkg.SecurityEvents) > 0 {
		b.WriteString("\nTop security events:\n")
		renderEvidenceItems(&b, pkg.SecurityEvents)
	}
	if len(pkg.HeuristicAlerts) > 0 {
		b.WriteString("\nHeuristic alerts:\n")
		renderEvidenceItems(&b, pkg.HeuristicAlerts)
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

func renderEvidenceItems(b *strings.Builder, items []EvidenceItem) {
	for i, item := range items {
		fmt.Fprintf(b, "%d. [%s] %s", i+1, item.Severity, item.Title)
		if item.FilePath != "" {
			fmt.Fprintf(b, " (%s)", item.FilePath)
		}
		b.WriteString("\n")
		if item.Description != "" {
			fmt.Fprintf(b, "   description: %s\n", item.Description)
		}
		if item.Snippet != "" {
			fmt.Fprintf(b, "   snippet: %s\n", item.Snippet)
		}
	}
}

func sortEvidenceItems(items []EvidenceItem) {
	slices.SortStableFunc(items, func(a, b EvidenceItem) int {
		if severityRank(a.Severity) != severityRank(b.Severity) {
			return severityRank(a.Severity) - severityRank(b.Severity)
		}
		return strings.Compare(a.Title, b.Title)
	})
}

func clampEvidenceItems(items []EvidenceItem, max int) []EvidenceItem {
	if len(items) <= max {
		return items
	}
	return items[:max]
}

func severityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	case "info":
		return 4
	case "none":
		return 5
	default:
		return 6
	}
}

func trimForBudget(input string, maxChars int) string {
	cleaned := strings.TrimSpace(input)
	if cleaned == "" {
		return ""
	}
	cleaned = strings.Join(strings.Fields(cleaned), " ")
	if len(cleaned) <= maxChars {
		return cleaned
	}
	if maxChars <= 3 {
		return cleaned[:maxChars]
	}
	return cleaned[:maxChars-3] + "..."
}
