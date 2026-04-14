package securityinsight

import (
	"fmt"
	"strings"
	"time"

	"github.com/tensorchord/watchu/export"
)

// llmAPIPatterns are URL substrings that identify LLM API endpoints.
var llmAPIPatterns = []struct {
	pattern  string
	provider string
}{
	{"/v1/chat/completions", "openai"},
	{"/v1/completions", "openai"},
	{"/v1/messages", "anthropic"},
	{"/v1/responses", "openai"},
	{"generativelanguage.googleapis.com", "google"},
	{"/api/generate", "ollama"},
	{"/api/chat", "ollama"},
	{"/chat/completions", "azure_openai"},
}

// CollectPromptEvidence gathers bounded prompt-injection evidence from an
// EventStore for a host and time window. This is the JSONL equivalent of
// the gateway's Service.CollectPromptEvidence.
func CollectPromptEvidence(store *EventStore, tree *ProcessTree, host string, since, until time.Time, opts CollectOptions) (*PromptEvidencePackage, error) {
	if !since.Before(until) {
		return nil, fmt.Errorf("since must be before until")
	}
	opts = opts.normalize()

	candidates := findPromptCandidates(store, tree, host, since, until, "", opts)

	return &PromptEvidencePackage{
		AnalysisType: "prompt",
		Host:         host,
		Since:        since.Format(time.RFC3339),
		Until:        until.Format(time.RFC3339),
		Goal:         "Determine whether prompt injection likely occurred within the selected host and time window.",
		Budget:       opts.budget(),
		TelemetrySummary: promptTelemetry(candidates),
		Candidates:   clampCandidates(candidates, opts.MaxCandidates),
		Notes: []string{
			"Prompt and HTTP payload snippets are truncated to fit the context budget.",
			"Candidates are the highest-priority rows returned by LLM API URL pattern matching for this host and time window.",
		},
	}, nil
}

// CollectPromptEvidenceByRootExecID collects prompt evidence for a specific
// root execution. It infers the time window and hosts from exec events.
func CollectPromptEvidenceByRootExecID(store *EventStore, tree *ProcessTree, rootExecID string, opts CollectOptions) (*PromptEvidencePackage, error) {
	rootExecID = strings.TrimSpace(rootExecID)
	if rootExecID == "" {
		return nil, fmt.Errorf("root_exec_id is required")
	}

	opts = opts.normalize()
	hosts, since, until, err := PromptWindowFromRootExecID(store, tree, rootExecID)
	if err != nil {
		return nil, err
	}

	host := strings.Join(hosts, ",")
	candidates := findPromptCandidates(store, tree, "", since, until, rootExecID, opts)

	return &PromptEvidencePackage{
		AnalysisType: "prompt",
		Host:         host,
		RootExecID:   rootExecID,
		Since:        since.Format(time.RFC3339),
		Until:        until.Format(time.RFC3339),
		Goal:         "Determine whether prompt injection likely occurred within the selected root execution.",
		Selection: map[string]any{
			"requested_mode": "explicit_root_exec_id",
			"selection_mode": "explicit_root_exec_id",
			"root_exec_id":   rootExecID,
			"hosts":          hosts,
		},
		Budget:           opts.budget(),
		TelemetrySummary: promptTelemetry(candidates),
		Candidates:       clampCandidates(candidates, opts.MaxCandidates),
		Notes: []string{
			"Prompt and HTTP payload snippets are truncated to fit the context budget.",
			"Candidates are filtered to prompt requests associated with the selected root execution.",
		},
	}, nil
}

func findPromptCandidates(store *EventStore, tree *ProcessTree, host string, since, until time.Time, rootExecID string, opts CollectOptions) []PromptCandidate {
	var pids map[int32]struct{}
	if rootExecID != "" {
		pids = tree.DescendantPIDs(rootExecID)
	}

	// index responses by pid+tid for pairing
	type respKey struct {
		Pid int32
		Tid int32
	}
	responseMap := make(map[respKey][]export.RecordResponse, len(store.Responses))
	for i := range store.Responses {
		rec := &store.Responses[i]
		key := respKey{rec.Pid, rec.Tid}
		responseMap[key] = append(responseMap[key], *rec)
	}

	var candidates []PromptCandidate

	for i := range store.Requests {
		req := &store.Requests[i]

		// time window filter
		if !since.IsZero() && req.Timestamp.Before(since) {
			continue
		}
		if !until.IsZero() && req.Timestamp.After(until) {
			continue
		}
		// host filter
		if host != "" && !hostMatches(req.Host, host) {
			continue
		}
		// pid filter for root_exec_id mode
		if pids != nil {
			if _, ok := pids[req.Pid]; !ok {
				continue
			}
		}

		provider := matchLLMProvider(req.URL)
		if provider == "" {
			continue
		}

		// find associated root_exec_id via pid
		candidateRootExecID := ""
		if tree != nil {
			if execIDs, ok := tree.pidToIDs[req.Pid]; ok && len(execIDs) > 0 {
				candidateRootExecID = tree.RootExecID(execIDs[0])
			}
		}

		// extract model from request body if possible
		model := extractModelFromBody(req.Body)

		// find closest response
		respBody := ""
		key := respKey{req.Pid, req.Tid}
		if resps, ok := responseMap[key]; ok {
			closest := findClosestResponse(req.Timestamp, resps)
			if closest != nil {
				respBody = string(closest.Body)
			}
		}

		candidate := PromptCandidate{
			ObservedAt:    req.Timestamp.Format(time.RFC3339),
			Provider:      provider,
			Model:         model,
			RootExecID:    candidateRootExecID,
			PromptSnippet: trimForBudget(extractPromptSnippet(req.Body), opts.MaxPromptChars),
			RequestBody:   trimForBudget(string(req.Body), opts.MaxPromptChars),
			ResponseBody:  trimForBudget(respBody, opts.MaxPromptChars/2),
		}
		candidates = append(candidates, candidate)
	}

	return candidates
}

func matchLLMProvider(url string) string {
	urlLower := strings.ToLower(url)
	for _, p := range llmAPIPatterns {
		if strings.Contains(urlLower, p.pattern) {
			return p.provider
		}
	}
	return ""
}

func findClosestResponse(reqTime time.Time, responses []export.RecordResponse) *export.RecordResponse {
	var best *export.RecordResponse
	bestDelta := time.Duration(0)
	for i := range responses {
		resp := &responses[i]
		if resp.Timestamp.Before(reqTime) {
			continue
		}
		delta := resp.Timestamp.Sub(reqTime)
		if best == nil || delta < bestDelta {
			best = resp
			bestDelta = delta
		}
	}
	return best
}

func extractPromptSnippet(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	// try to extract "messages" or "prompt" field as a simple heuristic
	s := string(body)
	// look for the last "content" field value as a rough prompt extractor
	if idx := strings.LastIndex(s, `"content"`); idx >= 0 {
		// find the start of the value
		rest := s[idx+len(`"content"`):]
		rest = strings.TrimLeft(rest, ": ")
		if len(rest) > 0 && rest[0] == '"' {
			end := strings.Index(rest[1:], `"`)
			if end > 0 {
				return rest[1 : end+1]
			}
		}
	}
	return s
}

func extractModelFromBody(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	s := string(body)
	if idx := strings.Index(s, `"model"`); idx >= 0 {
		rest := s[idx+len(`"model"`):]
		rest = strings.TrimLeft(rest, ": ")
		if len(rest) > 0 && rest[0] == '"' {
			end := strings.Index(rest[1:], `"`)
			if end > 0 {
				return rest[1 : end+1]
			}
		}
	}
	return ""
}

func promptTelemetry(candidates []PromptCandidate) map[string]any {
	rootExecIDs := make(map[string]struct{})
	providers := make(map[string]struct{})
	models := make(map[string]struct{})
	for _, c := range candidates {
		if c.RootExecID != "" {
			rootExecIDs[c.RootExecID] = struct{}{}
		}
		if c.Provider != "" {
			providers[c.Provider] = struct{}{}
		}
		if c.Model != "" {
			models[c.Model] = struct{}{}
		}
	}
	return map[string]any{
		"candidate_count": len(candidates),
		"root_exec_ids":   sortedKeys(rootExecIDs),
		"providers":       sortedKeys(providers),
		"models":          sortedKeys(models),
	}
}

func clampCandidates(candidates []PromptCandidate, max int) []PromptCandidate {
	if len(candidates) <= max {
		return candidates
	}
	return candidates[:max]
}
