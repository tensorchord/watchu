package securityinsight

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/tensorchord/watchu/export"
)

// llmHostProviders maps well-known LLM API host substrings to provider names.
// More specific entries must appear before broader ones to avoid false matches.
// Hosts not listed here fall back to the raw host string as the provider label.
var llmHostProviders = []struct {
	host     string
	provider string
}{
	{"api.openai.com", "openai"},
	{"api.anthropic.com", "anthropic"},
	{"generativelanguage.googleapis.com", "google"},
	{"openrouter.ai", "openrouter"},
	{"api.groq.com", "groq"},
	{"api.together.xyz", "together"},
	{"api.fireworks.ai", "fireworks"},
	{"api.perplexity.ai", "perplexity"},
	{"api.deepseek.com", "deepseek"},
	{"api.mistral.ai", "mistral"},
	{"api.cohere.com", "cohere"},
	{"azure.com", "azure_openai"},
}

// CollectPromptEvidence gathers bounded prompt-injection evidence from an
// EventStore for a host and time window. This is the JSONL equivalent of
// the gateway's Service.CollectPromptEvidence.
func CollectPromptEvidence(store *EventStore, tree *ProcessTree, host string, since, until time.Time, opts CollectOptions) (*PromptEvidencePackage, error) {
	if !since.Before(until) {
		return nil, fmt.Errorf("since must be before until")
	}
	opts = opts.normalize()

	candidates := findPromptCandidates(store, tree, promptFilter{
		host:  host,
		since: since,
		until: until,
	}, opts)

	return &PromptEvidencePackage{
		AnalysisType: AnalysisTypePrompt,
		Host:         host,
		Since:        since.Format(time.RFC3339),
		Until:        until.Format(time.RFC3339),
		Goal:         "Determine whether prompt injection likely occurred within the selected host and time window.",
		Budget:       opts.budget(),
		TelemetrySummary: promptTelemetry(candidates),
		Candidates:   clampCandidates(candidates, opts.MaxLLMCalls),
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
	candidates := findPromptCandidates(store, tree, promptFilter{
		since:      since,
		until:      until,
		rootExecID: rootExecID,
	}, opts)

	return &PromptEvidencePackage{
		AnalysisType: AnalysisTypePrompt,
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
		Candidates:       clampCandidates(candidates, opts.MaxLLMCalls),
		Notes: []string{
			"Prompt and HTTP payload snippets are truncated to fit the context budget.",
			"Candidates are filtered to prompt requests associated with the selected root execution.",
		},
	}, nil
}

// promptFilter bundles the query parameters for findPromptCandidates,
// keeping the function signature under 4 parameters.
type promptFilter struct {
	host       string
	since      time.Time
	until      time.Time
	rootExecID string
}

func findPromptCandidates(store *EventStore, tree *ProcessTree, f promptFilter, opts CollectOptions) []PromptCandidate {
	var pids map[int32]struct{}
	if f.rootExecID != "" {
		pids = tree.DescendantPIDs(f.rootExecID)
	}

	// Build a sorted response index keyed by (pid, tid). Sorting by timestamp
	// enables a consume-once cursor: each response is matched to at most one
	// request, preventing a single response from being paired with multiple
	// back-to-back requests on the same thread.
	//
	// Limitation: (pid, tid) is the finest granularity available in the current
	// eBPF data model. Socket fd or a correlation ID would allow exact 1:1
	// matching for HTTP/2 multiplexed streams, but those fields are not
	// captured yet.
	type respKey struct {
		Pid int32
		Tid int32
	}
	type respCursor struct {
		resps []export.RecordResponse
		next  int // index of the first unconsumed response
	}
	respIndex := make(map[respKey]*respCursor, len(store.Responses))
	for i := range store.Responses {
		rec := &store.Responses[i]
		key := respKey{rec.Pid, rec.Tid}
		if respIndex[key] == nil {
			respIndex[key] = &respCursor{}
		}
		respIndex[key].resps = append(respIndex[key].resps, *rec)
	}
	for _, cur := range respIndex {
		sort.Slice(cur.resps, func(i, j int) bool {
			return cur.resps[i].Timestamp.Before(cur.resps[j].Timestamp)
		})
	}

	candidates := make([]PromptCandidate, 0, 8)

	for i := range store.Requests {
		req := &store.Requests[i]

		// time window filter
		if !f.since.IsZero() && req.Timestamp.Before(f.since) {
			continue
		}
		if !f.until.IsZero() && req.Timestamp.After(f.until) {
			continue
		}
		// host filter
		if f.host != "" && !hostMatches(req.Host, f.host) {
			continue
		}
		// pid filter for root_exec_id mode
		if pids != nil {
			if _, ok := pids[req.Pid]; !ok {
				continue
			}
		}

		provider := matchLLMProvider(urlHost(req.URL), req.Body)
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

		// Consume the first response after req.Timestamp in the same pid+tid
		// bucket. Advancing the cursor ensures each response is used at most once.
		respBody := ""
		key := respKey{req.Pid, req.Tid}
		if cur, ok := respIndex[key]; ok {
			// Skip responses that arrived before this request.
			for cur.next < len(cur.resps) && !cur.resps[cur.next].Timestamp.After(req.Timestamp) {
				cur.next++
			}
			if cur.next < len(cur.resps) {
				respBody = string(cur.resps[cur.next].Body)
				cur.next++
			}
		}

		candidate := PromptCandidate{
			ObservedAt:    req.Timestamp.Format(time.RFC3339),
			Provider:      provider,
			Model:         model,
			RootExecID:    candidateRootExecID,
		PromptSnippet: trimForBudget(extractPromptSnippet(req.Body), opts.MaxSnippetChars),
		RequestBody:   trimForBudget(string(req.Body), opts.MaxSnippetChars),
		ResponseBody:  trimForBudget(respBody, opts.MaxSnippetChars/2),
		}
		candidates = append(candidates, candidate)
	}

	return candidates
}

// urlHost extracts the hostname from a raw URL string, returning empty string
// on parse failure. Port is excluded from the result.
func urlHost(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil {
		return u.Hostname()
	}
	return ""
}

// isLLMRequestBody reports whether body looks like an LLM API request payload
// by checking for characteristic JSON field names, regardless of URL path.
// This handles proxied calls (e.g. litellm) where the path is arbitrary.
func isLLMRequestBody(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	s := string(body)
	if !strings.Contains(s, `"model"`) {
		return false
	}
	// Require at least one prompt-bearing field alongside "model".
	return strings.Contains(s, `"messages"`) ||
		strings.Contains(s, `"prompt"`) ||
		strings.Contains(s, `"contents"`) ||
		strings.Contains(s, `"input"`)
}

// matchLLMProvider returns the inferred provider name if the request looks like
// an LLM API call, or empty string otherwise.
//
// Detection uses two independent signals, either of which is sufficient:
//   - Host matches a known LLM provider (llmHostProviders)
//   - Request body contains characteristic LLM fields ("model" + prompt fields)
//
// Body-based detection handles proxied or self-hosted setups (e.g. litellm,
// ollama, vllm) where the URL path is arbitrary and cannot be relied upon.
// Provider attribution uses the host map, falling back to the raw host string.
func matchLLMProvider(host string, body []byte) string {
	hostLower := strings.ToLower(host)

	// Known provider by host — fastest path and most reliable.
	for _, h := range llmHostProviders {
		if strings.Contains(hostLower, h.host) {
			return h.provider
		}
	}

	// Unknown host: fall back to body-shape detection.
	if !isLLMRequestBody(body) {
		return ""
	}
	if host != "" {
		return host
	}
	return "unknown"
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
