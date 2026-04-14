package securityinsight

import "time"

const (
	defaultMaxEvents          = 50
	defaultMaxFindingsPerKind = 20
	defaultMaxRunnerChars     = 12000
	defaultMaxPromptChars     = 4000
	defaultMaxCandidates      = 25
)

// OutputFormat controls the rendering mode for collected evidence.
type OutputFormat string

const (
	OutputFormatPrompt OutputFormat = "prompt"
	OutputFormatJSON   OutputFormat = "json"
)

// CollectOptions controls how much evidence is included in the output.
type CollectOptions struct {
	MaxEvents          int
	MaxFindingsPerKind int
	MaxRunnerChars     int
	MaxPromptChars     int
	MaxCandidates      int
}

func (o CollectOptions) normalize() CollectOptions {
	if o.MaxEvents <= 0 {
		o.MaxEvents = defaultMaxEvents
	}
	if o.MaxFindingsPerKind <= 0 {
		o.MaxFindingsPerKind = defaultMaxFindingsPerKind
	}
	if o.MaxRunnerChars <= 0 {
		o.MaxRunnerChars = defaultMaxRunnerChars
	}
	if o.MaxPromptChars <= 0 {
		o.MaxPromptChars = defaultMaxPromptChars
	}
	if o.MaxCandidates <= 0 {
		o.MaxCandidates = defaultMaxCandidates
	}
	return o
}

func (o CollectOptions) budget() EvidenceBudget {
	return EvidenceBudget{
		MaxEvents:          o.MaxEvents,
		MaxFindingsPerKind: o.MaxFindingsPerKind,
		MaxRunnerChars:     o.MaxRunnerChars,
		MaxPromptChars:     o.MaxPromptChars,
		MaxCandidates:      o.MaxCandidates,
	}
}

// EvidenceBudget records the size limits applied during collection.
type EvidenceBudget struct {
	MaxEvents          int `json:"max_events"`
	MaxFindingsPerKind int `json:"max_findings_per_kind"`
	MaxRunnerChars     int `json:"max_runner_chars"`
	MaxPromptChars     int `json:"max_prompt_chars"`
	MaxCandidates      int `json:"max_candidates"`
}

// EvidenceItem is one piece of security evidence.
type EvidenceItem struct {
	Source      string         `json:"source"`
	Severity    string         `json:"severity"`
	Title       string         `json:"title"`
	Description string         `json:"description,omitempty"`
	FilePath    string         `json:"file_path,omitempty"`
	Snippet     string         `json:"snippet,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// RunnerExcerpt is a security-relevant line extracted from agent output.
type RunnerExcerpt struct {
	Reason  string `json:"reason"`
	Content string `json:"content"`
}

// ThreatEvidencePackage is the bounded evidence package for threat analysis.
type ThreatEvidencePackage struct {
	AnalysisType       string          `json:"analysis_type"`
	RootExecID         string          `json:"root_exec_id"`
	Goal               string          `json:"goal"`
	Selection          map[string]any  `json:"selection,omitempty"`
	Budget             EvidenceBudget  `json:"budget"`
	TelemetrySummary   map[string]any  `json:"telemetry_summary"`
	HeuristicAlerts    []EvidenceItem  `json:"heuristic_alerts"`
	SecurityEvents     []EvidenceItem  `json:"security_events"`
	RunnerExcerpts     []RunnerExcerpt `json:"runner_output_excerpts"`
	Notes              []string        `json:"notes"`
	EnvironmentContext map[string]any  `json:"environment_context,omitempty"`
}

// PromptCandidate is one LLM request/response pair under analysis.
type PromptCandidate struct {
	ObservedAt    string `json:"observed_at"`
	Provider      string `json:"provider,omitempty"`
	Model         string `json:"model,omitempty"`
	RootExecID    string `json:"root_exec_id,omitempty"`
	AgentRootExec string `json:"agent_root_exec_id,omitempty"`
	PromptSnippet string `json:"prompt_snippet"`
	RequestBody   string `json:"request_body,omitempty"`
	ResponseBody  string `json:"response_body,omitempty"`
}

// PromptEvidencePackage is the bounded evidence package for prompt injection analysis.
type PromptEvidencePackage struct {
	AnalysisType     string            `json:"analysis_type"`
	Host             string            `json:"host"`
	RootExecID       string            `json:"root_exec_id,omitempty"`
	Since            string            `json:"since"`
	Until            string            `json:"until"`
	Goal             string            `json:"goal"`
	Selection        map[string]any    `json:"selection,omitempty"`
	Budget           EvidenceBudget    `json:"budget"`
	TelemetrySummary map[string]any    `json:"telemetry_summary"`
	Candidates       []PromptCandidate `json:"candidates"`
	Notes            []string          `json:"notes"`
}

// ThreatSelector controls how the CLI resolves a root_exec_id for threat analysis.
type ThreatSelector struct {
	Latest    bool
	Since     time.Time
	Until     time.Time
	SourceRef string
	AgentType string
}
