package securityinsight

import "time"

const (
	defaultMaxEvents       = 50
	defaultMaxAgentOutput  = 12000
	defaultMaxSnippetChars = 4000
	defaultMaxLLMCalls     = 25
)

// OutputFormat controls the rendering mode for collected evidence.
type OutputFormat string

const (
	OutputFormatPrompt OutputFormat = "prompt"
	OutputFormatJSON   OutputFormat = "json"
)

// ────────────────────────────────────────────────────────────────────────────
// Pattern IDs — single-event red flags (S*) and temporal sequences (T*)
// ────────────────────────────────────────────────────────────────────────────

const (
	// Red-flag patterns (single-event match).
	PatternS1DestructiveCommand    = "S1_destructive_command"
	PatternS2ReverseShell          = "S2_reverse_shell"
	PatternS3CodeInjectionPipe     = "S3_code_injection_pipe"
	PatternS4Base64DecodeExec      = "S4_base64_decode_exec"
	PatternS5PersistenceInstall    = "S5_persistence_install"
	PatternS6SystemdServiceChange  = "S6_systemd_service_change"
	PatternS7SensitiveChmod        = "S7_sensitive_chmod"
	PatternS8CredentialInArgs      = "S8_credential_in_args"
	PatternS9ShellRCWrite          = "S9_shell_rc_write"
	PatternS10CommandSubstSensRead = "S10_command_subst_sensitive_read"

	// Suspicious-sequence patterns (cross-category temporal correlation).
	PatternT1SensitiveReadThenExfil  = "T1_sensitive_read_then_exfil"
	PatternT2ReconThenExfil          = "T2_recon_then_exfil"
	PatternT3DownloadThenExecute     = "T3_download_then_execute"
	PatternT5AuthTamperThenNetwork   = "T5_auth_tamper_then_network"
	PatternT6PersistenceThenDownload = "T6_persistence_then_download"
	PatternT7ChmodThenExecute        = "T7_chmod_then_execute"
	PatternT8FileWriteThenExecute    = "T8_file_write_then_execute"
)

// Severity levels for red flags and suspicious sequences.
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
)

// Analysis type identifiers for evidence packages.
const (
	AnalysisTypeThreat       = "threat"
	AnalysisTypeThreatDetail = "threat_detail"
	AnalysisTypePrompt       = "prompt"
	AnalysisTypeScan         = "scan"
)

// CollectOptions controls how much evidence is included in the output.
type CollectOptions struct {
	MaxEvents       int
	MaxAgentOutput  int
	MaxSnippetChars int
	MaxLLMCalls     int
}

func (o CollectOptions) normalize() CollectOptions {
	if o.MaxEvents <= 0 {
		o.MaxEvents = defaultMaxEvents
	}
	if o.MaxAgentOutput <= 0 {
		o.MaxAgentOutput = defaultMaxAgentOutput
	}
	if o.MaxSnippetChars <= 0 {
		o.MaxSnippetChars = defaultMaxSnippetChars
	}
	if o.MaxLLMCalls <= 0 {
		o.MaxLLMCalls = defaultMaxLLMCalls
	}
	return o
}

func (o CollectOptions) budget() EvidenceBudget {
	return EvidenceBudget(o)
}

// EvidenceBudget records the size limits applied during collection.
type EvidenceBudget struct {
	MaxEvents       int `json:"max_events"`
	MaxAgentOutput  int `json:"max_agent_output"`
	MaxSnippetChars int `json:"max_snippet_chars"`
	MaxLLMCalls     int `json:"max_llm_calls"`
}

// RunnerExcerpt is a security-relevant line extracted from agent output.
type RunnerExcerpt struct {
	Reason  string `json:"reason"`
	Content string `json:"content"`
}

// EventSample captures a representative raw event for evidence context.
type EventSample struct {
	Category  string `json:"category"`
	Timestamp string `json:"timestamp"`
	Summary   string `json:"summary"`
	Pid       int32  `json:"pid,omitempty"`
	Comm      string `json:"comm,omitempty"`
}

// ThreatEvidencePackage is kept for backward compatibility with prompt
// collection that shares selection metadata. The two-phase scan/detail
// workflow uses ScanPackage and DetailPackage instead.
type ThreatEvidencePackage struct {
	AnalysisType       string          `json:"analysis_type"`
	RootExecID         string          `json:"root_exec_id"`
	Goal               string          `json:"goal"`
	Selection          map[string]any  `json:"selection,omitempty"`
	Budget             EvidenceBudget  `json:"budget"`
	TelemetrySummary   map[string]any  `json:"telemetry_summary"`
	EventSamples       []EventSample   `json:"event_samples,omitempty"`
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

// AgentRunInfo describes one detected agent run in a time window.
type AgentRunInfo struct {
	RootExecID    string    `json:"root_exec_id"`
	Host          string    `json:"host"`
	Timestamp     time.Time `json:"timestamp"`
	EventCount    int       `json:"event_count"`
	AgentProvider string    `json:"agent_provider"`
}

// ThreatSelector controls how the CLI resolves a root_exec_id for threat analysis.
type ThreatSelector struct {
	Latest    bool
	Since     time.Time
	Until     time.Time
	SourceRef string
	AgentType string
}

// --- Two-phase collect types ---

// CollectMode controls the scan/detail phase for threat collection.
type CollectMode string

const (
	CollectModeScan   CollectMode = "scan"
	CollectModeDetail CollectMode = "detail"
)

// DetailFocus specifies which event category to retrieve in detail mode.
type DetailFocus string

const (
	DetailFocusExec      DetailFocus = "exec"
	DetailFocusFileRead  DetailFocus = "file_read"
	DetailFocusFileWrite DetailFocus = "file_write"
	DetailFocusNetwork   DetailFocus = "network"
	DetailFocusHTTP      DetailFocus = "http"
	DetailFocusMCP       DetailFocus = "mcp"
	DetailFocusAll       DetailFocus = "all"
)

// CategoryOverview summarizes one event category in a scan.
type CategoryOverview struct {
	Count    int      `json:"count"`
	TopItems []string `json:"top_items,omitempty"`
}

// ProcessTreeNode is a simplified process tree entry for scan output.
type ProcessTreeNode struct {
	ExecID        string            `json:"exec_id"`
	Pid           int32             `json:"pid"`
	Comm          string            `json:"comm"`
	Args          string            `json:"args,omitempty"`
	ChildCount    int               `json:"child_count"`
	AgentProvider string            `json:"agent_provider,omitempty"`
	Children      []ProcessTreeNode `json:"children,omitempty"`
}

// RedFlag is a single-event pattern match (no temporal correlation needed).
type RedFlag struct {
	PatternID string `json:"pattern_id"` // e.g. "S1_destructive_command"
	Severity  string `json:"severity"`   // CRITICAL | HIGH
	Comm      string `json:"comm"`
	Pid       int32  `json:"pid"`
	Timestamp string `json:"timestamp"`
	Evidence  string `json:"evidence"` // the matched arg/path fragment
	Reason    string `json:"reason"`   // human-readable explanation
}

// SuspiciousSequence is a cross-category temporal correlation within a time window.
type SuspiciousSequence struct {
	PatternID string      `json:"pattern_id"` // e.g. "T1_sensitive_read_then_exfil"
	Severity  string      `json:"severity"`   // CRITICAL | HIGH
	DeltaMs   int64       `json:"delta_ms"`   // elapsed time between trigger and follower
	Trigger   EventSample `json:"trigger"`
	Follower  EventSample `json:"follower"`
	Reason    string      `json:"reason"`
}

// ScanPackage is the phase-1 output: a compact overview of an agent run.
type ScanPackage struct {
	AnalysisType        string                       `json:"analysis_type"`
	RootExecID          string                       `json:"root_exec_id"`
	Selection           map[string]any               `json:"selection,omitempty"`
	Goal                string                       `json:"goal"`
	TelemetrySummary    map[string]any               `json:"telemetry_summary"`
	EventOverview       map[string]*CategoryOverview `json:"event_overview"`
	ProcessTree         []ProcessTreeNode            `json:"process_tree"`
	RedFlags            []RedFlag                    `json:"red_flags,omitempty"`
	SuspiciousSequences []SuspiciousSequence         `json:"suspicious_sequences,omitempty"`
	RunnerExcerpts      []RunnerExcerpt              `json:"runner_output_excerpts,omitempty"`
	Notes               []string                     `json:"notes"`
}

// DetailPackage is the phase-2 output: raw events for a focused category.
type DetailPackage struct {
	AnalysisType string         `json:"analysis_type"`
	RootExecID   string         `json:"root_exec_id"`
	Focus        string         `json:"focus"`
	Filter       string         `json:"filter,omitempty"`
	Selection    map[string]any `json:"selection,omitempty"`
	TotalEvents  int            `json:"total_events"`
	ShownEvents  int            `json:"shown_events"`
	Events       []EventSample  `json:"events"`
	Notes        []string       `json:"notes"`
}
