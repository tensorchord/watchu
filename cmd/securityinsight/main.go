package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tensorchord/watchu/securityinsight"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "collect":
		runCollect(os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown command %q\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Security Insight CLI (open-source)

Usage:
  securityinsight collect <prompt|threat> [options]

Commands:
  collect prompt    Collect bounded prompt-injection evidence from JSONL files
  collect threat    Collect telemetry evidence for agent run analysis

Common Options:
  --input string                 JSONL file path or glob pattern (required)
  --format string                Output format: prompt or json (default: prompt)
  --max-events int               Max events in output (default: 50)
  --max-agent-output int         Max total chars for agent output excerpts (default: 12000)
  --max-snippet-chars int        Max chars per field in each LLM call record (default: 4000)
  --max-llm-calls int            Max LLM API call pairs in output (default: 25)

Prompt Collection:
  --root-exec-id string          Collect prompt evidence for an explicit root execution ID
  --host string                  Host to analyze (optional, defaults to auto-detect)
  --since string                 Start time in RFC3339 format (required unless --root-exec-id)
  --until string                 End time in RFC3339 format (required unless --root-exec-id)

Threat Collection (two-phase):
  --mode string                  Collection mode: scan or detail (default: scan)
  --root-exec-id string          Target root execution ID
  --latest                       Resolve the most recent root execution automatically
  --since string                 Start time in RFC3339 format
  --until string                 End time in RFC3339 format

  Scan mode options:
    (no additional options — produces a compact overview)

  Detail mode options:
    --focus string               Category to deep-dive: exec, file_read, file_write, network, http, mcp, all
    --filter string              Pipe-separated patterns to match (e.g. "curl|wget|chmod")
`)
}

func runCollect(args []string) {
	if len(args) < 1 {
		printUsage()
		os.Exit(1)
	}

	switch args[0] {
	case "prompt":
		runCollectPrompt(args[1:])
	case "threat":
		runCollectThreat(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown collect target %q\n\n", args[0])
		printUsage()
		os.Exit(1)
	}
}

// baseFlags bundles the flag pointers shared between collect sub-commands.
type baseFlags struct {
	input           *string
	format          *string
	maxEvents       *int
	maxAgentOutput  *int
	maxSnippetChars *int
	maxLLMCalls     *int
}

func registerBaseFlags(fs *flag.FlagSet) baseFlags {
	return baseFlags{
		input:           fs.String("input", "", "JSONL file path or glob pattern (required)"),
		format:          fs.String("format", "prompt", "Output format: prompt or json"),
		maxEvents:       fs.Int("max-events", 50, "Max events in output"),
		maxAgentOutput:  fs.Int("max-agent-output", 12000, "Max total chars for agent output excerpts"),
		maxSnippetChars: fs.Int("max-snippet-chars", 4000, "Max chars per field in each LLM call record"),
		maxLLMCalls:     fs.Int("max-llm-calls", 25, "Max LLM API call pairs in output"),
	}
}

func (bf baseFlags) collectOptions() securityinsight.CollectOptions {
	return securityinsight.CollectOptions{
		MaxEvents:       *bf.maxEvents,
		MaxAgentOutput:  *bf.maxAgentOutput,
		MaxSnippetChars: *bf.maxSnippetChars,
		MaxLLMCalls:     *bf.maxLLMCalls,
	}
}

func loadStore(input string) (*securityinsight.EventStore, *securityinsight.ProcessTree) {
	if strings.TrimSpace(input) == "" {
		exitf("Error: --input is required")
	}
	store, malformed, err := securityinsight.LoadEvents(input)
	if err != nil {
		exitf("Error loading JSONL: %v", err)
	}
	if malformed > 0 {
		fmt.Fprintf(os.Stderr, "Warning: %d malformed lines skipped\n", malformed)
	}
	tree := securityinsight.BuildProcessTree(store.ExecEvents)
	return store, tree
}

func runCollectPrompt(args []string) {
	fs := flag.NewFlagSet("collect prompt", flag.ExitOnError)
	bf := registerBaseFlags(fs)
	rootExecIDRaw := fs.String("root-exec-id", "", "Collect prompt evidence for an explicit root execution ID")
	host := fs.String("host", "", "Host to analyze")
	sinceRaw := fs.String("since", "", "Start time in RFC3339 format")
	untilRaw := fs.String("until", "", "End time in RFC3339 format")
	if err := fs.Parse(args); err != nil {
		exitf("Error parsing flags: %v", err)
	}

	store, tree := loadStore(*bf.input)
	opts := bf.collectOptions()

	rootExecID := strings.TrimSpace(*rootExecIDRaw)
	if rootExecID != "" {
		if strings.TrimSpace(*host) != "" || strings.TrimSpace(*sinceRaw) != "" || strings.TrimSpace(*untilRaw) != "" {
			exitf("Error: --root-exec-id is mutually exclusive with --host, --since, and --until")
		}
		pkg, err := securityinsight.CollectPromptEvidenceByRootExecID(store, tree, rootExecID, opts)
		if err != nil {
			exitf("Error collecting prompt evidence: %v", err)
		}
		writeOutput(*bf.format, pkg, securityinsight.RenderPromptEvidencePrompt(pkg))
		return
	}

	since, err := parseRFC3339("since", *sinceRaw)
	if err != nil {
		exitf("Error: %v", err)
	}
	until, err := parseRFC3339("until", *untilRaw)
	if err != nil {
		exitf("Error: %v", err)
	}

	pkg, err := securityinsight.CollectPromptEvidence(store, tree, *host, since, until, opts)
	if err != nil {
		exitf("Error collecting prompt evidence: %v", err)
	}
	writeOutput(*bf.format, pkg, securityinsight.RenderPromptEvidencePrompt(pkg))
}

func runCollectThreat(args []string) {
	fs := flag.NewFlagSet("collect threat", flag.ExitOnError)
	bf := registerBaseFlags(fs)
	mode := fs.String("mode", "scan", "Collection mode: scan or detail")
	focus := fs.String("focus", "", "Detail mode: category to deep-dive (exec, file_read, file_write, network, http, mcp, all)")
	filter := fs.String("filter", "", "Detail mode: pipe-separated patterns to match")
	rootExecIDRaw := fs.String("root-exec-id", "", "Target root execution ID")
	latest := fs.Bool("latest", false, "Resolve the most recent root execution automatically")
	sinceRaw := fs.String("since", "", "Start time in RFC3339 format")
	untilRaw := fs.String("until", "", "End time in RFC3339 format")
	if err := fs.Parse(args); err != nil {
		exitf("Error parsing flags: %v", err)
	}

	collectMode := securityinsight.CollectMode(strings.TrimSpace(*mode))
	switch collectMode {
	case securityinsight.CollectModeScan, securityinsight.CollectModeDetail:
	default:
		exitf("Error: --mode must be 'scan' or 'detail', got %q", *mode)
	}

	if collectMode == securityinsight.CollectModeDetail && strings.TrimSpace(*focus) == "" {
		exitf("Error: --focus is required when --mode=detail")
	}

	store, tree := loadStore(*bf.input)
	opts := bf.collectOptions()

	rootExecID := strings.TrimSpace(*rootExecIDRaw)

	switch collectMode {
	case securityinsight.CollectModeScan:
		runScanMode(store, tree, opts, *bf.format, rootExecID, *latest, *sinceRaw, *untilRaw)
	case securityinsight.CollectModeDetail:
		runDetailMode(store, tree, opts, *bf.format, rootExecID, *latest, *sinceRaw, *untilRaw,
			securityinsight.DetailFocus(strings.TrimSpace(*focus)), strings.TrimSpace(*filter))
	}
}

func runScanMode(
	store *securityinsight.EventStore,
	tree *securityinsight.ProcessTree,
	opts securityinsight.CollectOptions,
	format string,
	rootExecID string,
	latest bool,
	sinceRaw, untilRaw string,
) {
	if rootExecID != "" {
		pkg, err := securityinsight.CollectScan(store, tree, rootExecID, opts)
		if err != nil {
			exitf("Error collecting scan: %v", err)
		}
		writeOutput(format, pkg, securityinsight.RenderScanPrompt(pkg))
		return
	}

	selector, err := resolveThreatSelector(latest, sinceRaw, untilRaw)
	if err != nil {
		exitf("Error: %v", err)
	}

	agentRuns, err := securityinsight.ResolveAllThreatAgentRuns(store, tree, selector)
	if err != nil {
		exitf("Error resolving agent runs: %v", err)
	}

	if len(agentRuns) > 1 {
		writeMultiScanOutput(format, store, tree, opts, agentRuns, selector)
		return
	}

	resolvedID, _, err := securityinsight.ResolveThreatRootExecID(store, tree, selector)
	if err != nil {
		exitf("Error resolving root exec ID: %v", err)
	}

	pkg, err := securityinsight.CollectScan(store, tree, resolvedID, opts)
	if err != nil {
		exitf("Error collecting scan: %v", err)
	}
	writeOutput(format, pkg, securityinsight.RenderScanPrompt(pkg))
}

func runDetailMode(
	store *securityinsight.EventStore,
	tree *securityinsight.ProcessTree,
	opts securityinsight.CollectOptions,
	format string,
	rootExecID string,
	latest bool,
	sinceRaw, untilRaw string,
	focus securityinsight.DetailFocus,
	filter string,
) {
	if rootExecID == "" {
		// Resolve a single root exec ID for detail mode.
		selector, err := resolveThreatSelector(latest, sinceRaw, untilRaw)
		if err != nil {
			exitf("Error: %v", err)
		}
		resolvedID, _, err := securityinsight.ResolveThreatRootExecID(store, tree, selector)
		if err != nil {
			exitf("Error resolving root exec ID: %v", err)
		}
		rootExecID = resolvedID
	}

	pkg, err := securityinsight.CollectDetail(store, tree, rootExecID, focus, filter, opts)
	if err != nil {
		exitf("Error collecting detail: %v", err)
	}
	writeOutput(format, pkg, securityinsight.RenderDetailPrompt(pkg))
}

func resolveThreatSelector(latest bool, sinceRaw, untilRaw string) (securityinsight.ThreatSelector, error) {
	var selector securityinsight.ThreatSelector
	if latest {
		if strings.TrimSpace(sinceRaw) != "" || strings.TrimSpace(untilRaw) != "" {
			return selector, fmt.Errorf("--latest is mutually exclusive with --since and --until")
		}
		selector.Latest = true
		return selector, nil
	}

	since, err := parseRFC3339("since", sinceRaw)
	if err != nil {
		return selector, err
	}
	until, err := parseRFC3339("until", untilRaw)
	if err != nil {
		return selector, err
	}
	selector.Since = since
	selector.Until = until
	return selector, nil
}

func writeOutput(format string, payload any, prompt string) {
	switch securityinsight.OutputFormat(strings.TrimSpace(format)) {
	case securityinsight.OutputFormatJSON:
		out, err := securityinsight.MarshalCollectedJSON(payload)
		if err != nil {
			exitf("Failed to marshal JSON output: %v", err)
		}
		fmt.Println(string(out))
	case securityinsight.OutputFormatPrompt, "":
		fmt.Println(prompt)
	default:
		exitf("Unsupported --format value %q", format)
	}
}

// writeMultiScanOutput collects and outputs a ScanPackage per agent run.
// For prompt format, packages are separated by a visual divider.
// For JSON format, an array of packages is emitted.
func writeMultiScanOutput(
	format string,
	store *securityinsight.EventStore,
	tree *securityinsight.ProcessTree,
	opts securityinsight.CollectOptions,
	runs []securityinsight.AgentRunInfo,
	selector securityinsight.ThreatSelector,
) {
	packages := make([]*securityinsight.ScanPackage, 0, len(runs))
	for i, run := range runs {
		pkg, err := securityinsight.CollectScan(store, tree, run.RootExecID, opts)
		if err != nil {
			exitf("Error collecting scan for run %d (%s): %v", i+1, run.RootExecID, err)
		}
		pkg.Selection = map[string]any{
			"run_index":        i + 1,
			"total_agent_runs": len(runs),
			"agent_provider":   run.AgentProvider,
			"host":             run.Host,
			"event_count":      run.EventCount,
		}
		if !selector.Since.IsZero() {
			pkg.Selection["since"] = selector.Since.Format(time.RFC3339)
		}
		if !selector.Until.IsZero() {
			pkg.Selection["until"] = selector.Until.Format(time.RFC3339)
		}
		packages = append(packages, pkg)
	}

	switch securityinsight.OutputFormat(strings.TrimSpace(format)) {
	case securityinsight.OutputFormatJSON:
		out, err := securityinsight.MarshalCollectedJSON(packages)
		if err != nil {
			exitf("Failed to marshal JSON output: %v", err)
		}
		fmt.Println(string(out))
	case securityinsight.OutputFormatPrompt, "":
		for i, pkg := range packages {
			if i > 0 {
				fmt.Println("\n" + strings.Repeat("=", 72) + "\n")
			}
			fmt.Println(securityinsight.RenderScanPrompt(pkg))
		}
	default:
		exitf("Unsupported --format value %q", format)
	}
}

func parseRFC3339(name, raw string) (time.Time, error) {
	if strings.TrimSpace(raw) == "" {
		return time.Time{}, fmt.Errorf("--%s is required", name)
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse --%s: %w", name, err)
	}
	return parsed, nil
}

func exitf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
