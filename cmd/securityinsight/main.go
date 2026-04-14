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
  collect threat    Collect bounded threat evidence for one root execution

Common Options:
  --input string                 JSONL file path or glob pattern (required)
  --format string                Output format: prompt or json (default: prompt)
  --max-events int               Max security events in threat output (default: 50)
  --max-findings-per-kind int    Max static or dynamic findings per kind (default: 20)
  --max-runner-chars int         Max runner output chars in threat output (default: 12000)
  --max-prompt-chars int         Max prompt or HTTP snippet chars per candidate (default: 4000)
  --max-candidates int           Max prompt candidates (default: 25)

Prompt Collection:
  --root-exec-id string          Collect prompt evidence for an explicit root execution ID
  --host string                  Host to analyze (optional, defaults to auto-detect)
  --since string                 Start time in RFC3339 format (required unless --root-exec-id)
  --until string                 End time in RFC3339 format (required unless --root-exec-id)

Threat Collection:
  --root-exec-id string          Collect threat evidence for an explicit root execution ID
  --latest                       Resolve the most recent root execution automatically
  --since string                 Start time in RFC3339 format (required unless --root-exec-id or --latest)
  --until string                 End time in RFC3339 format (required unless --root-exec-id or --latest)
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

func baseCollectOptions(fs *flag.FlagSet) (*string, *string, *int, *int, *int, *int, *int) {
	input := fs.String("input", "", "JSONL file path or glob pattern (required)")
	format := fs.String("format", "prompt", "Output format: prompt or json")
	maxEvents := fs.Int("max-events", 50, "Max security events in threat output")
	maxFindingsPerKind := fs.Int("max-findings-per-kind", 20, "Max findings per kind")
	maxRunnerChars := fs.Int("max-runner-chars", 12000, "Max runner output chars")
	maxPromptChars := fs.Int("max-prompt-chars", 4000, "Max prompt or HTTP snippet chars")
	maxCandidates := fs.Int("max-candidates", 25, "Max prompt candidates")
	return input, format, maxEvents, maxFindingsPerKind, maxRunnerChars, maxPromptChars, maxCandidates
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
	input, format, maxEvents, maxFindingsPerKind, maxRunnerChars, maxPromptChars, maxCandidates := baseCollectOptions(fs)
	rootExecIDRaw := fs.String("root-exec-id", "", "Collect prompt evidence for an explicit root execution ID")
	host := fs.String("host", "", "Host to analyze")
	sinceRaw := fs.String("since", "", "Start time in RFC3339 format")
	untilRaw := fs.String("until", "", "End time in RFC3339 format")
	if err := fs.Parse(args); err != nil {
		exitf("Error parsing flags: %v", err)
	}

	store, tree := loadStore(*input)

	opts := securityinsight.CollectOptions{
		MaxEvents:          *maxEvents,
		MaxFindingsPerKind: *maxFindingsPerKind,
		MaxRunnerChars:     *maxRunnerChars,
		MaxPromptChars:     *maxPromptChars,
		MaxCandidates:      *maxCandidates,
	}

	rootExecID := strings.TrimSpace(*rootExecIDRaw)
	if rootExecID != "" {
		if strings.TrimSpace(*host) != "" || strings.TrimSpace(*sinceRaw) != "" || strings.TrimSpace(*untilRaw) != "" {
			exitf("Error: --root-exec-id is mutually exclusive with --host, --since, and --until")
		}
		pkg, err := securityinsight.CollectPromptEvidenceByRootExecID(store, tree, rootExecID, opts)
		if err != nil {
			exitf("Error collecting prompt evidence: %v", err)
		}
		writeOutput(*format, pkg, securityinsight.RenderPromptEvidencePrompt(pkg))
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
	writeOutput(*format, pkg, securityinsight.RenderPromptEvidencePrompt(pkg))
}

func runCollectThreat(args []string) {
	fs := flag.NewFlagSet("collect threat", flag.ExitOnError)
	input, format, maxEvents, maxFindingsPerKind, maxRunnerChars, maxPromptChars, maxCandidates := baseCollectOptions(fs)
	rootExecIDRaw := fs.String("root-exec-id", "", "Collect threat evidence for an explicit root execution ID")
	latest := fs.Bool("latest", false, "Resolve the most recent root execution automatically")
	sinceRaw := fs.String("since", "", "Start time in RFC3339 format")
	untilRaw := fs.String("until", "", "End time in RFC3339 format")
	if err := fs.Parse(args); err != nil {
		exitf("Error parsing flags: %v", err)
	}

	store, tree := loadStore(*input)

	opts := securityinsight.CollectOptions{
		MaxEvents:          *maxEvents,
		MaxFindingsPerKind: *maxFindingsPerKind,
		MaxRunnerChars:     *maxRunnerChars,
		MaxPromptChars:     *maxPromptChars,
		MaxCandidates:      *maxCandidates,
	}

	rootExecID := strings.TrimSpace(*rootExecIDRaw)
	var selection map[string]any

	if rootExecID != "" {
		if *latest || strings.TrimSpace(*sinceRaw) != "" || strings.TrimSpace(*untilRaw) != "" {
			exitf("Error: --root-exec-id is mutually exclusive with --latest, --since, and --until")
		}
		selection = map[string]any{
			"requested_mode": "explicit_root_exec_id",
			"selection_mode": "explicit_root_exec_id",
			"root_exec_id":   rootExecID,
		}
	} else {
		selector, err := resolveThreatSelector(*latest, *sinceRaw, *untilRaw)
		if err != nil {
			exitf("Error: %v", err)
		}
		var resolvedID string
		resolvedID, selection, err = securityinsight.ResolveThreatRootExecID(store, tree, selector)
		if err != nil {
			exitf("Error resolving threat target: %v", err)
		}
		rootExecID = resolvedID
	}

	pkg, err := securityinsight.CollectThreatEvidence(store, tree, rootExecID, opts)
	if err != nil {
		exitf("Error collecting threat evidence: %v", err)
	}
	pkg.Selection = selection
	writeOutput(*format, pkg, securityinsight.RenderThreatEvidencePrompt(pkg))
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
