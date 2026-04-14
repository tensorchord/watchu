package securityinsight

import (
	"fmt"
	"strings"

	"github.com/tensorchord/watchu/export"
)

// HeuristicAlert represents a security-relevant pattern detected in events.
type HeuristicAlert struct {
	AlertType string
	Severity  string
	Reason    string
	Details   map[string]any
}

// RunHeuristics scans filtered events and returns heuristic alerts.
func RunHeuristics(events *FilteredEvents) []HeuristicAlert {
	var alerts []HeuristicAlert
	alerts = append(alerts, detectSuspiciousCommands(events.ExecEvents)...)
	alerts = append(alerts, detectSensitiveFileAccess(events.FileOps)...)
	alerts = append(alerts, detectSuspiciousNetwork(events.TCPConns)...)
	alerts = append(alerts, detectMCPAnomalies(events.StdIO)...)
	alerts = append(alerts, detectSuspiciousHTTP(events.Requests)...)
	return alerts
}

// ToEvidenceItems converts heuristic alerts into EvidenceItem slice.
func HeuristicAlertsToItems(alerts []HeuristicAlert) []EvidenceItem {
	items := make([]EvidenceItem, 0, len(alerts))
	for _, alert := range alerts {
		item := EvidenceItem{
			Source:   "telemetry",
			Severity: alert.Severity,
			Title:    alert.AlertType,
			Metadata: alert.Details,
		}
		if alert.Reason != "" {
			item.Description = alert.Reason
		}
		if item.Severity == "" {
			item.Severity = "info"
		}
		if path, ok := alert.Details["path"].(string); ok && path != "" {
			item.FilePath = path
		}
		if cmd, ok := alert.Details["command"].(string); ok && cmd != "" {
			item.Snippet = trimForBudget(cmd, 320)
		}
		items = append(items, item)
	}
	return items
}

// --- Suspicious command patterns ---

var suspiciousCommandPatterns = []struct {
	keywords []string
	severity string
	reason   string
}{
	{[]string{"curl", "|", "bash"}, "high", "Remote code execution via curl pipe to bash"},
	{[]string{"curl", "|", "sh"}, "high", "Remote code execution via curl pipe to sh"},
	{[]string{"wget", "chmod"}, "high", "Download and make executable"},
	{[]string{"base64", "-d"}, "medium", "Base64 decode (potential obfuscation)"},
	{[]string{"eval"}, "medium", "Dynamic code evaluation"},
	{[]string{"nc", "-e"}, "high", "Netcat with execute (reverse shell indicator)"},
	{[]string{"ncat", "-e"}, "high", "Ncat with execute (reverse shell indicator)"},
	{[]string{"/dev/tcp/"}, "high", "Bash /dev/tcp (reverse shell indicator)"},
	{[]string{"mkfifo"}, "medium", "Named pipe creation (potential reverse shell)"},
	{[]string{"xargs", "rm"}, "medium", "Bulk file deletion"},
	{[]string{"rm", "-rf", "/"}, "critical", "Recursive root deletion"},
	{[]string{"chmod", "777"}, "medium", "World-writable permission"},
	{[]string{"chmod", "+s"}, "high", "Set SUID bit"},
}

func detectSuspiciousCommands(execs []export.RecordExec) []HeuristicAlert {
	var alerts []HeuristicAlert
	for i := range execs {
		rec := &execs[i]
		cmdLine := strings.ToLower(rec.Comm + " " + rec.Args)
		for _, pattern := range suspiciousCommandPatterns {
			if matchAllKeywords(cmdLine, pattern.keywords) {
				alerts = append(alerts, HeuristicAlert{
					AlertType: "suspicious_command",
					Severity:  pattern.severity,
					Reason:    pattern.reason,
					Details: map[string]any{
						"command": trimForBudget(rec.Comm+" "+rec.Args, 320),
						"pid":    rec.Pid,
						"cwd":    rec.Cwd,
					},
				})
				break // one alert per command
			}
		}
	}
	return alerts
}

func matchAllKeywords(text string, keywords []string) bool {
	for _, kw := range keywords {
		if !strings.Contains(text, kw) {
			return false
		}
	}
	return true
}

// --- Sensitive file access ---

var sensitiveFilePaths = []struct {
	prefix   string
	severity string
	reason   string
}{
	{"/etc/passwd", "medium", "Access to /etc/passwd"},
	{"/etc/shadow", "high", "Access to /etc/shadow"},
	{"/etc/sudoers", "high", "Access to sudoers config"},
	{"/.ssh/", "high", "Access to SSH keys or config"},
	{"/.aws/credentials", "high", "Access to AWS credentials"},
	{"/.kube/config", "medium", "Access to Kubernetes config"},
	{"/.env", "medium", "Access to environment file"},
	{"/proc/self/", "low", "Access to /proc/self"},
	{"/.gnupg/", "medium", "Access to GPG keyring"},
	{"/.docker/config.json", "medium", "Access to Docker config"},
}

func detectSensitiveFileAccess(fileOps []export.RecordFileOp) []HeuristicAlert {
	var alerts []HeuristicAlert
	seen := make(map[string]struct{})
	for i := range fileOps {
		rec := &fileOps[i]
		for _, rule := range sensitiveFilePaths {
			if strings.Contains(rec.Path, rule.prefix) {
				key := fmt.Sprintf("%s|%s", rule.prefix, rec.Path)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				alerts = append(alerts, HeuristicAlert{
					AlertType: "sensitive_file_access",
					Severity:  rule.severity,
					Reason:    rule.reason,
					Details: map[string]any{
						"path":      rec.Path,
						"op":        rec.Op,
						"pid":       rec.Pid,
						"comm":      rec.Comm,
						"new_path":  rec.NewPath,
						"timestamp": rec.Timestamp.Format("2006-01-02T15:04:05Z"),
					},
				})
			}
		}
	}
	return alerts
}

// --- Suspicious network connections ---

var suspiciousPorts = map[uint16]string{
	4444: "Common reverse shell port",
	5555: "Common backdoor port",
	6666: "Common backdoor port",
	1337: "Leet port (common in exploits)",
	9001: "Tor hidden service",
}

func detectSuspiciousNetwork(conns []export.RecordTCPConnect) []HeuristicAlert {
	var alerts []HeuristicAlert
	for i := range conns {
		rec := &conns[i]
		if reason, ok := suspiciousPorts[rec.TargetPort]; ok {
			alerts = append(alerts, HeuristicAlert{
				AlertType: "suspicious_network",
				Severity:  "medium",
				Reason:    reason,
				Details: map[string]any{
					"target_addr": rec.TargetAddr,
					"target_port": rec.TargetPort,
					"pid":         rec.Pid,
					"comm":        rec.Comm,
				},
			})
		}
	}
	return alerts
}

// --- MCP anomalies ---

func detectMCPAnomalies(stdio []export.RecordStdIO) []HeuristicAlert {
	var alerts []HeuristicAlert
	for i := range stdio {
		rec := &stdio[i]
		if rec.Error != nil && len(rec.Error) > 2 { // not just "null"
			alerts = append(alerts, HeuristicAlert{
				AlertType: "mcp_error",
				Severity:  "low",
				Reason:    "MCP tool returned an error",
				Details: map[string]any{
					"method":       rec.Method,
					"error":        trimForBudget(string(rec.Error), 200),
					"message_type": rec.MessageType,
				},
			})
		}
	}
	return alerts
}

// --- Suspicious HTTP requests ---

var suspiciousHTTPPatterns = []struct {
	urlPattern string
	severity   string
	reason     string
}{
	{"metadata.google.internal", "high", "Cloud metadata service access (SSRF indicator)"},
	{"169.254.169.254", "high", "Cloud metadata service access (SSRF indicator)"},
	{"metadata.azure.com", "high", "Azure metadata service access (SSRF indicator)"},
	{".onion", "medium", "Tor hidden service access"},
}

func detectSuspiciousHTTP(requests []export.RecordRequest) []HeuristicAlert {
	var alerts []HeuristicAlert
	for i := range requests {
		rec := &requests[i]
		urlLower := strings.ToLower(rec.URL)
		for _, pattern := range suspiciousHTTPPatterns {
			if strings.Contains(urlLower, pattern.urlPattern) {
				alerts = append(alerts, HeuristicAlert{
					AlertType: "suspicious_http_request",
					Severity:  pattern.severity,
					Reason:    pattern.reason,
					Details: map[string]any{
						"url":    trimForBudget(rec.URL, 200),
						"method": rec.Method,
						"pid":    rec.Pid,
						"comm":   rec.Comm,
					},
				})
				break
			}
		}
	}
	return alerts
}
