package securityinsight

// signals.go — security pattern definitions and detection engine.
//
// Architecture:
//   - All rule tables are package-level var slices of typed structs.
//   - Detection is pure: functions take FilteredEvents and return value types.
//   - flattenTimeline() is the single canonical place that merges event kinds
//     into []timedEvent, ensuring consistent ordering for all temporal rules.

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ────────────────────────────────────────────────────────────────────────────
// Keyword / path sets used by both S-rules and T-rules
// ────────────────────────────────────────────────────────────────────────────

var sensitivePaths = []string{
	"/etc/shadow", "/etc/passwd", "/etc/master.passwd",
	"/etc/sudoers", "/etc/sudoers.d",
	"/.ssh/", "id_rsa", "id_ed25519", "id_ecdsa", ".pem", ".p12", ".pfx",
	".env", ".env.local", ".env.production",
	"openclaw.json", "paired.json",
	"token", "secret", "api_key", "api-key", "credentials", "credential",
	"aws_secret", "aws_access", ".aws/credentials",
	"client_secret", "private_key",
}

// sensitivePathsLower is pre-lowercased for hot-path matching.
var sensitivePathsLower []string

func init() {
	sensitivePathsLower = make([]string, len(sensitivePaths))
	for i, p := range sensitivePaths {
		sensitivePathsLower[i] = strings.ToLower(p)
	}
}

var reconComms = map[string]bool{
	"cat": true, "head": true, "tail": true, "less": true,
	"more": true, "grep": true, "find": true, "locate": true, "strings": true,
}

var exfilComms = map[string]bool{
	"curl": true, "wget": true, "nc": true, "ncat": true, "netcat": true,
	"scp": true, "rsync": true, "aria2c": true, "ftp": true, "sftp": true,
}

var downloadComms = map[string]bool{
	"curl": true, "wget": true, "aria2c": true,
}

var shellComms = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "fish": true, "dash": true,
	"python": true, "python3": true, "ruby": true, "php": true,
	"perl": true, "node": true, "nodejs": true, "deno": true, "bun": true,
}

var persistenceComms = map[string]bool{
	"crontab": true, "useradd": true, "usermod": true, "visudo": true,
	"adduser": true, "passwd": true,
}

var shellRCPaths = []string{
	".bashrc", ".zshrc", ".profile", ".bash_profile",
	".bash_login", ".zprofile", ".zshenv",
}

var authConfigPaths = []string{
	"sshd_config", "authorized_keys", "openclaw.json", "paired.json",
}

// ────────────────────────────────────────────────────────────────────────────
// Pre-compiled regexes for single-event S-rules
// ────────────────────────────────────────────────────────────────────────────

var (
	reDestructive       = regexp.MustCompile(`(?i)(rm\s+(-[a-z]*f[a-z]*\s+)?(-[a-z]*r[a-z]*\s+)?(\/|~|\.\.)|mkfs|dd\s+if=|wipefs|shred\s|find\s.*-delete)`)
	reReverseShell      = regexp.MustCompile(`(?i)(bash\s+-i\s+>&\s*/dev/tcp|/dev/tcp/|nc\s+-e\s+/bin|ncat\s+.*-e\s+|socat\s+.*exec:|socat\s+.*pty)`)
	reCurlPipeShell     = regexp.MustCompile(`(?i)(curl|wget)\s+.*\|\s*(ba)?sh`)
	reBase64Exec        = regexp.MustCompile(`(?i)base64\s+-d.*\|\s*(ba)?sh`)
	reSensitiveChmod    = regexp.MustCompile(`(?i)(openclaw\.json|paired\.json|authorized_keys|sshd_config)`)
	reCredentialInArgs  = regexp.MustCompile(`(?i)(token=|key=|password=|passwd=|secret=|api_key=)`)
	reCommandSubst      = regexp.MustCompile(`\$\(.*\)`)
	reCommandSubstSens  = regexp.MustCompile(`\$\(.*\b(cat|head|tail|grep)\b.*(shadow|passwd|\.ssh|key|token|secret)`)
)

// ────────────────────────────────────────────────────────────────────────────
// timedEvent — unified internal representation for timeline sorting
// ────────────────────────────────────────────────────────────────────────────

type timedEventKind string

const (
	kindExec     timedEventKind = "exec"
	kindFileRead  timedEventKind = "file_read"
	kindFileWrite timedEventKind = "file_write"
	kindTCPConn  timedEventKind = "tcp_connect"
	kindHTTP     timedEventKind = "http_request"
	kindStdIO    timedEventKind = "stdio"
)

type timedEvent struct {
	Kind      timedEventKind
	Timestamp time.Time
	Pid       int32
	Comm      string
	// kind-specific payload (may be empty)
	Path    string // file path for file_read/file_write
	Remote  string // host:port for tcp_connect; URL for http_request
	Method  string // HTTP method
	Args    string // exec args
	Summary string // pre-built human summary
}

func (e timedEvent) toEventSample() EventSample {
	summary := e.Summary
	if summary == "" {
		switch e.Kind {
		case kindExec:
			summary = fmt.Sprintf("%s %s", e.Comm, e.Args)
		case kindFileRead, kindFileWrite:
			summary = fmt.Sprintf("%s %s", e.Kind, e.Path)
		case kindTCPConn:
			summary = fmt.Sprintf("connect→%s", e.Remote)
		case kindHTTP:
			summary = fmt.Sprintf("%s %s", e.Method, e.Remote)
		case kindStdIO:
			summary = fmt.Sprintf("stdio(%s)", e.Comm)
		}
	}
	return EventSample{
		Category:  string(e.Kind),
		Timestamp: e.Timestamp.UTC().Format(time.RFC3339),
		Summary:   summary,
		Pid:       e.Pid,
		Comm:      e.Comm,
	}
}

// ────────────────────────────────────────────────────────────────────────────
// flattenTimeline — single source of truth for merged event ordering
// ────────────────────────────────────────────────────────────────────────────

func flattenTimeline(events *FilteredEvents) []timedEvent {
	var all []timedEvent

	for _, e := range events.ExecEvents {
		all = append(all, timedEvent{
			Kind:      kindExec,
			Timestamp: e.Timestamp,
			Pid:       e.Pid,
			Comm:      e.Comm,
			Args:      e.Args,
			Summary:   fmt.Sprintf("%s %s", e.Comm, trimArg(e.Args, 80)),
		})
	}
	for _, e := range events.FileOps {
		k := kindFileRead
		if e.Create || e.Truncate || e.Append {
			k = kindFileWrite
		}
		all = append(all, timedEvent{
			Kind:      k,
			Timestamp: e.Timestamp,
			Pid:       e.Pid,
			Comm:      e.Comm,
			Path:      e.Path,
			Summary:   fmt.Sprintf("%s %s", k, e.Path),
		})
	}
	for _, e := range events.TCPConns {
		remote := fmt.Sprintf("%s:%d", e.TargetAddr, e.TargetPort)
		all = append(all, timedEvent{
			Kind:      kindTCPConn,
			Timestamp: e.Timestamp,
			Pid:       e.Pid,
			Comm:      e.Comm,
			Remote:    remote,
			Summary:   fmt.Sprintf("connect→%s", remote),
		})
	}
	for _, e := range events.Requests {
		all = append(all, timedEvent{
			Kind:      kindHTTP,
			Timestamp: e.Timestamp,
			Pid:       e.Pid,
			Comm:      e.Comm,
			Method:    e.Method,
			Remote:    e.URL,
			Summary:   fmt.Sprintf("%s %s", e.Method, trimArg(e.URL, 80)),
		})
	}

	sort.Slice(all, func(i, j int) bool {
		return all[i].Timestamp.Before(all[j].Timestamp)
	})
	return all
}

func trimArg(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func hasSensitivePath(s string) bool {
	lower := strings.ToLower(s)
	for _, kw := range sensitivePathsLower {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func isExternalAddr(addr string) bool {
	// loopback / link-local / private ranges → not exfil destination
	if strings.HasPrefix(addr, "127.") ||
		strings.HasPrefix(addr, "::1") ||
		strings.HasPrefix(addr, "169.254.") ||
		strings.HasPrefix(addr, "10.") ||
		is172Private(addr) ||
		strings.HasPrefix(addr, "192.168.") ||
		addr == "localhost" {
		return false
	}
	return true
}

// is172Private checks if addr falls in the RFC 1918 range 172.16.0.0 – 172.31.255.255.
func is172Private(addr string) bool {
	if !strings.HasPrefix(addr, "172.") {
		return false
	}
	// extract second octet
	rest := addr[4:] // after "172."
	dotIdx := strings.IndexByte(rest, '.')
	if dotIdx <= 0 {
		return false
	}
	octet := 0
	for _, ch := range rest[:dotIdx] {
		if ch < '0' || ch > '9' {
			return false
		}
		octet = octet*10 + int(ch-'0')
	}
	return octet >= 16 && octet <= 31
}

// ────────────────────────────────────────────────────────────────────────────
// DetectRedFlags — single-event pattern matching (S1–S10)
// ────────────────────────────────────────────────────────────────────────────

// DetectRedFlags scans exec events and file writes for high-severity single-event patterns.
// Results are deduplicated by (patternID, pid) to avoid noise from short loops.
func DetectRedFlags(events *FilteredEvents) []RedFlag {
	seen := map[string]bool{}
	var out []RedFlag

	add := func(rf RedFlag) {
		key := rf.PatternID + "|" + fmt.Sprint(rf.Pid)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, rf)
	}

	for _, e := range events.ExecEvents {
		args := e.Args
		comm := strings.ToLower(e.Comm)
		ts := e.Timestamp.UTC().Format(time.RFC3339)

		// S1 — destructive command
		if reDestructive.MatchString(args) {
			add(RedFlag{
				PatternID: PatternS1DestructiveCommand,
				Severity:  SeverityCritical,
				Comm:      e.Comm, Pid: e.Pid, Timestamp: ts,
				Evidence: trimArg(args, 120),
				Reason:   "destructive operation pattern (rm -rf / mkfs / dd if= / shred)",
			})
		}

		// S2 — reverse shell
		if reReverseShell.MatchString(args) {
			add(RedFlag{
				PatternID: PatternS2ReverseShell,
				Severity:  SeverityCritical,
				Comm:      e.Comm, Pid: e.Pid, Timestamp: ts,
				Evidence: trimArg(args, 120),
				Reason:   "reverse shell invocation pattern detected in args",
			})
		}

		// S3 — curl/wget pipe to shell
		if reCurlPipeShell.MatchString(args) {
			add(RedFlag{
				PatternID: PatternS3CodeInjectionPipe,
				Severity:  SeverityCritical,
				Comm:      e.Comm, Pid: e.Pid, Timestamp: ts,
				Evidence: trimArg(args, 120),
				Reason:   "curl/wget output piped directly to shell",
			})
		}

		// S4 — base64 decode piped to shell
		if reBase64Exec.MatchString(args) {
			add(RedFlag{
				PatternID: PatternS4Base64DecodeExec,
				Severity:  SeverityCritical,
				Comm:      e.Comm, Pid: e.Pid, Timestamp: ts,
				Evidence: trimArg(args, 120),
				Reason:   "base64-decoded payload piped to shell",
			})
		}

		// S5 — persistence install (crontab / useradd / usermod / visudo)
		if persistenceComms[comm] {
			add(RedFlag{
				PatternID: PatternS5PersistenceInstall,
				Severity:  SeverityHigh,
				Comm:      e.Comm, Pid: e.Pid, Timestamp: ts,
				Evidence: trimArg(args, 120),
				Reason:   "persistence mechanism invoked (" + e.Comm + ")",
			})
		}

		// S6 — systemctl enable/disable (potential systemd hijack)
		if comm == "systemctl" && (strings.Contains(args, "enable") || strings.Contains(args, "disable")) {
			add(RedFlag{
				PatternID: PatternS6SystemdServiceChange,
				Severity:  SeverityHigh,
				Comm:      e.Comm, Pid: e.Pid, Timestamp: ts,
				Evidence: trimArg(args, 120),
				Reason:   "systemd service enabled/disabled by agent",
			})
		}

		// S7 — chmod on sensitive auth files
		if comm == "chmod" && reSensitiveChmod.MatchString(args) {
			add(RedFlag{
				PatternID: PatternS7SensitiveChmod,
				Severity:  SeverityHigh,
				Comm:      e.Comm, Pid: e.Pid, Timestamp: ts,
				Evidence: trimArg(args, 120),
				Reason:   "chmod on sensitive auth/credential file",
			})
		}

		// S8 — credential token leaked in exfil command args
		if exfilComms[comm] && reCredentialInArgs.MatchString(args) {
			add(RedFlag{
				PatternID: PatternS8CredentialInArgs,
				Severity:  SeverityHigh,
				Comm:      e.Comm, Pid: e.Pid, Timestamp: ts,
				Evidence: trimArg(args, 120),
				Reason:   "potential credential/token value passed as CLI argument to network tool",
			})
		}

		// S10 — command substitution embedding sensitive read
		if reCommandSubstSens.MatchString(args) {
			add(RedFlag{
				PatternID: PatternS10CommandSubstSensRead,
				Severity:  SeverityCritical,
				Comm:      e.Comm, Pid: e.Pid, Timestamp: ts,
				Evidence: trimArg(args, 120),
				Reason:   "command substitution reads sensitive file inline",
			})
		}
	}

	// S9 — file write to shell RC paths containing alias override or PATH hijack
	for _, e := range events.FileOps {
		if !(e.Create || e.Truncate || e.Append) {
			continue
		}
		path := strings.ToLower(e.Path)
		for _, rc := range shellRCPaths {
			if strings.HasSuffix(path, rc) {
				ts := e.Timestamp.UTC().Format(time.RFC3339)
				add(RedFlag{
					PatternID: PatternS9ShellRCWrite,
					Severity:  SeverityHigh,
					Comm:      e.Comm, Pid: e.Pid, Timestamp: ts,
					Evidence: e.Path,
					Reason:   "write to shell startup file could establish persistence",
				})
				break
			}
		}
	}

	return out
}

// ────────────────────────────────────────────────────────────────────────────
// DetectSuspiciousSequences — temporal correlation (T1–T9)
// ────────────────────────────────────────────────────────────────────────────

// DetectSuspiciousSequences walks the merged timeline and finds cross-category
// causal pairs within windowDur. At most 5 sequences are returned to preserve
// prompt token budget; the most time-proximate (smallest delta) are preferred.
func DetectSuspiciousSequences(events *FilteredEvents, windowDur time.Duration) []SuspiciousSequence {
	tl := flattenTimeline(events)
	seen := map[string]bool{}
	var out []SuspiciousSequence

	add := func(seq SuspiciousSequence) {
		key := seq.PatternID + "|" + seq.Trigger.Timestamp + "|" + seq.Follower.Timestamp
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, seq)
	}

	const maxWindow = 60 * time.Second

	for i := 0; i < len(tl); i++ {
		trigger := tl[i]

		// Pre-compute trigger-level predicates once per trigger to avoid
		// repeated ToLower / map lookups in the inner loop.
		trigComm := strings.ToLower(trigger.Comm)

		isT1Trigger := trigger.Kind == kindFileRead && hasSensitivePath(trigger.Path)
		isT2Trigger := trigger.Kind == kindExec && reconComms[trigComm] && hasSensitivePath(trigger.Args)
		isT3aTrigger := trigger.Kind == kindExec && downloadComms[trigComm]
		isT3bTrigger := trigger.Kind == kindHTTP && strings.EqualFold(trigger.Method, "GET")
		isT6Trigger := trigger.Kind == kindExec && (persistenceComms[trigComm] ||
			(trigComm == "systemctl" && strings.Contains(trigger.Args, "enable")))
		isT7Trigger := trigger.Kind == kindExec && trigComm == "chmod" &&
			(strings.Contains(trigger.Args, "+x") || strings.Contains(trigger.Args, "7"))

		// T5 trigger: file_write to auth config path
		var isT5Trigger bool
		if trigger.Kind == kindFileWrite {
			path := strings.ToLower(trigger.Path)
			for _, ap := range authConfigPaths {
				if strings.HasSuffix(path, strings.ToLower(ap)) {
					isT5Trigger = true
					break
				}
			}
		}
		isT8Trigger := trigger.Kind == kindFileWrite

		// Skip triggers that cannot match any rule.
		if !(isT1Trigger || isT2Trigger || isT3aTrigger || isT3bTrigger ||
			isT5Trigger || isT6Trigger || isT7Trigger || isT8Trigger) {
			continue
		}

		// Binary-search for the 60s window upper bound to avoid scanning
		// events far beyond any rule's maximum window.
		maxTime := trigger.Timestamp.Add(maxWindow)
		upperJ := sort.Search(len(tl), func(k int) bool {
			return tl[k].Timestamp.After(maxTime)
		})

		for j := i + 1; j < upperJ; j++ {
			follower := tl[j]
			delta := follower.Timestamp.Sub(trigger.Timestamp)

			// T1: sensitive_read_then_exfil (10s window)
			if isT1Trigger && delta <= 10*time.Second {
				if (follower.Kind == kindTCPConn && isExternalAddr(follower.Remote)) ||
					follower.Kind == kindHTTP {
					add(SuspiciousSequence{
						PatternID: PatternT1SensitiveReadThenExfil,
						Severity:  SeverityCritical,
						DeltaMs:   delta.Milliseconds(),
						Trigger:   trigger.toEventSample(),
						Follower:  follower.toEventSample(),
						Reason:    fmt.Sprintf("sensitive file read (%s) followed %.1fs later by network egress", trigger.Path, delta.Seconds()),
					})
				}
			}

			// T2: recon_then_exfil (15s window)
			if isT2Trigger && delta <= 15*time.Second {
				follComm := strings.ToLower(follower.Comm)
				if (follower.Kind == kindExec && exfilComms[follComm]) ||
					(follower.Kind == kindTCPConn && isExternalAddr(follower.Remote)) {
					add(SuspiciousSequence{
						PatternID: PatternT2ReconThenExfil,
						Severity:  SeverityCritical,
						DeltaMs:   delta.Milliseconds(),
						Trigger:   trigger.toEventSample(),
						Follower:  follower.toEventSample(),
						Reason:    fmt.Sprintf("recon of sensitive path (%s) followed %.1fs later by exfil tool", trimArg(trigger.Args, 60), delta.Seconds()),
					})
				}
			}

			// T3: download_then_execute (15s window)
			if isT3aTrigger && delta <= 15*time.Second {
				if follower.Kind == kindExec && shellComms[strings.ToLower(follower.Comm)] {
					add(SuspiciousSequence{
						PatternID: PatternT3DownloadThenExecute,
						Severity:  SeverityHigh,
						DeltaMs:   delta.Milliseconds(),
						Trigger:   trigger.toEventSample(),
						Follower:  follower.toEventSample(),
						Reason:    fmt.Sprintf("download tool (%s) followed %.1fs later by shell/interpreter exec", trigger.Comm, delta.Seconds()),
					})
				}
			}
			if isT3bTrigger && delta <= 15*time.Second {
				if follower.Kind == kindExec && shellComms[strings.ToLower(follower.Comm)] {
					add(SuspiciousSequence{
						PatternID: PatternT3DownloadThenExecute,
						Severity:  SeverityHigh,
						DeltaMs:   delta.Milliseconds(),
						Trigger:   trigger.toEventSample(),
						Follower:  follower.toEventSample(),
						Reason:    fmt.Sprintf("HTTP GET followed %.1fs later by shell/interpreter exec", delta.Seconds()),
					})
				}
			}

			// T5: auth_tamper_then_network (30s window)
			if isT5Trigger && delta <= 30*time.Second {
				if (follower.Kind == kindTCPConn && isExternalAddr(follower.Remote)) ||
					follower.Kind == kindHTTP {
					add(SuspiciousSequence{
						PatternID: PatternT5AuthTamperThenNetwork,
						Severity:  SeverityCritical,
						DeltaMs:   delta.Milliseconds(),
						Trigger:   trigger.toEventSample(),
						Follower:  follower.toEventSample(),
						Reason:    fmt.Sprintf("auth config write (%s) followed %.1fs later by network egress", trigger.Path, delta.Seconds()),
					})
				}
			}

			// T6: persistence_then_download (30s window)
			if isT6Trigger && delta <= 30*time.Second {
				follComm := strings.ToLower(follower.Comm)
				if (follower.Kind == kindExec && downloadComms[follComm]) ||
					follower.Kind == kindHTTP {
					add(SuspiciousSequence{
						PatternID: PatternT6PersistenceThenDownload,
						Severity:  SeverityHigh,
						DeltaMs:   delta.Milliseconds(),
						Trigger:   trigger.toEventSample(),
						Follower:  follower.toEventSample(),
						Reason:    fmt.Sprintf("persistence mechanism (%s) followed %.1fs later by download", trigger.Comm, delta.Seconds()),
					})
				}
			}

			// T7: chmod_then_execute (15s window)
			if isT7Trigger && delta <= 15*time.Second {
				if follower.Kind == kindExec {
					add(SuspiciousSequence{
						PatternID: PatternT7ChmodThenExecute,
						Severity:  SeverityHigh,
						DeltaMs:   delta.Milliseconds(),
						Trigger:   trigger.toEventSample(),
						Follower:  follower.toEventSample(),
						Reason:    fmt.Sprintf("chmod on file followed %.1fs later by exec", delta.Seconds()),
					})
				}
			}

			// T8: file_write_then_execute (15s window)
			if isT8Trigger && delta <= 15*time.Second {
				if follower.Kind == kindExec {
					add(SuspiciousSequence{
						PatternID: PatternT8FileWriteThenExecute,
						Severity:  SeverityHigh,
						DeltaMs:   delta.Milliseconds(),
						Trigger:   trigger.toEventSample(),
						Follower:  follower.toEventSample(),
						Reason:    fmt.Sprintf("file write followed %.1fs later by exec", delta.Seconds()),
					})
				}
			}
		}
	}

	// Sort by severity (CRITICAL first) then by delta ascending
	sort.Slice(out, func(i, j int) bool {
		si, sj := out[i].Severity, out[j].Severity
		if si != sj {
			return si == SeverityCritical // CRITICAL < HIGH in sort order = comes first
		}
		return out[i].DeltaMs < out[j].DeltaMs
	})

	// Cap at 5 to stay within token budget
	if len(out) > 5 {
		out = out[:5]
	}
	return out
}
