package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/phuslu/log"

	"github.com/tensorchord/watchu/execve"
	"github.com/tensorchord/watchu/export"
	"github.com/tensorchord/watchu/fileop"
	"github.com/tensorchord/watchu/internal/logger"
	"github.com/tensorchord/watchu/internal/tool"
	"github.com/tensorchord/watchu/otelrecv"
	"github.com/tensorchord/watchu/postgres"
	"github.com/tensorchord/watchu/stdio"
	"github.com/tensorchord/watchu/tcpconn"
	"github.com/tensorchord/watchu/tls"
	"github.com/tensorchord/watchu/tui"
)

const fileOpPolicyExample = `{
	"read":{
		"prefixes":["/etc/"],
		"home_prefixes":[".ssh/"],
		"suffixes":[".pem"]
	},
	"write":{
		"prefixes":["/var/log/"],
		"home_prefixes":[".config/"],
		"suffixes":[".env"]
	}
}`

type CmdConfig struct {
	exportTarget     string
	sslPath          string
	otelAddr         string
	fileOpPolicyPath string
}

func main() {
	debug := flag.Bool("debug", false, "enable debug-level colorful log")
	SSLPath := flag.String("ssl-path", "", "extra user binary path to attach SSL uprobes (optional)")
	exportTarget := flag.String("export", "", "event export target: empty=discard, http[s]://...=gateway, file://...=local jsonl")
	logPath := flag.String("log-path", "", "local log file path; empty=stderr")
	otelAddr := flag.String("otel-addr", "", "OTLP gRPC receiver address, e.g., ':4317' (optional). Enable to capture AI tool telemetry")
	fileOpPolicyPath := flag.String("fileop-policy", "", fmt.Sprintf(`path to fileop match policy config (.json only); empty=built-in. Example: %s`, fileOpPolicyExample))
	enableTUI := flag.Bool("tui", false, "render a terminal dashboard backed by a local JSONL export file; defaults logs to a local file besides to the export file")
	flag.Parse()

	resolvedExportTarget, tuiPath, resolvedLogPath, tempDir, err := resolveRuntimePaths(*exportTarget, *logPath, *enableTUI)
	if err != nil {
		log.Panic().Err(err).Msg("failed to resolve export target")
	}
	if tempDir != "" {
		defer func() {
			if err := os.RemoveAll(tempDir); err != nil {
				log.Error().Err(err).Str("path", tempDir).Msg("failed to remove tui temp dir")
			}
		}()
	}

	logFile, err := logger.SetUpLogger(*debug, resolvedLogPath)
	if err != nil {
		log.Panic().Err(err).Msg("failed to initialize logger")
	}
	if logFile != nil {
		defer func() {
			if err := logFile.Close(); err != nil {
				log.Error().Err(err).Msg("failed to close log file")
			}
		}()
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	cfg := CmdConfig{
		exportTarget:     resolvedExportTarget,
		sslPath:          *SSLPath,
		otelAddr:         *otelAddr,
		fileOpPolicyPath: *fileOpPolicyPath,
	}

	if *enableTUI {
		ErrCh := make(chan error, 1)
		go func() {
			err := run(ctx, cfg)
			if err != nil && !errors.Is(err, context.Canceled) {
				log.Error().Err(err).Msg("watchu stopped")
				cancel()
			}
			ErrCh <- err
		}()

		if err := tui.Run(ctx, tuiPath); err != nil {
			log.Panic().Err(err).Msg("failed to run tui")
		}
		cancel()
		if err := <-ErrCh; err != nil && !errors.Is(err, context.Canceled) {
			log.Panic().Err(err).Msg("watchu exited with error")
		}
		return
	}

	if err := run(ctx, cfg); err != nil && !errors.Is(err, context.Canceled) {
		log.Panic().Err(err).Msg("watchu exited with error")
	}
}

func run(ctx context.Context, cfg CmdConfig) error {
	exporter, err := export.NewExporter(ctx, cfg.exportTarget)
	if err != nil {
		return fmt.Errorf("initialize exporter: %w", err)
	}
	defer func() {
		if err := exporter.Close(); err != nil {
			log.Error().Err(err).Msg("failed to close exporter")
		}
	}()

	if err := tool.InitEBPF(); err != nil {
		return fmt.Errorf("initialize eBPF: %w", err)
	}

	execProbe, err := execve.NewProcExecProbe()
	if err != nil {
		return fmt.Errorf("initialize exec probe: %w", err)
	}
	defer execProbe.Close()
	go execProbe.Start(ctx)
	go execProbe.IngestExecEvents(ctx, exporter)

	sslProbe := tls.NewTLSProbe(execProbe, &cfg.sslPath, exporter)
	defer sslProbe.Close()
	go sslProbe.Start(ctx)

	stdioProbe, err := stdio.NewStdioProbe(exporter)
	if err != nil {
		return fmt.Errorf("initialize stdio probe: %w", err)
	}
	defer stdioProbe.Close()
	go stdioProbe.Start(ctx)

	pgProbe := postgres.NewPostgresProbe(exporter)
	defer pgProbe.Close()
	go pgProbe.Start(ctx)

	tcpConnProbe, err := tcpconn.NewTCPConnProbe(exporter)
	if err != nil {
		return fmt.Errorf("initialize tcpconn probe: %w", err)
	}
	defer tcpConnProbe.Close()
	go tcpConnProbe.Start(ctx)

	fileOpPolicy, err := fileop.LoadPolicy(cfg.fileOpPolicyPath)
	if err != nil {
		return fmt.Errorf("load fileop policy %q: %w", cfg.fileOpPolicyPath, err)
	}

	fileOpProbe, err := fileop.NewFileOpProbe(exporter, fileOpPolicy)
	if err != nil {
		return fmt.Errorf("initialize fileop probe: %w", err)
	}
	defer fileOpProbe.Close()
	go fileOpProbe.Start(ctx)

	var otelReceiver *otelrecv.OTELReceiver
	if len(cfg.otelAddr) > 0 {
		log.Info().Str("addr", cfg.otelAddr).Msg("enable OTEL receiver for AI tool telemetry")
		otelReceiver, err = otelrecv.NewOTELReceiver(ctx, cfg.otelAddr, exporter)
		if err != nil {
			return fmt.Errorf("create OTEL receiver: %w", err)
		}
		defer otelReceiver.Close()
		go otelReceiver.Start(ctx)
	}

	<-ctx.Done()
	return normalizeShutdownCause(context.Cause(ctx))
}

func normalizeShutdownCause(err error) error {
	if isNotifySignalCause(err, syscall.SIGINT, syscall.SIGTERM) {
		return context.Canceled
	}
	return err
}

func isNotifySignalCause(err error, signals ...syscall.Signal) bool {
	if err == nil {
		return false
	}
	for _, sig := range signals {
		if err.Error() == sig.String()+" signal received" {
			return true
		}
	}
	return false
}

func resolveRuntimePaths(target string, logPath string, enableTUI bool) (string, string, string, string, error) {
	if !enableTUI {
		return target, "", logPath, "", nil
	}

	if target == "" {
		path, err := os.MkdirTemp("", "watchu-tui-")
		if err != nil {
			return "", "", "", "", fmt.Errorf("create tui temp dir: %w", err)
		}
		filePath := filepath.Join(path, "events.jsonl")
		if logPath == "" {
			logPath = filepath.Join(path, "watchu.log")
		}
		return "file://" + filePath, filePath, logPath, path, nil
	}

	filePath, err := export.FilePathFromTarget(target)
	if err != nil {
		return "", "", "", "", fmt.Errorf("tui mode requires --export to be a file:// target: %w", err)
	}
	if logPath == "" {
		logPath = filepath.Join(filepath.Dir(filePath), "watchu.log")
	}
	return target, filePath, logPath, "", nil
}
