package tui

import (
	"bytes"
	"context"
	"io"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func waitForStream(stream <-chan tea.Msg) tea.Cmd {
	return func() tea.Msg {
		msg, ok := <-stream
		if !ok {
			return streamClosedMsg{}
		}
		return msg
	}
}

func streamFile(ctx context.Context, path string, out chan<- tea.Msg) {
	defer close(out)

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	var offset int64
	var partial []byte

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			size, err := fileSize(path)
			if err != nil {
				if !os.IsNotExist(err) && !sendStreamMsg(ctx, out, tailErrMsg{err: err}) {
					return
				}
				continue
			}
			if size < offset {
				offset = 0
				partial = nil
			}
			if size == offset {
				continue
			}

			chunk, err := readChunk(path, offset)
			if err != nil {
				if !sendStreamMsg(ctx, out, tailErrMsg{err: err}) {
					return
				}
				continue
			}
			offset += int64(len(chunk))

			buf := make([]byte, 0, len(partial)+len(chunk))
			buf = append(buf, partial...)
			buf = append(buf, chunk...)
			lines := bytes.Split(buf, []byte{'\n'})
			if len(lines) == 0 {
				continue
			}
			partial = bytes.Clone(lines[len(lines)-1])

			records := make([]displayRecord, 0, len(lines)-1)
			for _, line := range lines[:len(lines)-1] {
				line = bytes.TrimSpace(line)
				if len(line) == 0 {
					continue
				}
				record, err := parseJSONLRecord(line)
				if err != nil {
					if !sendStreamMsg(ctx, out, tailErrMsg{err: err}) {
						return
					}
					continue
				}
				records = append(records, record)
			}
			if len(records) > 0 && !sendStreamMsg(ctx, out, batchMsg{records: records}) {
				return
			}
		}
	}
}

func sendStreamMsg(ctx context.Context, out chan<- tea.Msg, msg tea.Msg) bool {
	select {
	case <-ctx.Done():
		return false
	case out <- msg:
		return true
	}
}

func fileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

func readChunk(path string, offset int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if _, err := file.Seek(offset, 0); err != nil {
		return nil, err
	}
	return io.ReadAll(file)
}
