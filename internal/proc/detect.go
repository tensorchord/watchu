package proc

import (
	"bufio"
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"syscall"

	"github.com/phuslu/log"

	"github.com/tensorchord/watchu/execve"
	"github.com/tensorchord/watchu/internal/tool"
)

const (
	procExeFormat  = "/proc/%d/exe"
	procMapsFormat = "/proc/%d/maps"
	procRootFormat = "/proc/%d/root/%s"
	procFdFormat   = "/proc/%d/fd/%d"

	// regex
	regexLibSSL = `libssl[0-9a-zA-Z_-]*\.so(\.\d+)*`
)

var patternLibSSL = regexp.MustCompile(regexLibSSL)

type TLSLibType int

const (
	TLSLibOpenSSL TLSLibType = iota
	TLSLibBoringSSL
)

type ProcTLSLib struct {
	Path string
	Type TLSLibType
}

func newOpenSSLLib(path string) ProcTLSLib {
	return ProcTLSLib{
		Path: path,
		Type: TLSLibOpenSSL,
	}
}

func isDefinedTextFunc(sym *elf.Symbol, sections []*elf.Section) bool {
	if sym.Section == elf.SHN_UNDEF {
		return false
	}
	switch elf.ST_BIND(sym.Info) {
	case elf.STB_LOCAL, elf.STB_GLOBAL, elf.STB_WEAK:
	default:
		return false
	}
	symType := elf.ST_TYPE(sym.Info)
	if symType != elf.STT_FUNC && symType != elf.STT_NOTYPE {
		return false
	}
	if int(sym.Section) >= len(sections) {
		return false
	}
	sec := sections[sym.Section]
	if sec == nil {
		return false
	}
	return sec.Flags&elf.SHF_EXECINSTR != 0
}

func findOpenSSLStaticSymbols(filepath string) (bool, error) {
	f, err := elf.Open(filepath)
	if err != nil {
		return false, err
	}
	defer f.Close()

	symbols, err := f.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		log.Error().Err(err).Str("file", filepath).Msg("failed to read symbols")
		return false, err
	}

	for _, sym := range symbols {
		if !isDefinedTextFunc(&sym, f.Sections) {
			continue
		}
		if strings.HasPrefix(sym.Name, "SSL_read") || strings.HasPrefix(sym.Name, "SSL_write") {
			return true, nil
		}
	}
	return false, nil
}

// DetectDynTLSLib detects the TLS lib from the dynamic library load event.
// 1. filepath
// 2. fd -> readlink
// 3. scan maps
func DetectDynTLSLib(dl *execve.DynLib) ([]ProcTLSLib, error) {
	path := fmt.Sprintf(procRootFormat, dl.Proc, dl.Filepath)
	if ok, err := tool.IsFilePath(path); err == nil && ok {
		return []ProcTLSLib{newOpenSSLLib(path)}, nil
	}
	realPath, err := os.Readlink(fmt.Sprintf(procFdFormat, dl.Proc, dl.Fd))
	if err == nil {
		return []ProcTLSLib{newOpenSSLLib(fmt.Sprintf(procRootFormat, dl.Proc, realPath))}, nil
	}

	// scan maps file
	mapsFile := fmt.Sprintf(procMapsFormat, dl.Proc)
	file, err := os.Open(mapsFile)
	if err != nil {
		log.Debug().Err(err).Int32("proc", dl.Proc).Msg("failed to open the maps")
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	seen := make(map[string]struct{})
	var libs []ProcTLSLib
	for scanner.Scan() {
		line := scanner.Bytes()
		if patternLibSSL.Match(line) {
			fields := bytes.Fields(line)
			if len(fields) >= 6 {
				path := fmt.Sprintf(procRootFormat, dl.Proc, fields[5])
				if _, ok := seen[path]; ok {
					continue
				}
				seen[path] = struct{}{}
				libs = append(libs, newOpenSSLLib(path))
			}
		}
	}
	if err := scanner.Err(); err != nil {
		log.Warn().Err(err).Int32("proc", dl.Proc).Msg("failed to scan the maps")
		return nil, err
	}
	return libs, nil
}

func DetectTLSLibType(proc int32) ([]ProcTLSLib, error) {
	path, err := os.Readlink(fmt.Sprintf(procExeFormat, proc))
	if err != nil {
		log.Debug().Err(err).Int32("proc", proc).Msg("failed to find the readlink")
		return nil, err
	}
	absPath := fmt.Sprintf(procRootFormat, proc, path)
	var libs []ProcTLSLib

	isBunBundle, err := isBunBundlePackage(absPath)
	if err != nil {
		log.Debug().Err(err).Msg("failed to detect if the file is bun bundle")
	}
	if isBunBundle {
		libs = append(libs, ProcTLSLib{
			Path: absPath,
			Type: TLSLibBoringSSL,
		})
	} else if hasOpenSSL, err := findOpenSSLStaticSymbols(absPath); err == nil && hasOpenSSL {
		libs = append(libs, newOpenSSLLib(absPath))
	}

	return libs, nil
}

type LibKey struct {
	DeviceID uint64
	INode    uint64
}

func FindLibKey(path string) (*LibKey, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat libssl path: %w", err)
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("failed to get stat_t for libssl path")
	}
	key := LibKey{
		DeviceID: stat.Dev,
		INode:    stat.Ino,
	}
	return &key, nil
}
