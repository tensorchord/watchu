package proc

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/phuslu/log"

	"github.com/tensorchord/watchu/internal/tool"
)

const (
	procEnvFormat  = "/proc/%d/environ"
	procOriginName = "$ORIGIN"
	ldCacheFile    = "/etc/ld.so.cache"
)

var (
	ldLibraryPathPrefix = []byte("LD_LIBRARY_PATH=")
	ldDefaultDirs       = []string{
		"/lib64",
		"/usr/lib64",
		"/lib",
		"/usr/lib",
	}

	errLibUnResolved            = errors.New("cannot resolve the lib path")
	errLibPathNotFoundInEnv     = errors.New("LD_LIBRARY_PATH not found in the proc env")
	errLibPathNotFoundInRunPath = errors.New("cannot find the lib path from DT_RUNPATH")
	errLibNotFoundInLdCache     = errors.New("cannot find the lib from ld cache")
	errInvalidLdCache           = errors.New("invalid ld cache")
	errNoDefaultLib             = errors.New("no default libs to search")
)

type DynamicLibResolver struct {
	Pid  int32
	Path string
	root string
	seen map[string]struct{}
	libs []ProcTLSLib
}

// This Resolver works like the `ld`:
// - env `LD_LIBRARY_PATH`
// - `DT_RUNPATH` > `DT_RPATH`
// - `/etc/ld.so.cache`
// - `/lib[64]`, `/usr/lib[64]`
func NewDynLibResolver(pid int32, path string) *DynamicLibResolver {
	return &DynamicLibResolver{
		Pid:  pid,
		Path: path,
		root: fmt.Sprintf(procRootFormat, pid, ""),
		seen: make(map[string]struct{}),
	}
}

func (dr *DynamicLibResolver) FindOpenSSL() ([]ProcTLSLib, error) {
	err := dr.search(dr.Path)
	if err != nil {
		log.Debug().Err(err).Msg("failed to resolve OpenSSL dyn libs")
		return nil, err
	}
	return dr.libs, nil
}

func (dr *DynamicLibResolver) search(currentPath string) error {
	_, exist := dr.seen[currentPath]
	if exist {
		return nil
	}
	dr.seen[currentPath] = struct{}{}
	logger := log.Logger{
		Context: log.NewContext(nil).Int32("pid", dr.Pid).Str("path", currentPath).Value(),
	}

	f, err := elf.Open(currentPath)
	if err != nil {
		logger.Debug().Err(err).Msg("failed to open the ELF file")
		return err
	}
	defer f.Close()

	libs, err := f.ImportedLibraries()
	if err != nil {
		logger.Debug().Err(err).Msg("failed to read the imported libs")
		return err
	}

	var finalErr error
	for _, lib := range libs {
		realPath, err := dr.resolvePath(currentPath, lib, f)
		if err != nil {
			logger.Debug().Err(err).Str("lib", lib).Msg("failed to resolve lib")
			finalErr = errors.Join(finalErr, err)
			continue
		}
		if patternLibSSL.MatchString(lib) {
			dr.libs = append(dr.libs, newOpenSSLLib(realPath))
		} else {
			// recursive check the dependencies
			finalErr = errors.Join(finalErr, dr.search(realPath))
		}
	}
	return finalErr
}

func (dr *DynamicLibResolver) resolvePath(path, lib string, elfFile *elf.File) (string, error) {
	if p, err := dr.checkEnv(lib); err == nil {
		return p, nil
	}
	if p, err := dr.checkRunPath(path, lib, elfFile); err == nil {
		return p, nil
	}
	if noDefault, _ := dr.hasNoDefaultLib(elfFile); noDefault {
		return "", errNoDefaultLib
	}
	if p, err := dr.checkLdCache(lib); err == nil {
		return p, nil
	}
	for _, dir := range ldDefaultDirs {
		fullPath := filepath.Join(dr.root, dir, lib)
		if ok, err := tool.IsFilePath(fullPath); err == nil && ok {
			return fullPath, nil
		}
	}
	return "", errLibUnResolved
}

func (dr *DynamicLibResolver) checkEnv(lib string) (string, error) {
	envs, err := os.ReadFile(fmt.Sprintf(procEnvFormat, dr.Pid))
	if err != nil {
		log.Debug().Err(err).Str("lib", lib).Msg("failed to read proc env")
		return "", err
	}
	for env := range bytes.SplitSeq(envs, []byte{0}) {
		if raw, found := bytes.CutPrefix(env, ldLibraryPathPrefix); found {
			for p := range bytes.SplitSeq(raw, []byte(":")) {
				fullPath := filepath.Join(dr.root, string(p), lib)
				if ok, err := tool.IsFilePath(fullPath); ok && err == nil {
					return fullPath, nil
				}
			}
		}
	}
	return "", errLibPathNotFoundInEnv
}

func (dr *DynamicLibResolver) checkRunPath(currentPath, lib string, f *elf.File) (string, error) {
	paths, err := f.DynString(elf.DT_RUNPATH)
	if err != nil {
		log.Debug().Err(err).Str("path", currentPath).Msg("failed to load DT_RUNPATH")
		return "", err
	}
	if len(paths) == 0 {
		paths, err = f.DynString(elf.DT_RPATH)
		if err != nil {
			log.Debug().Err(err).Str("path", currentPath).Msg("failed to load DT_RPATH")
			return "", err
		}
	}

	callerDir := filepath.Dir(currentPath)
	internalPath := strings.TrimPrefix(callerDir, dr.root)
	for _, raw := range paths {
		for p := range strings.SplitSeq(raw, ":") {
			resolved := strings.ReplaceAll(p, procOriginName, internalPath)
			fullPath := filepath.Join(dr.root, resolved, lib)
			if ok, err := tool.IsFilePath(fullPath); err == nil && ok {
				return fullPath, nil
			}
		}
	}
	return "", errLibPathNotFoundInRunPath
}

func (dr *DynamicLibResolver) hasNoDefaultLib(f *elf.File) (bool, error) {
	flags1, err := f.DynValue(elf.DT_FLAGS_1)
	if err != nil {
		log.Debug().Err(err).Str("path", dr.Path).Msg("failed to get the DT_FLAGS_1 value")
		return false, err
	}
	if len(flags1) == 0 {
		return false, nil
	}
	return (flags1[0] & uint64(elf.DF_1_NODEFLIB)) != 0, nil
}

func (dr *DynamicLibResolver) checkLdCache(lib string) (string, error) {
	cache, err := os.ReadFile(filepath.Join(dr.root, ldCacheFile))
	if err != nil {
		log.Debug().Err(err).Int32("pid", dr.Pid).Msg("failed to read ld cache")
		return "", err
	}
	idx := bytes.Index(cache, []byte(lib))
	if idx == -1 {
		return "", errLibNotFoundInLdCache
	}
	pathIdx := bytes.Index(cache[idx:], []byte("/"))
	if pathIdx == -1 {
		return "", errInvalidLdCache
	}
	remind := cache[idx+pathIdx:]
	before, _, _ := bytes.Cut(remind, []byte{0})
	return filepath.Join(dr.root, string(before)), nil
}
