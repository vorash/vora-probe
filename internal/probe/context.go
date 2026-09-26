package probe

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vorash/vora-probe/gateway"
	"github.com/vorash/vora-probe/investigation"
)

// ContextSource is where context packages come from. The controller owns it;
// the worker only ever sees what it returns, through the state.
type ContextSource interface {
	Catalog() ([]investigation.ContextSummary, error)
	Load(name string) investigation.Context
}

// DirContexts serves packages from one directory: each <name>.md, whose first
// line is its description and the rest its body. Loading is bounded to that
// directory, whatever a name, a path or a symlink says.
type DirContexts struct {
	Root string
}

// Catalog lists the directory's packages, sorted. A file whose name is not a
// valid package name is not a package and is left out.
func (d DirContexts) Catalog() ([]investigation.ContextSummary, error) {
	entries, err := os.ReadDir(d.Root)
	if err != nil {
		return nil, err
	}
	var out []investigation.ContextSummary
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".md")
		if !ok || !investigation.ContextNamePattern.MatchString(name) {
			continue
		}
		c := d.Load(name)
		if c.Unavailable != "" {
			continue
		}
		out = append(out, investigation.ContextSummary{Name: name, Description: c.Description})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Load reads one package. A package that cannot be read comes back with the
// reason, and the run continues without it.
func (d DirContexts) Load(name string) investigation.Context {
	c := investigation.Context{Name: name}
	raw, err := d.read(name)
	if err != nil {
		c.Unavailable = err.Error()
		return c
	}
	first, body, _ := strings.Cut(string(raw), "\n")
	c.Description = strings.TrimSpace(strings.TrimLeft(first, "# "))
	// Reference reaches the planner, so it is redacted like any text that
	// does.
	c.Body, _ = gateway.RedactText(strings.TrimSpace(body))
	c.Digest = gateway.Digest(raw)
	return c
}

func (d DirContexts) read(name string) ([]byte, error) {
	if !investigation.ContextNamePattern.MatchString(name) {
		return nil, fmt.Errorf("%q is not a context package name", name)
	}
	root, err := filepath.EvalSymlinks(d.Root)
	if err != nil {
		return nil, fmt.Errorf("context directory: %w", err)
	}
	path, err := filepath.EvalSymlinks(filepath.Join(root, name+".md"))
	if err != nil {
		return nil, fmt.Errorf("context package %q: %w", name, err)
	}
	// The resolved file must still be inside the directory: a symlink that
	// points elsewhere is refused, not followed.
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return nil, fmt.Errorf("context package %q resolves outside the context directory", name)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("context package %q is not a regular file", name)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(bufio.NewReader(f), investigation.MaxContextBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > investigation.MaxContextBytes {
		return nil, fmt.Errorf("context package %q is over the %d byte bound", name, investigation.MaxContextBytes)
	}
	if bytes.IndexByte(raw, 0) >= 0 {
		return nil, errors.New("context package is not text")
	}
	return raw, nil
}
