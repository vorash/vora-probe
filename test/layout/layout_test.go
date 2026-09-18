package layout_test

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Package is the subset of `go list -json` this guard needs.
type Package struct {
	ImportPath string
	Name       string
	Imports    []string
	Standard   bool
}

// TestPublicPackagesDoNotImportInternal keeps the published surface honest.
//
// Everything under internal/ is private by construction: Go refuses to let another
// module import it. Everything else in this module is importable by anyone who
// runs `go get`, so a library package reaching into internal/ would either break
// consumers or leak an unsupported API. Command packages are exempt: nobody
// imports a main package, and the CLI legitimately drives the internals.
func TestPublicPackagesDoNotImportInternal(t *testing.T) {
	packages := list(t)
	for _, p := range packages {
		if p.Name == "main" || p.Standard {
			continue
		}
		if strings.Contains(p.ImportPath, "/internal/") || strings.HasSuffix(p.ImportPath, "/internal") {
			continue
		}
		for _, imported := range p.Imports {
			if strings.Contains(imported, "/internal/") {
				t.Errorf("%s is importable but imports the private package %s", p.ImportPath, imported)
			}
		}
	}
}

// TestExpectedPublicSurface pins the packages a consumer may rely on. Renaming one
// of these is a breaking change, so it should fail here rather than in someone
// else's build.
func TestExpectedPublicSurface(t *testing.T) {
	want := []string{
		"github.com/vorash/vora-probe/evaluation",
		"github.com/vorash/vora-probe/fixtures",
		"github.com/vorash/vora-probe/gateway",
		"github.com/vorash/vora-probe/investigation",
		"github.com/vorash/vora-probe/models",
		"github.com/vorash/vora-probe/worker",
	}
	have := map[string]bool{}
	for _, p := range list(t) {
		have[p.ImportPath] = true
	}
	for _, path := range want {
		if !have[path] {
			t.Errorf("expected the public package %s to exist", path)
		}
	}
}

// TestInternalStaysPrivate asserts the other half: the private packages are still
// private, so the split is a decision rather than an accident.
func TestInternalStaysPrivate(t *testing.T) {
	for _, path := range []string{
		"github.com/vorash/vora-probe/internal/probe",
		"github.com/vorash/vora-probe/internal/store",
	} {
		found := false
		for _, p := range list(t) {
			if p.ImportPath == path {
				found = true
			}
		}
		if !found {
			t.Errorf("expected %s to remain under internal/", path)
		}
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve the module root from this source file")
	}
	return filepath.Join(filepath.Dir(file), "..", "..")
}

func list(t *testing.T) []Package {
	t.Helper()
	// `./...` must be evaluated from the module root: a test's working directory
	// is its own package, which would make this guard inspect almost nothing and
	// pass vacuously.
	cmd := exec.Command("go", "list", "-json", "./...")
	cmd.Dir = moduleRoot(t)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(out)))
	var packages []Package
	for dec.More() {
		var p Package
		if err := dec.Decode(&p); err != nil {
			t.Fatalf("decode go list output: %v", err)
		}
		packages = append(packages, p)
	}
	if len(packages) == 0 {
		t.Fatal("go list returned no packages")
	}
	// Guard against the vacuous pass above: the module has more than one package.
	if len(packages) < 5 {
		t.Fatalf("go list returned only %d packages, which cannot be the whole module: %s",
			len(packages), fmt.Sprint(packages))
	}
	return packages
}
