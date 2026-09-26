package probe

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vorash/vora-probe/fixtures"
	"github.com/vorash/vora-probe/investigation"
	"github.com/vorash/vora-probe/models"
)

// A context package is read from its directory and nowhere else: not through a
// crafted name, an absolute path, or a symlink that points out. Each refusal is
// a way reference loading could become a file-read primitive.
func TestAContextPackageIsReadFromItsDirectoryOnly(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "context")
	outside := filepath.Join(base, "outside")
	os.MkdirAll(root, 0o755)
	os.MkdirAll(outside, 0o755)
	os.WriteFile(filepath.Join(root, "topology.md"), []byte("# services and what they call\ncheckout-api calls payments-api; password=hunter2\n"), 0o644)
	os.WriteFile(filepath.Join(outside, "secret.md"), []byte("# not reference\nthe crown jewels\n"), 0o644)
	os.Symlink(filepath.Join(outside, "secret.md"), filepath.Join(root, "escape.md"))
	os.Symlink(filepath.Join(root, "topology.md"), filepath.Join(root, "alias.md"))
	os.MkdirAll(filepath.Join(root, "folder.md"), 0o755)
	os.WriteFile(filepath.Join(root, "huge.md"), []byte("# too big\n"+strings.Repeat("x", investigation.MaxContextBytes)), 0o644)
	d := DirContexts{Root: root}

	c := d.Load("topology")
	if c.Unavailable != "" || c.Description != "services and what they call" || c.Digest == "" {
		t.Fatalf("a valid package did not load: %+v", c)
	}
	if strings.Contains(c.Body, "hunter2") {
		t.Fatal("a secret in a package reached its body")
	}
	if c := d.Load("alias"); c.Unavailable != "" {
		t.Fatalf("a symlink that stays inside the directory was refused: %s", c.Unavailable)
	}
	for _, name := range []string{"escape", "folder", "huge", "../outside/secret", "/etc/passwd", "a/b", "Topology", "", "missing"} {
		if c := d.Load(name); c.Unavailable == "" || strings.Contains(c.Body, "crown jewels") {
			t.Errorf("%q: loaded (%q), want refused", name, c.Body)
		}
	}

	catalog, err := d.Catalog()
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	var names []string
	for _, s := range catalog {
		names = append(names, s.Name)
	}
	if strings.Join(names, ",") != "alias,topology" {
		t.Fatalf("catalog %v, want only the packages that load safely", names)
	}
}

// readingPlanner reads one context package first, then plans from the recorded
// turns, keeping every request it was sent.
type readingPlanner struct {
	recorded *models.RecordedPlanner
	first    investigation.ModelResponse
	asked    bool
	requests []investigation.ModelRequest
}

func (p *readingPlanner) Plan(ctx context.Context, req investigation.ModelRequest) (investigation.ModelResponse, error) {
	p.requests = append(p.requests, req)
	if !p.asked {
		p.asked = true
		return p.first, nil
	}
	return p.recorded.Plan(ctx, req)
}

// A package the planner reads reaches its next request, and is recorded in the
// report apart from the evidence. Nothing is built on it, and a claim that
// cites it cites nothing the policy recognises.
func TestAContextPackageInformsThePlannerAndIsNeverEvidence(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "topology.md"), []byte("# services and what they call\npayment-api is memory-bound by design at peak\n"), 0o644)
	bundle, err := loadBundle(filepath.Join(fixtures.Root(), "oom", "oom-positive"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	engine := defaultEngine()
	gw, err := openFixtureGateway(engine, bundle, wallClock)
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	turns := plannerTurns(bundle)
	first := turns[0]
	first.NextAction, first.ReadContext = nil, "topology"
	planner := &readingPlanner{recorded: models.NewRecordedPlanner(turns), first: first}
	incident := bundle.Incident
	incident.StartedAt = time.Now().UTC()
	result, err := Run(context.Background(), RunOptions{Incident: incident, Engine: engine, OutDir: t.TempDir(),
		Planner: planner, Gateway: gw, Contexts: DirContexts{Root: root}})
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if len(planner.requests) < 2 || len(planner.requests[0].ContextCatalog) != 1 {
		t.Fatalf("the planner was not offered the catalog: %+v", planner.requests[0].ContextCatalog)
	}
	after := planner.requests[1]
	if len(after.Contexts) != 1 || !strings.Contains(after.Contexts[0].Body, "memory-bound by design") {
		t.Fatalf("the package read did not reach the planner's next request: %+v", after.Contexts)
	}
	report := result.Report
	if len(report.Contexts) != 1 || report.Contexts[0].Name != "topology" || report.Contexts[0].Digest == "" {
		t.Fatalf("the report must list the package consulted: %+v", report.Contexts)
	}
	for _, r := range report.Relations {
		if r.Observation == "topology" {
			t.Fatal("a relation was built on reference")
		}
	}
	for _, c := range report.Claims {
		for _, id := range c.Evidence {
			if id == "topology" {
				t.Fatal("a claim cites reference as evidence")
			}
		}
	}
	if !strings.Contains(report.Markdown(), "Context consulted (not evidence)") {
		t.Fatal("the rendered report must set the package apart from the evidence")
	}
	// The read is charged like an evidence request: one more than the
	// gateway served.
	if report.Run.Used.InfraCalls != gw.Executed()+1 {
		t.Fatalf("infra calls = %d, want the %d the gateway served plus the read", report.Run.Used.InfraCalls, gw.Executed())
	}

	v := investigation.DefaultClaimPolicy().Evaluate(investigation.Claim{Kind: investigation.ClaimMemoryLimitTermination,
		Subject: "payment-api", Statement: "s", Evidence: []string{"topology"}}, investigation.Facts{}, map[string]investigation.Observation{})
	if v.Allowed || !strings.Contains(strings.Join(v.Reasons, ";"), "not in the retained evidence set") {
		t.Fatalf("a claim citing reference must be refused as unretained evidence: %+v", v)
	}
}
