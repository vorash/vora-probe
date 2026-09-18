package fixtures

import (
	"flag"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/vorash/vora-probe/investigation"
)

var update = flag.Bool("update", false, "re-freeze fixture payload digests and rewrite bundle.json")

// TestFixtureIntegrity freezes and verifies every bundle. Run with -update after
// intentionally changing a payload.
func TestFixtureIntegrity(t *testing.T) {
	root := filepath.Join(Root(), "oom")
	dirs, err := Cases(root)
	if err != nil {
		t.Fatalf("list cases: %v", err)
	}
	if len(dirs) < 4 {
		t.Fatalf("expected at least the four agreed cases, found %d", len(dirs))
	}
	for _, dir := range dirs {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			b, err := Load(dir)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if *update {
				Sign(&b)
				if err := Write(dir, b); err != nil {
					t.Fatalf("write: %v", err)
				}
			}
			if err := Verify(b); err != nil {
				t.Fatalf("verify: %v", err)
			}
			g, err := LoadTruth(dir)
			if err != nil {
				t.Fatalf("load ground truth: %v", err)
			}
			if err := VerifyTruth(g); err != nil {
				t.Fatalf("verify ground truth: %v", err)
			}
		})
	}
}

// TestFixtureIntegrityCatchesTampering proves the digest check is load-bearing:
// a payload edited without re-freezing must fail.
func TestFixtureIntegrityCatchesTampering(t *testing.T) {
	b, err := Load(filepath.Join(Root(), "oom", "oom-positive"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := Verify(b); err != nil {
		t.Fatalf("baseline fixture should verify: %v", err)
	}
	b.Evidence[0].Response.Payload = []byte(`{"metric":"container_memory_working_set_bytes","unit":"bytes","samples":[]}`)
	err = Verify(b)
	if err == nil {
		t.Fatal("tampered payload verified; fixture integrity is not enforced")
	}
}

// TestGroundTruthIsSeparate proves the engine's inputs do not depend on the
// answer key: a case directory with no ground truth still loads and verifies.
func TestGroundTruthIsSeparate(t *testing.T) {
	src := filepath.Join(Root(), "oom", "oom-positive")
	dst := t.TempDir()
	raw, err := os.ReadFile(filepath.Join(src, "bundle.json"))
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	caseDir := filepath.Join(dst, "oom-positive")
	if err := os.MkdirAll(caseDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(caseDir, "bundle.json"), raw, 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	b, err := Load(caseDir)
	if err != nil {
		t.Fatalf("load without ground truth: %v", err)
	}
	if err := Verify(b); err != nil {
		t.Fatalf("verify without ground truth: %v", err)
	}
}

// TestCaseExpectations is the step-1 acceptance check. It runs the claims policy
// over each case's recorded evidence and asserts that the expected leading claim
// is admissible while every forbidden claim is refused.
func TestCaseExpectations(t *testing.T) {
	root := filepath.Join(Root(), "oom")
	dirs, err := Cases(root)
	if err != nil {
		t.Fatalf("list cases: %v", err)
	}
	policy := investigation.DefaultClaimPolicy()
	for _, dir := range dirs {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			b, err := Load(dir)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			g, err := LoadTruth(dir)
			if err != nil {
				t.Fatalf("load ground truth: %v", err)
			}

			obs, err := b.Observations()
			if err != nil {
				t.Fatalf("normalize: %v", err)
			}
			byID := ByID(obs)
			facts := investigation.BuildFacts(b.Incident.Service, obs)

			assertObservationTypes(t, obs, g.Expected.RequiredObservationTypes)
			assertGaps(t, facts.Gaps, g.Expected.RequiredGapActions)

			cited := allIDs(obs)
			leading := verdict(policy, g.Expected.LeadingClaim, b.Incident.Service, cited, facts, byID)
			if !leading.Allowed {
				t.Errorf("leading claim %s was refused: %v", g.Expected.LeadingClaim, leading.Reasons)
			}
			for _, kind := range g.Expected.ForbiddenClaims {
				v := verdict(policy, kind, b.Incident.Service, cited, facts, byID)
				if v.Allowed {
					t.Errorf("forbidden claim %s was allowed", kind)
				}
				if v.Narrowed == "" {
					t.Errorf("refused claim %s has no narrowed statement to report instead", kind)
				}
			}
			for _, kind := range g.Expected.AllowedClaims {
				v := verdict(policy, kind, b.Incident.Service, cited, facts, byID)
				if !v.Allowed {
					t.Errorf("expected claim %s to be admissible: %v", kind, v.Reasons)
				}
			}
		})
	}
}

func verdict(p investigation.ClaimPolicy, kind, subject string, cited []string, facts investigation.Facts, byID map[string]investigation.Observation) investigation.ClaimVerdict {
	return p.Evaluate(investigation.Claim{
		Kind:      investigation.ClaimKind(kind),
		Subject:   subject,
		Statement: string(kind) + " for " + subject,
		Evidence:  cited,
	}, facts, byID)
}

func allIDs(obs []investigation.Observation) []string {
	out := make([]string, 0, len(obs))
	for _, o := range obs {
		out = append(out, o.ID)
	}
	sort.Strings(out)
	return out
}

func assertObservationTypes(t *testing.T, obs []investigation.Observation, required []string) {
	t.Helper()
	present := map[string]bool{}
	for _, o := range obs {
		present[string(o.Type)] = true
	}
	for _, want := range required {
		if !present[want] {
			t.Errorf("expected an observation of type %s, found none", want)
		}
	}
}

func assertGaps(t *testing.T, gaps []investigation.CoverageGap, required []string) {
	t.Helper()
	present := map[string]bool{}
	for _, g := range gaps {
		present[string(g.Action)] = true
	}
	for _, want := range required {
		if !present[want] {
			t.Errorf("expected a coverage gap for action %s, found none (gaps: %v)", want, gaps)
		}
	}
}
