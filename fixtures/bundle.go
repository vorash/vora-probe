// Package fixtures loads the frozen evidence bundles Probe is evaluated
// against, and verifies their integrity.
//
// A bundle contains everything the engine is allowed to see: the incident, the
// recorded planner turns and the recorded infrastructure answers. Ground truth
// lives in a separate file and is loaded only by the evaluation harness, so it
// cannot reach the planner or the evaluators through this package.
//
// Payloads are frozen by content digest. Editing a payload without re-signing it
// fails verification, which is what stops a fixture from drifting silently.
package fixtures

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/vorash/vora-probe/gateway"
	"github.com/vorash/vora-probe/investigation"
)

// PlannerTurn is one recorded planner response.
type PlannerTurn struct {
	Hypotheses []PlannerHypothesis `json:"hypotheses"`
	NextAction *gateway.Action     `json:"next_action,omitempty"`
	Reason     string              `json:"reason"`
}

type PlannerHypothesis struct {
	Statement      string   `json:"statement"`
	FaultDomain    string   `json:"fault_domain"`
	ClaimKind      string   `json:"claim_kind"`
	EvidenceNeeded []string `json:"evidence_needed,omitempty"`
}

type Bundle struct {
	SchemaVersion string                 `json:"schema_version"`
	Case          string                 `json:"case"`
	Description   string                 `json:"description"`
	Incident      investigation.Incident `json:"incident"`
	Planner       []PlannerTurn          `json:"planner"`
	Evidence      []gateway.Recorded     `json:"evidence"`
}

type GroundTruth struct {
	SchemaVersion string   `json:"schema_version"`
	Case          string   `json:"case"`
	Notes         string   `json:"notes"`
	Expected      Expected `json:"expected"`
}

// Expected is the hidden answer key for one case.
type Expected struct {
	FaultDomain              string   `json:"fault_domain"`
	LeadingClaim             string   `json:"leading_claim"`
	CauseAsserted            bool     `json:"cause_asserted"`
	AllowedClaims            []string `json:"allowed_claims"`
	ForbiddenClaims          []string `json:"forbidden_claims"`
	RequiredObservationTypes []string `json:"required_observation_types"`
	RequiredGapActions       []string `json:"required_gap_actions,omitempty"`
	RecommendationExecuted   bool     `json:"recommendation_executed"`
}

// Root is the fixture data directory, resolved from this source file.
//
// The loader is an importable package but the data is not: it stays under
// test/fixtures/ in the repository. Root is therefore a convenience for tests and
// in-repo development only. Anything outside this repository passes an explicit
// path, which every loader function accepts.
func Root() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "test/fixtures"
	}
	return filepath.Join(filepath.Dir(file), "..", "test", "fixtures")
}

// IncidentClasses are the incident fixture sets under Root, one directory each.
// A class ships only with its refusal cases, so every one is held to the same
// integrity checks and the same answer keys.
var IncidentClasses = []string{"oom", "crashloop"}

// AllCases lists every incident fixture case across the classes, sorted.
func AllCases(root string) ([]string, error) {
	var out []string
	for _, class := range IncidentClasses {
		dirs, err := Cases(filepath.Join(root, class))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", class, err)
		}
		out = append(out, dirs...)
	}
	return out, nil
}

// Cases lists the fixture case directories, sorted.
func Cases(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(root, e.Name(), "bundle.json")); err != nil {
			continue
		}
		out = append(out, filepath.Join(root, e.Name()))
	}
	sort.Strings(out)
	return out, nil
}

func Load(dir string) (Bundle, error) {
	var b Bundle
	if err := readJSON(filepath.Join(dir, "bundle.json"), &b); err != nil {
		return Bundle{}, err
	}
	if want := filepath.Base(dir); b.Case != want {
		return Bundle{}, fmt.Errorf("%s: case %q does not match directory %q", dir, b.Case, want)
	}
	return b, nil
}

// LoadTruth reads the hidden answer key. Only the evaluation harness calls this.
func LoadTruth(dir string) (GroundTruth, error) {
	var g GroundTruth
	if err := readJSON(filepath.Join(dir, "ground-truth.json"), &g); err != nil {
		return GroundTruth{}, err
	}
	if want := filepath.Base(dir); g.Case != want {
		return GroundTruth{}, fmt.Errorf("%s: ground truth case %q does not match directory %q", dir, g.Case, want)
	}
	return g, nil
}

func readJSON(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// Verify checks structural integrity, that every recorded request is legal, and
// that every payload still matches its recorded digest.
func Verify(b Bundle) error {
	if b.SchemaVersion != gateway.SchemaVersion {
		return fmt.Errorf("bundle schema_version %q, want %q", b.SchemaVersion, gateway.SchemaVersion)
	}
	if b.Case == "" {
		return fmt.Errorf("bundle case must be set")
	}
	if err := b.Incident.Validate(); err != nil {
		return fmt.Errorf("incident: %w", err)
	}
	if len(b.Planner) < 2 {
		return fmt.Errorf("bundle has %d planner turns; at least 2 are required to exercise a loop", len(b.Planner))
	}
	for i, turn := range b.Planner {
		if len(turn.Hypotheses) < 2 {
			return fmt.Errorf("planner turn %d has %d hypotheses; competing hypotheses are required", i, len(turn.Hypotheses))
		}
		for _, h := range turn.Hypotheses {
			if h.Statement == "" {
				return fmt.Errorf("planner turn %d has a hypothesis without a statement", i)
			}
			if !investigation.FaultDomain(h.FaultDomain).Valid() {
				return fmt.Errorf("planner turn %d: fault domain %q is invalid", i, h.FaultDomain)
			}
			if !investigation.ClaimKind(h.ClaimKind).Valid() {
				return fmt.Errorf("planner turn %d: claim kind %q is invalid", i, h.ClaimKind)
			}
		}
		if turn.NextAction != nil {
			if err := turn.NextAction.Validate(); err != nil {
				return fmt.Errorf("planner turn %d action: %w", i, err)
			}
		}
	}
	if len(b.Evidence) == 0 {
		return fmt.Errorf("bundle has no recorded evidence")
	}
	seen := map[string]bool{}
	for i, p := range b.Evidence {
		if err := p.Action.Validate(); err != nil {
			return fmt.Errorf("evidence %d action: %w", i, err)
		}
		key := p.Action.Key()
		if seen[key] {
			return fmt.Errorf("evidence %d: duplicate action %s", i, key)
		}
		seen[key] = true
		if err := p.Response.Validate(); err != nil {
			return fmt.Errorf("evidence %d (%s) response: %w", i, key, err)
		}
		if p.Response.Kind != p.Action.Kind {
			return fmt.Errorf("evidence %d: response kind %q does not match action kind %q", i, p.Response.Kind, p.Action.Kind)
		}
		if p.Response.Entity != p.Action.Entity {
			return fmt.Errorf("evidence %d: response entity %q does not match action entity %q", i, p.Response.Entity, p.Action.Entity)
		}
	}
	return nil
}

// VerifyTruth checks that the answer key is coherent. A claim cannot be both
// required and forbidden, and the leading claim must be one of the allowed ones.
func VerifyTruth(g GroundTruth) error {
	if g.SchemaVersion != gateway.SchemaVersion {
		return fmt.Errorf("ground truth schema_version %q, want %q", g.SchemaVersion, gateway.SchemaVersion)
	}
	if g.Case == "" {
		return fmt.Errorf("ground truth case must be set")
	}
	if g.Expected.LeadingClaim == "" {
		return fmt.Errorf("ground truth leading_claim must be set")
	}
	if !investigation.ClaimKind(g.Expected.LeadingClaim).Valid() {
		return fmt.Errorf("ground truth leading_claim %q is not a known claim kind", g.Expected.LeadingClaim)
	}
	if len(g.Expected.AllowedClaims) == 0 {
		return fmt.Errorf("ground truth allowed_claims must not be empty")
	}
	allowed := map[string]bool{}
	for _, c := range g.Expected.AllowedClaims {
		if !investigation.ClaimKind(c).Valid() {
			return fmt.Errorf("ground truth allowed claim %q is not a known claim kind", c)
		}
		allowed[c] = true
	}
	for _, c := range g.Expected.ForbiddenClaims {
		if !investigation.ClaimKind(c).Valid() {
			return fmt.Errorf("ground truth forbidden claim %q is not a known claim kind", c)
		}
		if allowed[c] {
			return fmt.Errorf("ground truth claim %q is both allowed and forbidden", c)
		}
	}
	if !allowed[g.Expected.LeadingClaim] {
		return fmt.Errorf("ground truth leading_claim %q is not in allowed_claims", g.Expected.LeadingClaim)
	}
	if g.Expected.RecommendationExecuted {
		return fmt.Errorf("ground truth expects an executed recommendation, which this slice cannot do")
	}
	return nil
}

// Observations normalizes every recorded answer into an observation, assigning
// stable sequential IDs in bundle order.
func (b Bundle) Observations() ([]investigation.Observation, error) {
	ids := investigation.NewIDGen()
	out := make([]investigation.Observation, 0, len(b.Evidence))
	for _, p := range b.Evidence {
		o, err := investigation.ObservationFromResponse(ids.Next(investigation.PrefixObservation), p.Action, p.Response, p.Response.RetrievedAt)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, nil
}

// ByID indexes observations for citations lookup.
func ByID(obs []investigation.Observation) map[string]investigation.Observation {
	out := make(map[string]investigation.Observation, len(obs))
	for _, o := range obs {
		out[o.ID] = o
	}
	return out
}

// Sign recomputes every recorded payload digest. Fixtures are authored with
// payload digests verified by Verify; Sign exists so that an intentional fixture
// change can be re-frozen with `go test ./test/fixtures -update`.
func Sign(b *Bundle) {
	for i := range b.Evidence {
		b.Evidence[i].Response.SchemaVersion = gateway.SchemaVersion
		b.Evidence[i].Response.Digest = gateway.Digest(b.Evidence[i].Response.Payload)
	}
}

func Write(dir string, b Bundle) error {
	raw, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "bundle.json"), append(raw, '\n'), 0o644)
}
