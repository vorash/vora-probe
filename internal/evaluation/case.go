// Package evaluation runs the step-3 comparison.
//
// Two claims are being tested. First, at fixed input: given the same evidence and
// the same hypothesis, how does each arm label the relation? Second, over the
// whole loop: does the choice of arm change the investigation's outcome?
//
// Nothing here produces a statistical claim. With a handful of authored cases the
// honest output is counts, the per-class breakdown, and the variance across
// repeats.
package evaluation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vorash/vora-probe/internal/gateway"
	"github.com/vorash/vora-probe/internal/investigation"
)

// Case is one frozen classification question: a body of evidence, a hypothesis,
// and the label the designated piece of that evidence deserves.
//
// Evidence is a list rather than a single item because real questions need
// context. Asking whether a rollout caused an impact requires both the rollout and
// the impact measurement; asking whether query volume changed requires a baseline.
// Every arm gets the same list, and Target names the item the expected label is
// about.
type Case struct {
	SchemaVersion string             `json:"schema_version"`
	ID            string             `json:"id"`
	Split         string             `json:"split"`
	Rationale     string             `json:"rationale"`
	Entity        string             `json:"entity"`
	Hypothesis    CaseHypothesis     `json:"hypothesis"`
	Evidence      []gateway.Recorded `json:"evidence"`
	// Target is the observation the expected label applies to, named as OBS-000n
	// in the order the evidence appears.
	Target   string `json:"target"`
	Expected string `json:"expected"`
	// Forbidden labels would be an overclaim on this evidence. They are counted
	// separately from plain disagreement: asserting support where none exists is
	// a worse error than declining to decide.
	Forbidden []string `json:"forbidden"`
}

type CaseHypothesis struct {
	Statement   string `json:"statement"`
	FaultDomain string `json:"fault_domain"`
	ClaimKind   string `json:"claim_kind"`
}

const (
	SplitDev     = "dev"
	SplitHeldOut = "held-out"
)

// LoadCases reads every case in a split directory, sorted by file name.
func LoadCases(dir string) ([]Case, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var cases []Case
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var c Case
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&c); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		if want := strings.TrimSuffix(e.Name(), ".json"); c.ID != want {
			return nil, fmt.Errorf("%s: case id %q does not match file name %q", e.Name(), c.ID, want)
		}
		if err := c.Validate(dir); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		cases = append(cases, c)
	}
	sort.Slice(cases, func(i, j int) bool { return cases[i].ID < cases[j].ID })
	if len(cases) == 0 {
		return nil, fmt.Errorf("no cases found in %s", dir)
	}
	return cases, nil
}

// LoadSplits loads the development and held-out splits. Both are required and
// must be disjoint: a held-out case that also appears in development measures
// memorisation rather than labelling.
func LoadSplits(root string) (dev, heldOut []Case, err error) {
	dev, err = LoadCases(filepath.Join(root, SplitDev))
	if err != nil {
		return nil, nil, err
	}
	heldOut, err = LoadCases(filepath.Join(root, SplitHeldOut))
	if err != nil {
		return nil, nil, err
	}
	seen := map[string]string{}
	for _, c := range append(append([]Case{}, dev...), heldOut...) {
		if previous, dup := seen[c.ID]; dup {
			return nil, nil, fmt.Errorf("case %q appears in both the %s and %s splits", c.ID, previous, c.Split)
		}
		seen[c.ID] = c.Split
	}
	return dev, heldOut, nil
}

func (c Case) Validate(dir string) error {
	if c.SchemaVersion != gateway.SchemaVersion {
		return fmt.Errorf("schema_version %q, want %q", c.SchemaVersion, gateway.SchemaVersion)
	}
	if c.ID == "" {
		return fmt.Errorf("id must be set")
	}
	if c.Rationale == "" {
		return fmt.Errorf("a case must record why its expected label is what it is")
	}
	if c.Split != SplitDev && c.Split != SplitHeldOut {
		return fmt.Errorf("split %q is not one of %s or %s", c.Split, SplitDev, SplitHeldOut)
	}
	if filepath.Base(dir) != c.Split {
		return fmt.Errorf("case split %q does not match directory %q", c.Split, filepath.Base(dir))
	}
	if c.Entity == "" {
		return fmt.Errorf("entity must be set")
	}
	if !investigation.ClaimKind(c.Hypothesis.ClaimKind).Valid() {
		return fmt.Errorf("claim kind %q is not known", c.Hypothesis.ClaimKind)
	}
	if !investigation.FaultDomain(c.Hypothesis.FaultDomain).Valid() {
		return fmt.Errorf("fault domain %q is not known", c.Hypothesis.FaultDomain)
	}
	if len(c.Evidence) == 0 {
		return fmt.Errorf("a case needs at least one piece of evidence")
	}
	for i, e := range c.Evidence {
		if err := e.Action.Validate(); err != nil {
			return fmt.Errorf("evidence %d action: %w", i, err)
		}
		if err := e.Response.Validate(); err != nil {
			return fmt.Errorf("evidence %d response: %w", i, err)
		}
	}
	if c.Target == "" {
		return fmt.Errorf("target must name the observation the expected label applies to")
	}
	observations, err := c.Observations()
	if err != nil {
		return err
	}
	found := false
	for _, o := range observations {
		if o.ID == c.Target {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("target %q is not one of the case's observations", c.Target)
	}
	if !validLabel(c.Expected) {
		return fmt.Errorf("expected label %q is not known", c.Expected)
	}
	for _, label := range c.Forbidden {
		if !validLabel(label) {
			return fmt.Errorf("forbidden label %q is not known", label)
		}
		if label == c.Expected {
			return fmt.Errorf("label %q is both expected and forbidden", label)
		}
	}
	return nil
}

// Observations normalizes the case's evidence the same way the loop does,
// numbering it OBS-0001 onwards in evidence order.
func (c Case) Observations() ([]investigation.Observation, error) {
	ids := investigation.NewIDGen()
	out := make([]investigation.Observation, 0, len(c.Evidence))
	for _, e := range c.Evidence {
		response := gateway.RedactResponse(e.Response)
		o, err := investigation.ObservationFromResponse(ids.Next(investigation.PrefixObservation), e.Action, response, response.RetrievedAt)
		if err != nil {
			return nil, fmt.Errorf("normalize evidence: %w", err)
		}
		out = append(out, o)
	}
	return out, nil
}

// Hypothesis materializes the case hypothesis.
func (c Case) AsHypothesis() investigation.Hypothesis {
	return investigation.Hypothesis{
		SchemaVersion: gateway.SchemaVersion,
		ID:            "HYP-0001",
		Statement:     c.Hypothesis.Statement,
		FaultDomain:   investigation.FaultDomain(c.Hypothesis.FaultDomain),
		Status:        investigation.HypothesisProposed,
		ClaimKind:     investigation.ClaimKind(c.Hypothesis.ClaimKind),
		Origin:        "fixture",
	}
}

func validLabel(label string) bool {
	for _, l := range labels {
		if l == label {
			return true
		}
	}
	return false
}

// labels mirrors the closed set in internal/models. It is duplicated deliberately
// so the suite's own integrity check does not depend on the package it evaluates.
var labels = []string{"supports", "contradicts", "neutral", "insufficient_context"}

// CanonicalLabel maps an arm's relationship back to the suite's label vocabulary.
func CanonicalLabel(r investigation.Relationship) string { return string(r) }

// Sign recomputes the recorded payload digests. Payloads are frozen by content
// digest, so editing one without re-freezing it fails validation: a case cannot
// drift silently. Re-freeze with
// `go test ./internal/evaluation -run TestCaseIntegrity -update`.
func Sign(c *Case) {
	for i := range c.Evidence {
		c.Evidence[i].Response.SchemaVersion = gateway.SchemaVersion
		c.Evidence[i].Response.Digest = gateway.Digest(c.Evidence[i].Response.Payload)
	}
}

// WriteCase rewrites a case file, preserving the field order of the struct.
func WriteCase(dir string, c Case) error {
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, c.ID+".json"), append(raw, '\n'), 0o644)
}
