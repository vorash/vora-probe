package gateway

import (
	"fmt"
	"time"
)

// FixtureGateway answers requests from recorded evidence. It is the second
// implementation of the same port the live adapter will implement, which is what
// lets the whole loop run offline without a special case anywhere else.
//
// A request with no recorded answer does not fail the run and does not silently
// disappear: it returns an explicit unavailable answer, which the investigation
// turns into a coverage gap.
type FixtureGateway struct {
	policy   Policy
	index    map[string]Response
	now      func() time.Time
	executed int
}

func NewFixtureGateway(policy Policy, recorded []Recorded, now func() time.Time) (*FixtureGateway, error) {
	if now == nil {
		now = time.Now
	}
	g := &FixtureGateway{policy: policy, index: make(map[string]Response, len(recorded)), now: now}
	for i, r := range recorded {
		if err := policy.Authorize(r.Action); err != nil {
			return nil, fmt.Errorf("recorded evidence %d: %w", i, err)
		}
		if err := r.Response.Validate(); err != nil {
			return nil, fmt.Errorf("recorded evidence %d (%s): %w", i, r.Action.Key(), err)
		}
		key := r.Action.Key()
		if _, dup := g.index[key]; dup {
			return nil, fmt.Errorf("recorded evidence %d: duplicate request %s", i, key)
		}
		g.index[key] = r.Response
	}
	return g, nil
}

// Execute returns the recorded answer, or an explicit unavailable answer when
// none was recorded.
func (g *FixtureGateway) Execute(a Action) (Response, error) {
	if err := g.policy.Authorize(a); err != nil {
		return Response{}, err
	}
	g.executed++
	if r, ok := g.index[a.Key()]; ok {
		return RedactResponse(r), nil
	}
	return Response{
		SchemaVersion: SchemaVersion,
		Kind:          a.Kind,
		Entity:        a.Entity,
		Status:        StatusUnavailable,
		Completeness:  Unavailable,
		RetrievedAt:   g.now().UTC(),
		Query:         QueryMeta{Datasource: "fixture", Query: a.Key(), Params: paramsFor(a), Resolution: a.Resolution},
		Reason:        "no recorded evidence for this request",
		Digest:        Digest(nil),
	}, nil
}

// Executed is how many requests the gateway served, for budget accounting.
func (g *FixtureGateway) Executed() int { return g.executed }

func paramsFor(a Action) map[string]string {
	if a.Metric == "" {
		return nil
	}
	return map[string]string{"metric": a.Metric}
}
