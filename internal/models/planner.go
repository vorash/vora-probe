// Package models holds the planner and evaluator clients. The planner is a port
// with several implementations: a recorded one that replays frozen turns
// offline, and a live one added in step 3. Holding the planner constant across
// evaluator arms is what makes a comparison between them meaningful.
package models

import (
	"context"
	"errors"

	"github.com/vorash/vora-probe/internal/investigation"
)

// ErrExhausted means the recorded turns ran out. The caller decides what that
// means; it is not silently treated as a normal planner response.
var ErrExhausted = errors.New("recorded planner turns exhausted")

// Planner is the only way the engine reaches a model.
type Planner interface {
	Plan(ctx context.Context, request investigation.ModelRequest) (investigation.ModelResponse, error)
}

// RecordedPlanner replays planner turns frozen in a fixture. It validates
// nothing itself: the engine applies the contract, so a recorded turn that breaks
// it fails the same way a live model would.
type RecordedPlanner struct {
	turns []investigation.ModelResponse
	next  int
}

func NewRecordedPlanner(turns []investigation.ModelResponse) *RecordedPlanner {
	return &RecordedPlanner{turns: turns}
}

func (p *RecordedPlanner) Plan(_ context.Context, _ investigation.ModelRequest) (investigation.ModelResponse, error) {
	if p.next >= len(p.turns) {
		return investigation.ModelResponse{}, ErrExhausted
	}
	turn := p.turns[p.next]
	p.next++
	return turn, nil
}

// Consumed is how many recorded turns were used, so a harness can detect a
// fixture that provides more planning than the engine needed.
func (p *RecordedPlanner) Consumed() int { return p.next }
