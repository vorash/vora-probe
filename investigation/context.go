package investigation

import (
	"fmt"
	"regexp"
)

// Context packages (vorash/vora-probe#13, P2.3).
//
// A context package is operator-written reference: topology, what normal looks
// like, known quirks. The planner sees the names and descriptions and may read a
// body on demand. The hard line: context is not evidence. It is its own record
// type, never an Observation, so a claim that cites it cites nothing the claims
// policy recognises and is refused like any unretained evidence. It never
// becomes a relation, a fact or a finding.

const (
	ResultContextRequest = "context_request"
	PendingContext       = "context"

	// MaxContextBytes bounds one package body, and maxLoadedContexts how many
	// a run may read, so reference never crowds out evidence in the state.
	MaxContextBytes   = 8 << 10
	maxLoadedContexts = 3
)

// ContextNamePattern is what a package name may be: no path separators, no
// dots, nothing a loader could resolve outside its directory.
var ContextNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ContextSummary is what the planner is told a package is.
type ContextSummary struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Context is a package as read. Unavailable says why a body could not be
// read; the run continues without it.
type Context struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Body        string `json:"body,omitempty"`
	Digest      string `json:"digest,omitempty"`
	Unavailable string `json:"unavailable,omitempty"`
}

// ContextRef is how a report lists a package it consulted: by name and digest,
// apart from the evidence.
type ContextRef struct {
	Name        string `json:"name"`
	Digest      string `json:"digest,omitempty"`
	Unavailable string `json:"unavailable,omitempty"`
}

func inCatalog(env *StepEnvelope, name string) bool {
	for _, c := range env.ContextCatalog {
		if c.Name == name {
			return true
		}
	}
	return false
}

func loaded(env *StepEnvelope, name string) bool {
	for _, c := range env.Contexts {
		if c.Name == name {
			return true
		}
	}
	return false
}

// contextReadError says why a planner's request to read a package is refused,
// or "" when it may proceed.
func contextReadError(env *StepEnvelope, name string) string {
	switch {
	case !inCatalog(env, name):
		return fmt.Sprintf("context package %q is not in the catalog", name)
	case loaded(env, name):
		return fmt.Sprintf("context package %q is already loaded", name)
	case len(env.Contexts) >= maxLoadedContexts:
		return fmt.Sprintf("at most %d context packages may be read in one run", maxLoadedContexts)
	}
	return ""
}

func contextRefs(env *StepEnvelope) []ContextRef {
	out := make([]ContextRef, 0, len(env.Contexts))
	for _, c := range env.Contexts {
		out = append(out, ContextRef{Name: c.Name, Digest: c.Digest, Unavailable: c.Unavailable})
	}
	return out
}
