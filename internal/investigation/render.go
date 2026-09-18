package investigation

import (
	"fmt"
	"strings"
)

// Markdown renders the report for a human reviewer. It is deliberately
// repetitive about provenance: every claim names its evidence, every refuted
// claim keeps its reasoning, and the execution state is stated rather than
// implied.
func (r Report) Markdown() string {
	var b strings.Builder

	title := r.Incident.ID
	if title == "" {
		title = "investigation"
	}
	fmt.Fprintf(&b, "# Investigation %s\n\n", title)
	fmt.Fprintf(&b, "- environment: %s\n- service: %s\n- symptom: %s\n- window: %s to %s\n- run: %s (attempt %d, %s)\n",
		r.Incident.Environment, r.Incident.Service, r.Incident.Symptom,
		r.Incident.Window.Start.UTC().Format("2006-01-02T15:04:05Z"),
		r.Incident.Window.End.UTC().Format("2006-01-02T15:04:05Z"),
		r.Run.ID, r.Run.Attempt, r.Run.Status)
	fmt.Fprintf(&b, "- evaluator arm: %s (%s)\n", r.Arm, r.ArmVersion)
	fmt.Fprintf(&b, "- budget: %d/%d infrastructure calls, %d/%d model calls, %d steps\n\n",
		r.Run.Used.InfraCalls, r.Run.Budgets.MaxInfraCalls,
		r.Run.Used.ModelCalls, r.Run.Budgets.MaxModelCalls, r.Run.Used.Steps)

	b.WriteString("## Summary\n\n")
	b.WriteString(strings.TrimRight(r.Summary, "\n"))
	b.WriteString("\n\n")

	if r.Impact != "" {
		b.WriteString("## Impact\n\n")
		b.WriteString(r.Impact)
		b.WriteString("\n\n")
	}

	if r.Leading != nil {
		b.WriteString("## Leading finding\n\n")
		fmt.Fprintf(&b, "- claim: `%s`\n- statement: %s\n", r.Leading.Kind, r.Leading.Statement)
		if r.Leading.Narrowed != "" {
			fmt.Fprintf(&b, "- scope: %s\n", r.Leading.Narrowed)
		}
		fmt.Fprintf(&b, "- evidence: %s\n", orNone(r.Leading.Evidence))
		fmt.Fprintf(&b, "- policy: %s\n\n", r.Leading.PolicyVersion)
	}

	if len(r.Supporting) > 0 || len(r.Contradicting) > 0 || len(r.InsufficientContext) > 0 {
		b.WriteString("## Evidence for the leading finding\n\n")
		writeLinks(&b, "Supporting", r.Supporting)
		writeLinks(&b, "Contradicting", r.Contradicting)
		writeLinks(&b, "Insufficient context", r.InsufficientContext)
	}

	if len(r.Claims) > 1 {
		b.WriteString("## Claims considered\n\n")
		for _, c := range r.Claims {
			status := "admissible"
			if !c.Allowed {
				status = "refused"
				if c.Overclaim {
					status = "refused as an overclaim"
				}
			}
			fmt.Fprintf(&b, "### `%s` — %s\n\n", c.Kind, status)
			fmt.Fprintf(&b, "%s\n\n", c.Statement)
			if len(c.Reasons) > 0 {
				for _, reason := range c.Reasons {
					fmt.Fprintf(&b, "- %s\n", reason)
				}
				b.WriteString("\n")
			}
			if c.Narrowed != "" {
				fmt.Fprintf(&b, "Narrowed: %s\n\n", c.Narrowed)
			}
		}
	}

	if len(r.Hypotheses) > 0 {
		b.WriteString("## Hypotheses\n\n")
		b.WriteString("| id | domain | claim | status | supports | contradicts | insufficient |\n")
		b.WriteString("| --- | --- | --- | --- | --- | --- | --- |\n")
		for _, h := range r.Hypotheses {
			fmt.Fprintf(&b, "| %s | %s | `%s` | %s | %d | %d | %d |\n",
				h.Hypothesis.ID, h.Hypothesis.FaultDomain, h.Hypothesis.ClaimKind, h.Hypothesis.Status,
				h.Supports, h.Contradicts, h.Insufficient)
		}
		b.WriteString("\n")
		for _, h := range r.Hypotheses {
			fmt.Fprintf(&b, "#### %s — %s\n\n%s\n\n", h.Hypothesis.ID, h.Hypothesis.Status, h.Hypothesis.Statement)
			fmt.Fprintf(&b, "- supporting: %s\n", linkIDs(h.Supporting))
			fmt.Fprintf(&b, "- contradicting: %s\n", linkIDs(h.Against))
			fmt.Fprintf(&b, "- insufficient context: %s\n\n", linkIDs(h.Missing))
		}
	}

	if len(r.Timeline) > 0 {
		b.WriteString("## Timeline\n\n")
		for _, t := range r.Timeline {
			fmt.Fprintf(&b, "- `%s` %s — %s\n", t.At.UTC().Format("2006-01-02T15:04:05Z"), t.Source, t.Text)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Recommendation\n\n")
	if r.Recommendation == nil {
		b.WriteString("None. The retained evidence does not support a recommendation.\n\n")
	} else {
		fmt.Fprintf(&b, "**%s**\n\n%s\n\nExecution: %s\n\n", r.Recommendation.Action, r.Recommendation.Rationale, r.Recommendation.Status)
	}

	if len(r.Unresolved) > 0 {
		b.WriteString("## Unresolved and missing evidence\n\n")
		for _, u := range r.Unresolved {
			fmt.Fprintf(&b, "- %s\n", u)
		}
		b.WriteString("\n")
	}

	if len(r.Derived) > 0 {
		b.WriteString("## Derived measurements\n\n")
		for _, d := range r.Derived {
			fmt.Fprintf(&b, "- `%s` %s (parents: %s, calc %s)\n", d.ID, d.Statement, orNone(d.Parents), d.CalcVersion)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Evidence index\n\n")
	seen := map[string]bool{}
	for _, group := range [][]EvidenceLink{r.Supporting, r.Contradicting, r.InsufficientContext} {
		for _, l := range group {
			if seen[l.Observation] {
				continue
			}
			seen[l.Observation] = true
			writeEvidenceIndex(&b, l)
		}
	}

	if len(r.EvaluatorCalls) > 0 {
		b.WriteString("## Evaluator calls\n\n")
		b.WriteString("| hypothesis | arm | model | observations | prompt | completion | ms | status |\n")
		b.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- |\n")
		for _, c := range r.EvaluatorCalls {
			fmt.Fprintf(&b, "| %s | %s | %s | %d | %d | %d | %d | %s |\n",
				c.Hypothesis, c.Arm, emptyDash(c.Model), c.Observations,
				c.PromptTokens, c.CompletionTokens, c.LatencyMS, c.Status)
		}
		b.WriteString("\n")
	}

	if len(r.Trace) > 0 {
		b.WriteString("## Call trace\n\n")
		if anyLatency(r.Trace) {
			b.WriteString("| step | kind | target | status | bytes | ms | request digest |\n")
			b.WriteString("| --- | --- | --- | --- | --- | --- | --- |\n")
		} else {
			// Replay latency is not real latency, so the column is omitted rather
			// than filled with zeros that look like measurements.
			b.WriteString("| step | kind | target | status | bytes | request digest |\n")
			b.WriteString("| --- | --- | --- | --- | --- | --- |\n")
		}
		for _, c := range r.Trace {
			target := cell(c.Target)
			if anyLatency(r.Trace) {
				fmt.Fprintf(&b, "| %d | %s | %s | %s | %d | %d | %s |\n",
					c.Step, c.Kind, target, c.Status, c.Bytes, c.DurationMS, shortDigest(c.RequestDigest))
				continue
			}
			fmt.Fprintf(&b, "| %d | %s | %s | %s | %d | %s |\n",
				c.Step, c.Kind, target, c.Status, c.Bytes, shortDigest(c.RequestDigest))
		}
		b.WriteString("\n")
	}

	return b.String()
}

func emptyDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func linkIDs(links []EvidenceLink) string {
	if len(links) == 0 {
		return "none"
	}
	ids := make([]string, 0, len(links))
	for _, l := range links {
		ids = append(ids, "`"+l.Observation+"`")
	}
	return strings.Join(ids, ", ")
}

func writeLinks(b *strings.Builder, heading string, links []EvidenceLink) {
	if len(links) == 0 {
		return
	}
	fmt.Fprintf(b, "### %s\n\n", heading)
	for _, l := range links {
		fmt.Fprintf(b, "- `%s` %s\n", l.Observation, l.Statement)
	}
	b.WriteString("\n")
}

func writeEvidenceIndex(b *strings.Builder, l EvidenceLink) {
	fmt.Fprintf(b, "- `%s` (%s, %s, %s)\n", l.Observation, l.Type, l.Source, l.Completeness)
	fmt.Fprintf(b, "  - query: `%s`", l.Query.Query)
	if l.Query.Datasource != "" {
		fmt.Fprintf(b, " on %s", l.Query.Datasource)
	}
	fmt.Fprintf(b, "\n")
	if l.Window.Start.Equal(l.Window.End) {
		fmt.Fprintf(b, "  - snapshot at %s\n", l.RetrievedAt.UTC().Format("2006-01-02T15:04:05Z"))
	} else {
		fmt.Fprintf(b, "  - window: %s to %s, retrieved %s\n",
			l.Window.Start.UTC().Format("2006-01-02T15:04:05Z"),
			l.Window.End.UTC().Format("2006-01-02T15:04:05Z"),
			l.RetrievedAt.UTC().Format("2006-01-02T15:04:05Z"))
	}
	fmt.Fprintf(b, "  - digest: `%s`\n", l.Digest)
}

// cell escapes a value for a markdown table cell. Evidence targets contain
// pipes, which would otherwise split the row.
func cell(s string) string { return strings.ReplaceAll(s, "|", "\\|") }

func anyLatency(calls []Call) bool {
	for _, c := range calls {
		if c.DurationMS > 0 {
			return true
		}
	}
	return false
}

func orNone(in []string) string {
	if len(in) == 0 {
		return "none"
	}
	return strings.Join(in, ", ")
}

func shortDigest(d string) string {
	if len(d) <= 19 {
		return d
	}
	return d[:19] + "…"
}
