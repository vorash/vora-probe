// Package deliver posts an incident's report to chat.
//
// What gets posted, where, and under which label is decided here, by code, from
// the report and the alert: never by a model. The message keeps what makes a
// Probe report worth reading in a channel: the leading claim with its evidence,
// the claims that were refused and what they were narrowed to, and the evidence
// that was missing. Delivery is idempotent and never fails an investigation:
// the report is on disk before anything is posted.
package deliver

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/vorash/vora-probe/internal/intake"
	"github.com/vorash/vora-probe/investigation"
)

// Channels are the destinations routing chooses between.
type Channels struct {
	Default string
	// Critical, when set, receives incidents whose alert is critical.
	Critical string
}

// Route is where a report goes and how it is labelled.
type Route struct {
	Channel string
	Label   string
}

// RouteFor decides the destination and label from the run's outcome and the
// alert's severity. report is nil when the run produced none.
func RouteFor(ch Channels, r intake.Record, report *investigation.Report) Route {
	channel := ch.Default
	if strings.EqualFold(r.Severity, "critical") && ch.Critical != "" {
		channel = ch.Critical
	}
	l := label(r, report)
	if r.Forecast != nil {
		// A forecast is about the future; the label says so before anyone
		// reads it as something that happened.
		l = "forecast · " + l
	}
	return Route{Channel: channel, Label: l}
}

func label(r intake.Record, report *investigation.Report) string {
	switch {
	case report == nil:
		return "no report"
	case !report.Concluded():
		return "not concluded (" + string(report.Run.Status) + ")"
	case report.Leading == nil || !report.Leading.Allowed || report.Leading.Kind == investigation.ClaimUnknownCause:
		return "inconclusive"
	default:
		return "finding: " + string(report.Leading.Kind)
	}
}

// Message is one chat message: blocks for display, text as the fallback and
// notification preview.
type Message struct {
	Channel  string  `json:"channel"`
	Text     string  `json:"text"`
	Blocks   []Block `json:"blocks,omitempty"`
	ThreadTS string  `json:"thread_ts,omitempty"`
}

// Block is the subset of Block Kit the messages use.
type Block struct {
	Type     string  `json:"type"`
	Text     *Text   `json:"text,omitempty"`
	Elements []*Text `json:"elements,omitempty"`
}

type Text struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Slack's limits, from its Block Kit reference: a header's text is at most 150
// characters, a section's at most 3000, and a message holds at most 50 blocks.
const (
	maxHeader  = 150
	maxSection = 3000
	maxBlocks  = 50
	maxItems   = 20
)

// ReportMessage renders an incident's report. Every string that came from
// outside Probe's code — the alert's labels and text, and the statements built
// from them — is escaped, so an alert summary cannot mention @channel or forge a
// link.
func ReportMessage(route Route, r intake.Record, report *investigation.Report) Message {
	env := r.Incident.Environment
	title := fmt.Sprintf("[%s] %s: %s", env, r.Incident.Service, route.Label)
	var blocks []Block
	blocks = append(blocks, header(title))
	meta := []string{
		"incident `" + escape(r.Incident.ID) + "`",
		"environment *" + escape(env) + "*",
	}
	if r.Alertname != "" {
		meta = append(meta, "alert "+escape(r.Alertname))
	}
	if r.Severity != "" {
		meta = append(meta, "severity "+escape(r.Severity))
	}
	if report != nil {
		meta = append(meta, fmt.Sprintf("run `%s` %s", escape(report.Run.ID), report.Run.Status))
	}
	blocks = append(blocks, contextBlock(strings.Join(meta, " · ")))
	blocks = append(blocks, section("*Symptom*\n"+escape(r.Incident.Symptom)))

	switch {
	case report == nil:
		blocks = append(blocks, section("*No report.* The investigation could not produce one: "+
			escape(r.Investigation.Reason)+"\nNothing is concluded and nothing is recommended."))
	case !report.Concluded():
		blocks = append(blocks, section(fmt.Sprintf("*Not concluded.* The run ended as %s: %s\nNo finding is drawn from partial evidence, and nothing is recommended.",
			report.Run.Status, escape(report.Run.Reason))))
	default:
		blocks = append(blocks, leading(report))
		if refused := refusedClaims(report); refused != "" {
			blocks = append(blocks, section("*Refused claims*\n"+refused))
		}
		blocks = append(blocks, recommendation(report))
	}
	if report != nil {
		if gaps := coverageGaps(report); gaps != "" {
			blocks = append(blocks, section("*Missing evidence*\n"+gaps))
		}
	}
	if r.Forecast != nil && r.Forecast.Revisions > 0 && r.Forecast.Closed == "" {
		blocks = append(blocks, section("*Latest forecast*\n"+escape(r.Forecast.Current.Statement())))
	}
	switch {
	case r.Forecast != nil && r.Forecast.Closed != "":
		blocks = append(blocks, contextBlock(escape(closure(r))))
	case r.Alert == intake.AlertResolved && r.ResolvedAt != nil:
		blocks = append(blocks, contextBlock("The alert has since resolved ("+r.ResolvedAt.UTC().Format("2006-01-02 15:04:05Z")+")."))
	}
	if r.Investigation.Report != "" {
		blocks = append(blocks, contextBlock("report: `"+escape(r.Investigation.Report)+"`"))
	}
	if len(blocks) > maxBlocks {
		blocks = blocks[:maxBlocks]
	}
	return Message{Channel: route.Channel, Text: escape(title), Blocks: blocks}
}

// ResolutionMessage is the thread reply for an alert that resolved after its
// report was posted.
func ResolutionMessage(r intake.Record) Message {
	if r.Forecast != nil {
		text := fmt.Sprintf("[%s] %s", escape(r.Incident.Environment), escape(closure(r)))
		return Message{Channel: r.Post.Channel, ThreadTS: r.Post.TS, Text: text}
	}
	at := ""
	if r.ResolvedAt != nil {
		at = " at " + r.ResolvedAt.UTC().Format("2006-01-02 15:04:05Z")
	}
	text := fmt.Sprintf("[%s] The alert for %s resolved%s. The report above is unchanged: a resolution is not evidence of the cause.",
		escape(r.Incident.Environment), escape(r.Incident.Service), at)
	return Message{Channel: r.Post.Channel, ThreadTS: r.Post.TS, Text: text}
}

// RevisionMessage is the thread reply for a forecast whose ETA moved.
func RevisionMessage(r intake.Record) Message {
	text := fmt.Sprintf("[%s] Forecast for %s revised: %s.", escape(r.Incident.Environment), escape(r.Incident.Service),
		escape(r.Forecast.Current.Statement()))
	return Message{Channel: r.Post.Channel, ThreadTS: r.Post.TS, Text: text}
}

// closure says how a forecast ended. A withdrawal is not an apology and a
// realization is not a finding: each is what the series did.
func closure(r intake.Record) string {
	at := ""
	if r.Forecast.ClosedAt != nil {
		at = " at " + r.Forecast.ClosedAt.UTC().Format("2006-01-02 15:04:05Z")
	}
	switch r.Forecast.Closed {
	case intake.ForecastRealized:
		return fmt.Sprintf("Forecast for %s realized%s: the working set reached its limit.", r.Incident.Service, at)
	default:
		return fmt.Sprintf("Forecast for %s withdrawn%s: %s. The limit was not reached.", r.Incident.Service, at, r.Forecast.Reason)
	}
}

func leading(report *investigation.Report) Block {
	l := report.Leading
	var b strings.Builder
	fmt.Fprintf(&b, "*Leading finding* `%s`\n%s", l.Kind, escape(l.Statement))
	if l.Narrowed != "" {
		fmt.Fprintf(&b, "\n_Scope:_ %s", escape(l.Narrowed))
	}
	fmt.Fprintf(&b, "\n_Evidence:_ %s", evidenceIDs(l.Evidence))
	return section(b.String())
}

func refusedClaims(report *investigation.Report) string {
	var items []string
	for _, c := range report.Claims {
		if c.Allowed {
			continue
		}
		how := "refused"
		if c.Overclaim {
			how = "refused as an overclaim"
		}
		item := fmt.Sprintf("• `%s` %s", c.Kind, how)
		if len(c.Reasons) > 0 {
			item += ": " + escape(strings.Join(c.Reasons, "; "))
		}
		if c.Narrowed != "" {
			item += "\n   narrowed to: " + escape(c.Narrowed)
		}
		items = append(items, item)
	}
	return list(items)
}

func coverageGaps(report *investigation.Report) string {
	var items []string
	for _, g := range report.CoverageGaps {
		items = append(items, "• "+escape(g.String()))
	}
	return list(items)
}

func recommendation(report *investigation.Report) Block {
	if report.Recommendation == nil {
		return section("*Recommendation*\nNone. The retained evidence does not support one.")
	}
	rec := report.Recommendation
	return section(fmt.Sprintf("*Recommendation* (%s)\n%s", escape(rec.Status), escape(rec.Action)))
}

func evidenceIDs(ids []string) string {
	if len(ids) == 0 {
		return "none"
	}
	quoted := make([]string, 0, len(ids))
	for _, id := range ids {
		quoted = append(quoted, "`"+escape(id)+"`")
	}
	return strings.Join(quoted, ", ")
}

func list(items []string) string {
	if len(items) > maxItems {
		items = append(items[:maxItems], fmt.Sprintf("… and %d more in the report", len(items)-maxItems))
	}
	return strings.Join(items, "\n")
}

func header(s string) Block {
	return Block{Type: "header", Text: &Text{Type: "plain_text", Text: bound(s, maxHeader)}}
}

func section(s string) Block {
	return Block{Type: "section", Text: &Text{Type: "mrkdwn", Text: bound(s, maxSection)}}
}

func contextBlock(s string) Block {
	return Block{Type: "context", Elements: []*Text{{Type: "mrkdwn", Text: bound(s, maxSection)}}}
}

// escape applies Slack's three control-character escapes. Without them, text
// taken from an alert could contain <!channel> or a disguised <url|link>.
func escape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// bound cuts s to at most max characters on a rune boundary, saying so.
func bound(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	const more = "… (truncated; see the report)"
	keep := max - utf8.RuneCountInString(more)
	runes := []rune(s)
	return string(runes[:keep]) + more
}
