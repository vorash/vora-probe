// Package worker is the bounded step protocol.
//
// The controller owns credentials, network and durable state; the worker owns a
// single deterministic transition. A worker invocation reads one state envelope
// and writes exactly one schema-validated request or the final report. It never
// chooses its own executable, URL or command, and it refuses an envelope that
// already exceeds its budget rather than growing it.
package worker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/vorash/vora-probe/investigation"
)

// Step runs one transition on serialized input: the bounded state envelope plus
// the pending result the controller is waiting on.
func Step(engine *investigation.Engine, input []byte, maxEnvelopeBytes, maxResponseBytes int64) ([]byte, error) {
	if int64(len(input)) > maxEnvelopeBytes+maxResponseBytes {
		return nil, fmt.Errorf("worker input of %d bytes exceeds the %d byte state plus %d byte response budget",
			len(input), maxEnvelopeBytes, maxResponseBytes)
	}
	var decoded investigation.WorkerInput
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&decoded); err != nil {
		return nil, fmt.Errorf("worker input is not valid: %w", err)
	}
	stateRaw, err := json.Marshal(decoded.State)
	if err != nil {
		return nil, err
	}
	if int64(len(stateRaw)) > maxEnvelopeBytes {
		return nil, fmt.Errorf("state envelope of %d bytes exceeds the %d byte limit", len(stateRaw), maxEnvelopeBytes)
	}
	if raw, err := json.Marshal(decoded.Pending); err == nil && decoded.Pending != nil && int64(len(raw)) > maxResponseBytes {
		return nil, fmt.Errorf("pending result of %d bytes exceeds the %d byte response limit", len(raw), maxResponseBytes)
	}
	result, err := engine.Step(decoded)
	if err != nil {
		return nil, err
	}
	switch result.Kind {
	case investigation.ResultModelRequest, investigation.ResultInfraRequest, investigation.ResultFinal:
	default:
		return nil, fmt.Errorf("worker produced an unknown result kind %q", result.Kind)
	}
	// The state envelope and the report have different budgets. The report is the
	// run's output artifact and is bound by the response budget, not by the one
	// that keeps the worker's own state small; conflating them would make a
	// detailed report fail the step protocol.
	resultState, err := json.Marshal(result.Envelope)
	if err != nil {
		return nil, err
	}
	if int64(len(resultState)) > maxEnvelopeBytes {
		return nil, fmt.Errorf("step result state of %d bytes exceeds the %d byte limit", len(resultState), maxEnvelopeBytes)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxEnvelopeBytes+maxResponseBytes {
		return nil, fmt.Errorf("step result of %d bytes exceeds the %d byte limit", len(raw), maxEnvelopeBytes+maxResponseBytes)
	}
	return raw, nil
}

// Run is the process-shaped entry point: one input in, one result out. The read
// is bounded, so an oversized input is refused rather than buffered.
func Run(engine *investigation.Engine, in io.Reader, out io.Writer, maxEnvelopeBytes, maxResponseBytes int64) error {
	limit := maxEnvelopeBytes + maxResponseBytes
	raw, err := io.ReadAll(io.LimitReader(in, limit+1))
	if err != nil {
		return err
	}
	if int64(len(raw)) > limit {
		return fmt.Errorf("worker input exceeds the %d byte limit", limit)
	}
	result, err := Step(engine, raw, maxEnvelopeBytes, maxResponseBytes)
	if err != nil {
		return err
	}
	_, err = out.Write(append(result, '\n'))
	return err
}
