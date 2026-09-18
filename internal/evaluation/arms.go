package evaluation

import (
	"strings"
	"time"

	"github.com/vorash/vora-probe/internal/investigation"
	"github.com/vorash/vora-probe/internal/models"
)

// ArmSet is the arms a run will use, together with how each was configured.
type ArmSet struct {
	Arms  []Arm
	Infos []ArmInfo
}

// BuildArms assembles the comparison arms from run configuration.
//
// An arm whose endpoint is absent is included as blocked rather than omitted. An
// omitted arm reads as "not interesting"; a blocked arm reads as "not measured",
// which is what actually happened.
func BuildArms(cfg models.Config, transport models.Transport, now func() time.Time) ArmSet {
	set := ArmSet{}

	deterministic := investigation.DeterministicEvaluator{Policy: investigation.DefaultClaimPolicy()}
	set.Arms = append(set.Arms, Arm{Evaluator: deterministic})
	set.Infos = append(set.Infos, ArmInfo{
		Arm: deterministic.Arm(), Version: deterministic.ArmVersion(), Configured: true,
	})

	if cfg.Baseline.Configured() {
		arm := models.BaselineArm{Endpoint: cfg.Baseline, Transport: transport, Now: now, MaxResponseBytes: 1 << 20}
		set.Arms = append(set.Arms, Arm{Evaluator: arm})
		set.Infos = append(set.Infos, ArmInfo{
			Arm: arm.Arm(), Version: arm.ArmVersion(), Model: cfg.Baseline.Model,
			Endpoint: cfg.Baseline.Redacted(), Configured: true,
		})
	} else {
		set.Infos = append(set.Infos, ArmInfo{
			Arm: investigation.BaselineArm, Version: models.BaselinePromptVersion,
			Configured: false, Blocked: "VORA_PROBE_MODEL_BASE_URL is not set",
		})
		set.Arms = append(set.Arms, Arm{
			Evaluator: models.BaselineArm{Endpoint: cfg.Baseline},
			Blocked:   "VORA_PROBE_MODEL_BASE_URL is not set",
		})
	}

	if cfg.Jev.Configured() {
		arm := models.JevArm{Endpoint: cfg.Jev, Transport: transport, Now: now, MaxResponseBytes: 1 << 20}
		set.Arms = append(set.Arms, Arm{Evaluator: arm})
		set.Infos = append(set.Infos, ArmInfo{
			Arm: arm.Arm(), Version: arm.ArmVersion(), Model: cfg.Jev.Model,
			Endpoint: cfg.Jev.Redacted(), Configured: true,
		})
	} else {
		set.Infos = append(set.Infos, ArmInfo{
			Arm: investigation.JevArm, Version: models.JevSchemaVersion,
			Configured: false, Blocked: "VORA_PROBE_JEV_BASE_URL is not set",
		})
		set.Arms = append(set.Arms, Arm{
			Evaluator: models.JevArm{Endpoint: cfg.Jev},
			Blocked:   "VORA_PROBE_JEV_BASE_URL is not set",
		})
	}

	return set
}

// Select filters the arm set to the requested names, preserving the order of
// the request so a run is reproducible from its command line. An unknown name is
// an error rather than a silent omission.
func (s ArmSet) Select(names []string) (ArmSet, error) {
	if len(names) == 0 {
		return s, nil
	}
	out := ArmSet{}
	for _, name := range names {
		found := false
		for i, info := range s.Infos {
			if info.Arm != name {
				continue
			}
			found = true
			out.Infos = append(out.Infos, info)
			out.Arms = append(out.Arms, s.Arms[i])
		}
		if !found {
			return ArmSet{}, &UnknownArm{Name: name, Known: s.Names()}
		}
	}
	return out, nil
}

func (s ArmSet) Names() []string {
	out := make([]string, 0, len(s.Infos))
	for _, info := range s.Infos {
		out = append(out, info.Arm)
	}
	return out
}

type UnknownArm struct {
	Name  string
	Known []string
}

func (e *UnknownArm) Error() string {
	return "unknown evaluator " + e.Name + " (known: " + strings.Join(e.Known, ", ") + ")"
}
