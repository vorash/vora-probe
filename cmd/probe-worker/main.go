// Command probe-worker is the fixed worker binary the controller invokes, one
// process per transition: a bounded state envelope on stdin, exactly one
// schema-validated request or the final report on stdout.
//
// The binary takes no arguments. There is nothing for a model to influence here
// beyond the envelope it is given, and its input is read under a hard byte limit.
package main

import (
	"fmt"
	"os"

	"github.com/vorash/vora-probe/internal/gateway"
	"github.com/vorash/vora-probe/internal/investigation"
	"github.com/vorash/vora-probe/internal/worker"
)

func main() {
	if len(os.Args) > 1 {
		fmt.Fprintln(os.Stderr, "probe-worker takes no arguments; it reads one state envelope on stdin")
		os.Exit(2)
	}
	budget := investigation.DefaultBudgets()
	engine := &investigation.Engine{
		Policy: gateway.DefaultPolicy(),
		Claims: investigation.DefaultClaimPolicy(),
	}
	if err := worker.Run(engine, os.Stdin, os.Stdout, budget.MaxEnvelopeBytes, budget.MaxResponseBytes); err != nil {
		fmt.Fprintln(os.Stderr, "probe-worker:", err)
		os.Exit(1)
	}
}
