// The lab workload is its own module so it stays out of probe's public
// surface and out of `go list ./...` from the repository root.
module github.com/vorash/vora-probe/deploy/lab/memory-test

go 1.25
