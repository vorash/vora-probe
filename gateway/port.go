package gateway

// Gateway is the infrastructure port. Every observation an investigation makes
// is read through it, and it has exactly two implementations: one that answers
// from frozen evidence, one that answers from a running lab.
//
// Swapping them is the whole difference between a replay and a live
// investigation. Nothing above this interface changes, and critically the
// policy does not: both implementations are authorized by the same
// gateway.Policy, so a permission cannot differ between the two.
type Gateway interface {
	Execute(a Action) (Response, error)
	// Executed is how many requests the gateway served, for budget accounting.
	Executed() int
}
