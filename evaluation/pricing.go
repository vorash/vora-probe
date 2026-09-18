package evaluation

// Pricing is operator-supplied and optional.
//
// Cost is reported only when the price is known. A guessed price would be worse
// than no price: it would put a number in a comparison table that nobody can
// check, next to counts that are exact.
type TokenPrice struct {
	// USDPerMillionPrompt and USDPerMillionCompletion are the published rates for
	// the model that actually answered.
	USDPerMillionPrompt     float64 `json:"usd_per_million_prompt_tokens"`
	USDPerMillionCompletion float64 `json:"usd_per_million_completion_tokens"`
	// Source records where the price came from, so a reader can check it.
	Source string `json:"source,omitempty"`
}

func (p TokenPrice) Cost(promptTokens, completionTokens int) float64 {
	return float64(promptTokens)/1_000_000*p.USDPerMillionPrompt +
		float64(completionTokens)/1_000_000*p.USDPerMillionCompletion
}
