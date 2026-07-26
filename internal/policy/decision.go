package policy

// Decision is the content-free authorization outcome.
type Decision struct {
	Effect        Effect
	ReasonCodes   []string
	PolicyVersion string
	PolicyDigest  string
	Context       DecisionContext
}

// DecisionContext records the non-content inputs needed to reproduce a decision.
type DecisionContext struct {
	PrincipalID    string
	Groups         []string
	Endpoint       string
	Model          string
	MatchedRuleIDs []string
}
