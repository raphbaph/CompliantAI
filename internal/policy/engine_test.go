package policy_test

import (
	"strings"
	"testing"

	"github.com/raphbaph/CompliantAI/internal/policy"
)

func TestEngineDefaultDenyWithoutMatchingAllow(t *testing.T) {
	engine := mustEngine(t, policy.Document{
		Version: "2026-07-26.1",
		Rules: []policy.Rule{{
			ID:         "allow-legal-chat",
			Effect:     policy.EffectAllow,
			Principals: []string{"00000000-0000-4000-8000-000000000001"},
			Endpoints:  []string{"chat.completions"},
			Models:     []string{"local-legal"},
		}},
	})

	decision := engine.Evaluate(policy.Request{
		PrincipalID: "00000000-0000-4000-8000-000000000099",
		Groups:      []string{},
		Endpoint:    "chat.completions",
		Model:       "local-legal",
	})
	if decision.Effect != policy.EffectDeny {
		t.Fatalf("effect = %q, want deny", decision.Effect)
	}
	assertReason(t, decision, "no_matching_allow")
	if decision.PolicyVersion != "2026-07-26.1" || decision.PolicyDigest == "" {
		t.Fatalf("missing policy identity: %#v", decision)
	}
}

func TestEngineAllowsExactPrincipalEndpointModelGrant(t *testing.T) {
	const principalID = "00000000-0000-4000-8000-000000000001"
	engine := mustEngine(t, policy.Document{
		Version: "2026-07-26.1",
		Rules: []policy.Rule{{
			ID:         "allow-legal-chat",
			Effect:     policy.EffectAllow,
			Principals: []string{principalID},
			Endpoints:  []string{"chat.completions"},
			Models:     []string{"local-legal"},
		}},
	})

	decision := engine.Evaluate(policy.Request{
		PrincipalID: principalID,
		Groups:      []string{},
		Endpoint:    "chat.completions",
		Model:       "local-legal",
	})
	if decision.Effect != policy.EffectAllow {
		t.Fatalf("effect = %q, want allow", decision.Effect)
	}
	assertReason(t, decision, "policy_allowed")
	if decision.Context.PrincipalID != principalID ||
		decision.Context.Endpoint != "chat.completions" ||
		decision.Context.Model != "local-legal" {
		t.Fatalf("decision context = %#v", decision.Context)
	}
	if len(decision.Context.MatchedRuleIDs) != 1 || decision.Context.MatchedRuleIDs[0] != "allow-legal-chat" {
		t.Fatalf("matched rules = %#v", decision.Context.MatchedRuleIDs)
	}
}

func TestEngineAllowsExactGroupGrant(t *testing.T) {
	engine := mustEngine(t, policy.Document{
		Version: "2026-07-26.1",
		Rules: []policy.Rule{{
			ID:        "allow-medical-group",
			Effect:    policy.EffectAllow,
			Groups:    []string{"medical-readers"},
			Endpoints: []string{"chat.completions"},
			Models:    []string{"local-medical"},
		}},
	})

	decision := engine.Evaluate(policy.Request{
		PrincipalID: "00000000-0000-4000-8000-000000000002",
		Groups:      []string{"legal-reviewers", "medical-readers"},
		Endpoint:    "chat.completions",
		Model:       "local-medical",
	})
	if decision.Effect != policy.EffectAllow {
		t.Fatalf("effect = %q, want allow", decision.Effect)
	}
	assertReason(t, decision, "policy_allowed")
}

func TestEngineDeniesUnknownEndpointOrModelEvenWithIdentityMatch(t *testing.T) {
	const principalID = "00000000-0000-4000-8000-000000000001"
	engine := mustEngine(t, policy.Document{
		Version: "2026-07-26.1",
		Rules: []policy.Rule{{
			ID:         "allow-legal-chat",
			Effect:     policy.EffectAllow,
			Principals: []string{principalID},
			Endpoints:  []string{"chat.completions"},
			Models:     []string{"local-legal"},
		}},
	})

	tests := []policy.Request{
		{PrincipalID: principalID, Groups: []string{}, Endpoint: "embeddings.create", Model: "local-legal"},
		{PrincipalID: principalID, Groups: []string{}, Endpoint: "chat.completions", Model: "other-model"},
	}
	for _, request := range tests {
		decision := engine.Evaluate(request)
		if decision.Effect != policy.EffectDeny {
			t.Fatalf("request %#v effect = %q, want deny", request, decision.Effect)
		}
		assertReason(t, decision, "no_matching_allow")
	}
}

func TestEngineDenyPrecedenceOverAllow(t *testing.T) {
	const principalID = "00000000-0000-4000-8000-000000000001"
	engine := mustEngine(t, policy.Document{
		Version: "2026-07-26.1",
		Rules: []policy.Rule{
			{
				ID:         "allow-all-chat",
				Effect:     policy.EffectAllow,
				Principals: []string{principalID},
				Endpoints:  []string{"chat.completions"},
				Models:     []string{"local-legal"},
			},
			{
				ID:         "deny-sensitive-model",
				Effect:     policy.EffectDeny,
				Principals: []string{principalID},
				Endpoints:  []string{"chat.completions"},
				Models:     []string{"local-legal"},
			},
		},
	})

	decision := engine.Evaluate(policy.Request{
		PrincipalID: principalID,
		Groups:      []string{},
		Endpoint:    "chat.completions",
		Model:       "local-legal",
	})
	if decision.Effect != policy.EffectDeny {
		t.Fatalf("effect = %q, want deny", decision.Effect)
	}
	assertReason(t, decision, "explicit_deny")
	if len(decision.Context.MatchedRuleIDs) != 2 {
		t.Fatalf("matched rules = %#v, want both allow and deny", decision.Context.MatchedRuleIDs)
	}
}

func TestEngineRejectsInvalidDocuments(t *testing.T) {
	tests := []policy.Document{
		{Version: "", Rules: nil},
		{Version: "v1", Rules: []policy.Rule{{
			ID: "bad effect", Effect: "maybe", Endpoints: []string{"chat.completions"}, Models: []string{"m"},
		}}},
		{Version: "v1", Rules: []policy.Rule{{
			ID: "no-scope", Effect: policy.EffectAllow, Endpoints: []string{"chat.completions"}, Models: []string{"m"},
		}}},
		{Version: "v1", Rules: []policy.Rule{{
			ID: "dup", Effect: policy.EffectAllow, Principals: []string{"00000000-0000-4000-8000-000000000001"}, Endpoints: []string{"chat.completions"}, Models: []string{"m"},
		}, {
			ID: "dup", Effect: policy.EffectDeny, Principals: []string{"00000000-0000-4000-8000-000000000001"}, Endpoints: []string{"chat.completions"}, Models: []string{"m"},
		}}},
	}
	for index, document := range tests {
		if _, err := policy.NewEngine(document); err == nil {
			t.Fatalf("case %d NewEngine() error = nil, want failure", index)
		}
	}
}

func TestEngineDigestIsStableAndContentFree(t *testing.T) {
	document := policy.Document{
		Version: "2026-07-26.1",
		Rules: []policy.Rule{{
			ID:         "allow-legal-chat",
			Effect:     policy.EffectAllow,
			Principals: []string{"00000000-0000-4000-8000-000000000001"},
			Groups:     []string{"legal-reviewers"},
			Endpoints:  []string{"chat.completions"},
			Models:     []string{"local-legal"},
		}},
	}
	first := mustEngine(t, document)
	second := mustEngine(t, document)
	if first.Digest() == "" || first.Digest() != second.Digest() {
		t.Fatalf("digests differ or empty: %q vs %q", first.Digest(), second.Digest())
	}
	if strings.Contains(first.Digest(), "local-legal") || strings.Contains(first.Digest(), "legal-reviewers") {
		t.Fatalf("digest unexpectedly embeds plaintext identifiers: %q", first.Digest())
	}
	// Reordered selectors and rules must canonicalize to the same digest.
	reordered := policy.Document{
		Version: "2026-07-26.1",
		Rules: []policy.Rule{
			{
				ID:         "zz-second",
				Effect:     policy.EffectDeny,
				Principals: []string{"00000000-0000-4000-8000-000000000002"},
				Endpoints:  []string{"models.list"},
				Models:     []string{"local-medical"},
			},
			{
				ID:         "allow-legal-chat",
				Effect:     policy.EffectAllow,
				Principals: []string{"00000000-0000-4000-8000-000000000001"},
				Groups:     []string{"legal-reviewers"},
				Endpoints:  []string{"chat.completions"},
				Models:     []string{"local-legal"},
			},
		},
	}
	canonical := policy.Document{
		Version: "2026-07-26.1",
		Rules: []policy.Rule{
			{
				ID:         "allow-legal-chat",
				Effect:     policy.EffectAllow,
				Principals: []string{"00000000-0000-4000-8000-000000000001"},
				Groups:     []string{"legal-reviewers"},
				Endpoints:  []string{"chat.completions"},
				Models:     []string{"local-legal"},
			},
			{
				ID:         "zz-second",
				Effect:     policy.EffectDeny,
				Principals: []string{"00000000-0000-4000-8000-000000000002"},
				Endpoints:  []string{"models.list"},
				Models:     []string{"local-medical"},
			},
		},
	}
	if mustEngine(t, reordered).Digest() != mustEngine(t, canonical).Digest() {
		t.Fatalf("canonical digest changed under reordered document")
	}
}

func TestEngineUnknownGroupDenies(t *testing.T) {
	engine := mustEngine(t, policy.Document{
		Version: "2026-07-26.1",
		Rules: []policy.Rule{{
			ID:        "allow-medical-group",
			Effect:    policy.EffectAllow,
			Groups:    []string{"medical-readers"},
			Endpoints: []string{"chat.completions"},
			Models:    []string{"local-medical"},
		}},
	})
	decision := engine.Evaluate(policy.Request{
		PrincipalID: "00000000-0000-4000-8000-000000000002",
		Groups:      []string{"legal-reviewers"},
		Endpoint:    "chat.completions",
		Model:       "local-medical",
	})
	if decision.Effect != policy.EffectDeny {
		t.Fatalf("effect = %q, want deny", decision.Effect)
	}
	assertReason(t, decision, "no_matching_allow")
}

func TestEnginePrincipalAndGroupBothRequiredWhenBothSet(t *testing.T) {
	const principalID = "00000000-0000-4000-8000-000000000001"
	engine := mustEngine(t, policy.Document{
		Version: "2026-07-26.1",
		Rules: []policy.Rule{{
			ID:         "allow-both",
			Effect:     policy.EffectAllow,
			Principals: []string{principalID},
			Groups:     []string{"medical-readers"},
			Endpoints:  []string{"chat.completions"},
			Models:     []string{"local-medical"},
		}},
	})

	// Principal matches, group does not.
	denied := engine.Evaluate(policy.Request{
		PrincipalID: principalID,
		Groups:      []string{"legal-reviewers"},
		Endpoint:    "chat.completions",
		Model:       "local-medical",
	})
	if denied.Effect != policy.EffectDeny {
		t.Fatalf("principal-only match effect = %q, want deny", denied.Effect)
	}

	// Both match.
	allowed := engine.Evaluate(policy.Request{
		PrincipalID: principalID,
		Groups:      []string{"medical-readers"},
		Endpoint:    "chat.completions",
		Model:       "local-medical",
	})
	if allowed.Effect != policy.EffectAllow {
		t.Fatalf("principal+group match effect = %q, want allow", allowed.Effect)
	}
}

func TestEngineHasNoHotReload(t *testing.T) {
	engineType := policy.Engine{}
	// Compile-time documentation: Engine is immutable after construction.
	// Runtime check: Evaluate uses the frozen digest/version only.
	engine := mustEngine(t, policy.Document{
		Version: "frozen-1",
		Rules: []policy.Rule{{
			ID:         "allow",
			Effect:     policy.EffectAllow,
			Principals: []string{"00000000-0000-4000-8000-000000000001"},
			Endpoints:  []string{"models.list"},
			Models:     []string{"local-legal"},
		}},
	})
	before := engine.Digest()
	_ = engineType
	decision := engine.Evaluate(policy.Request{
		PrincipalID: "00000000-0000-4000-8000-000000000001",
		Groups:      []string{},
		Endpoint:    "models.list",
		Model:       "local-legal",
	})
	if decision.PolicyDigest != before || engine.Digest() != before {
		t.Fatal("engine digest changed after evaluate")
	}
}

func mustEngine(t *testing.T, document policy.Document) *policy.Engine {
	t.Helper()
	engine, err := policy.NewEngine(document)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	return engine
}

func assertReason(t *testing.T, decision policy.Decision, want string) {
	t.Helper()
	if len(decision.ReasonCodes) != 1 || decision.ReasonCodes[0] != want {
		t.Fatalf("reason codes = %#v, want [%q]", decision.ReasonCodes, want)
	}
}
