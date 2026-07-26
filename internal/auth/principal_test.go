package auth

import "testing"

func TestPrincipalValidateAcceptsAPIKeyAndOIDCShapes(t *testing.T) {
	apiKey := Principal{
		ID:             "00000000-0000-4000-8000-000000000001",
		AuthMethod:     AuthMethodAPIKey,
		APIKeyIDPrefix: "abcdef01",
		Groups:         []string{},
	}
	if err := apiKey.Validate(); err != nil {
		t.Fatalf("API-key principal Validate() error = %v", err)
	}

	oidc := Principal{
		ID:         "00000000-0000-4000-8000-000000000002",
		AuthMethod: AuthMethodOIDC,
		Groups:     []string{"legal-reviewers", "medical-readers"},
	}
	if err := oidc.Validate(); err != nil {
		t.Fatalf("OIDC principal Validate() error = %v", err)
	}
}

func TestPrincipalValidateRejectsInvalidOIDCShapes(t *testing.T) {
	tests := []Principal{
		{ID: "not-a-uuid", AuthMethod: AuthMethodOIDC},
		{ID: "00000000-0000-4000-8000-000000000003", AuthMethod: AuthMethod("jwt")},
		{
			ID:             "00000000-0000-4000-8000-000000000004",
			AuthMethod:     AuthMethodOIDC,
			APIKeyIDPrefix: "abcdef01",
		},
		{
			ID:         "00000000-0000-4000-8000-000000000005",
			AuthMethod: AuthMethodOIDC,
			Groups:     []string{"bad group with spaces"},
		},
		{
			ID:         "00000000-0000-4000-8000-000000000006",
			AuthMethod: AuthMethodOIDC,
			Groups:     []string{"ok", "ok"},
		},
		{
			ID:         "00000000-0000-4000-8000-000000000007",
			AuthMethod: AuthMethodAPIKey,
			Groups:     []string{"should-not-exist"},
		},
	}
	for index, principal := range tests {
		if err := principal.Validate(); err != ErrInvalidPrincipal {
			t.Fatalf("case %d Validate() error = %v, want ErrInvalidPrincipal", index, err)
		}
	}
}
