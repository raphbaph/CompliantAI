package auth

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
)

func TestAPIKeyGeneratedCredentialAuthenticatesAndRevealsOnce(t *testing.T) {
	random := bytes.NewReader(bytes.Repeat([]byte{0x42}, apiKeyIDBytes+apiKeySecretBytes))
	credential, err := generateAPIKey(random)
	if err != nil {
		t.Fatalf("generateAPIKey() error = %v", err)
	}

	bearer, err := credential.Reveal()
	if err != nil {
		t.Fatalf("Reveal() error = %v", err)
	}
	if bearer == "" {
		t.Fatal("Reveal() returned an empty bearer")
	}
	if !VerifyAPIKey(bearer, credential.Verifier()) {
		t.Fatal("generated bearer does not match its verifier")
	}
	if VerifyAPIKey(credential.Verifier(), credential.Verifier()) {
		t.Fatal("stored verifier authenticates directly as a bearer")
	}
	if _, err := credential.Reveal(); !errors.Is(err, ErrAPIKeyUnavailable) {
		t.Fatalf("second Reveal() error = %v, want ErrAPIKeyUnavailable", err)
	}
}

func TestAPIKeyGeneratedCredentialIsFormattingSafeAndCopySafe(t *testing.T) {
	credential, err := generateAPIKey(bytes.NewReader(bytes.Repeat([]byte{0x43}, apiKeyIDBytes+apiKeySecretBytes)))
	if err != nil {
		t.Fatalf("generateAPIKey() error = %v", err)
	}
	secretText := "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M"
	for _, formatted := range []string{
		fmt.Sprintf("%s", credential),
		fmt.Sprintf("%v", credential),
		fmt.Sprintf("%+v", credential),
		fmt.Sprintf("%#v", credential),
		fmt.Sprintf("%d", credential),
		fmt.Sprintf("%x", credential),
		fmt.Sprintf("%p", credential),
		fmt.Sprintf("%v", *credential),
		fmt.Sprintf("%#v", *credential),
		fmt.Sprintf("%d", *credential),
		fmt.Sprintf("%p", *credential),
	} {
		if strings.Contains(formatted, secretText) || strings.Contains(formatted, "67 67 67") || strings.Contains(formatted, credential.KeyID()) || strings.Contains(formatted, credential.Verifier()) {
			t.Fatalf("formatted credential exposed secret material: %q", formatted)
		}
	}

	copyOfCredential := *credential
	if _, err := copyOfCredential.Reveal(); err != nil {
		t.Fatalf("copied Reveal() error = %v", err)
	}
	if _, err := credential.Reveal(); !errors.Is(err, ErrAPIKeyUnavailable) {
		t.Fatalf("original Reveal() after copied reveal error = %v, want ErrAPIKeyUnavailable", err)
	}
}

func TestAPIKeyVerificationRejectsMalformedAndNoncanonicalInputs(t *testing.T) {
	credential, err := generateAPIKey(bytes.NewReader(bytes.Repeat([]byte{0xab}, apiKeyIDBytes+apiKeySecretBytes)))
	if err != nil {
		t.Fatalf("generate API key: %v", err)
	}
	bearer, err := credential.Reveal()
	if err != nil {
		t.Fatalf("reveal API key: %v", err)
	}
	verifier := credential.Verifier()
	parts := strings.Split(bearer, ".")
	for _, test := range []struct {
		name     string
		bearer   string
		verifier string
	}{
		{name: "wrong prefix", bearer: "other." + parts[1] + "." + parts[2], verifier: verifier},
		{name: "uppercase key ID", bearer: parts[0] + "." + strings.ToUpper(parts[1]) + "." + parts[2], verifier: verifier},
		{name: "extra segment", bearer: bearer + ".extra", verifier: verifier},
		{name: "short secret", bearer: parts[0] + "." + parts[1] + ".AA", verifier: verifier},
		{name: "uppercase verifier", bearer: bearer, verifier: strings.ToUpper(verifier)},
		{name: "short verifier", bearer: bearer, verifier: verifier[:len(verifier)-2]},
		{name: "verifier as bearer", bearer: verifier, verifier: verifier},
	} {
		t.Run(test.name, func(t *testing.T) {
			if VerifyAPIKey(test.bearer, test.verifier) {
				t.Fatal("VerifyAPIKey() accepted malformed or noncanonical input")
			}
		})
	}
}

func TestAPIKeyGenerationFailsClosedWhenEntropyReadFails(t *testing.T) {
	credential, err := generateAPIKey(io.LimitReader(strings.NewReader("short"), 5))
	if credential != nil || !errors.Is(err, ErrAPIKeyGeneration) || err != ErrAPIKeyGeneration {
		t.Fatalf("generateAPIKey() = %#v, %v; want nil, exact ErrAPIKeyGeneration", credential, err)
	}
}

func TestAPIKeyGeneratedCredentialConcurrentRevealSucceedsExactlyOnce(t *testing.T) {
	credential, err := generateAPIKey(bytes.NewReader(bytes.Repeat([]byte{0xac}, apiKeyIDBytes+apiKeySecretBytes)))
	if err != nil {
		t.Fatalf("generate API key: %v", err)
	}
	const callers = 32
	results := make(chan error, callers)
	var wait sync.WaitGroup
	wait.Add(callers)
	for range callers {
		go func() {
			defer wait.Done()
			_, err := credential.Reveal()
			results <- err
		}()
	}
	wait.Wait()
	close(results)

	successes := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrAPIKeyUnavailable):
		default:
			t.Fatalf("Reveal() error = %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful concurrent reveals = %d, want 1", successes)
	}
}

func TestAPIKeyGeneratedCredentialConcurrentRevealAndDestroyIsRaceSafe(t *testing.T) {
	credential, err := generateAPIKey(bytes.NewReader(bytes.Repeat([]byte{0xad}, apiKeyIDBytes+apiKeySecretBytes)))
	if err != nil {
		t.Fatalf("generate API key: %v", err)
	}
	const callers = 32
	copyOfCredential := *credential
	start := make(chan struct{})
	results := make(chan error, callers/2)
	var wait sync.WaitGroup
	wait.Add(callers)
	for index := range callers {
		target := credential
		if index >= callers/2 {
			target = &copyOfCredential
		}
		if index%2 == 0 {
			go func(target *generatedAPIKey) {
				defer wait.Done()
				<-start
				_, err := target.Reveal()
				results <- err
			}(target)
			continue
		}
		go func(target *generatedAPIKey) {
			defer wait.Done()
			<-start
			target.Destroy()
		}(target)
	}
	close(start)
	wait.Wait()
	close(results)

	successes := 0
	for err := range results {
		if err == nil {
			successes++
			continue
		}
		if !errors.Is(err, ErrAPIKeyUnavailable) {
			t.Fatalf("Reveal() error = %v", err)
		}
	}
	if successes > 1 {
		t.Fatalf("successful mixed concurrent reveals = %d, want at most 1", successes)
	}
	if _, err := credential.Reveal(); !errors.Is(err, ErrAPIKeyUnavailable) {
		t.Fatalf("Reveal() after mixed race error = %v, want ErrAPIKeyUnavailable", err)
	}
}
