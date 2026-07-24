package audit

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
)

func TestHMACGoldenVector(t *testing.T) {
	key := make([]byte, ContentHMACKeySize)
	for index := range key {
		key[index] = byte(index)
	}

	digester, err := NewContentDigester("content-key-v1", key)
	if err != nil {
		t.Fatalf("NewContentDigester(): %v", err)
	}
	digest, err := digester.Sum([]byte("yes"))
	if err != nil {
		t.Fatalf("Sum(): %v", err)
	}
	const want = "a2027312797c0482a8d83bcff68cf93882c6e6fa56c192545fd311adf875af4c"
	if digest.String() != want {
		t.Fatalf("digest = %s, want %s", digest.String(), want)
	}
}

func TestHMACDeploymentKeyIsolation(t *testing.T) {
	firstKey := make([]byte, ContentHMACKeySize)
	secondKey := make([]byte, ContentHMACKeySize)
	for index := range firstKey {
		firstKey[index] = byte(index)
		secondKey[index] = byte(index + 1)
	}
	first, err := NewContentDigester("content-key-v1", firstKey)
	if err != nil {
		t.Fatalf("first NewContentDigester(): %v", err)
	}
	second, err := NewContentDigester("content-key-v2", secondKey)
	if err != nil {
		t.Fatalf("second NewContentDigester(): %v", err)
	}

	content := []byte("yes")
	firstDigest, err := first.Sum(content)
	if err != nil {
		t.Fatalf("first Sum(): %v", err)
	}
	repeatedDigest, err := first.Sum(content)
	if err != nil {
		t.Fatalf("repeated Sum(): %v", err)
	}
	secondDigest, err := second.Sum(content)
	if err != nil {
		t.Fatalf("second Sum(): %v", err)
	}
	if firstDigest != repeatedDigest {
		t.Fatal("same exact bytes and key produced different HMACs")
	}
	if firstDigest == secondDigest {
		t.Fatal("different deployment keys produced the same HMAC")
	}
	if !first.Verify(content, firstDigest) {
		t.Fatal("correct deployment key did not verify content")
	}
	if second.Verify(content, firstDigest) {
		t.Fatal("wrong deployment key verified low-entropy content")
	}
	plainHash := Digest(sha256.Sum256(content))
	if first.Verify(content, plainHash) {
		t.Fatal("unkeyed content hash verified as keyed evidence")
	}
}

func TestHMACKeyIdentity(t *testing.T) {
	key := make([]byte, ContentHMACKeySize)
	digester, err := NewContentDigester("content-key-v1", key)
	if err != nil {
		t.Fatalf("NewContentDigester(): %v", err)
	}
	if digester.KeyID() != "content-key-v1" {
		t.Fatalf("key ID = %q, want content-key-v1", digester.KeyID())
	}
	if _, err := NewContentDigester("PROMPT CONTENT CANARY", key); !errors.Is(err, ErrInvalidContentHMACKey) {
		t.Fatalf("content-shaped key ID error = %v, want ErrInvalidContentHMACKey", err)
	}
}

func TestHMACKeyMaterialIsNotFormattable(t *testing.T) {
	if _, err := NewContentDigester("content-key-v1", make([]byte, ContentHMACKeySize-1)); !errors.Is(err, ErrInvalidContentHMACKey) {
		t.Fatalf("short key error = %v, want ErrInvalidContentHMACKey", err)
	}
	var nilDigester *ContentDigester
	if _, err := nilDigester.Sum(nil); !errors.Is(err, ErrContentHMACUnavailable) {
		t.Fatalf("nil digester error = %v, want ErrContentHMACUnavailable", err)
	}
	if nilDigester.Verify([]byte("yes"), Digest{}) {
		t.Fatal("nil digester verified content")
	}
	var zeroDigester ContentDigester
	if _, err := zeroDigester.Sum(nil); !errors.Is(err, ErrContentHMACUnavailable) {
		t.Fatalf("zero digester error = %v, want ErrContentHMACUnavailable", err)
	}

	key := make([]byte, ContentHMACKeySize)
	for index := range key {
		key[index] = byte(index)
	}
	digester, err := NewContentDigester("content-key-v1", key)
	if err != nil {
		t.Fatalf("NewContentDigester(): %v", err)
	}
	for _, formatted := range []string{
		fmt.Sprintf("%v", digester),
		fmt.Sprintf("%+v", digester),
		fmt.Sprintf("%#v", digester),
		fmt.Sprintf("%v", *digester),
		fmt.Sprintf("%+v", *digester),
		fmt.Sprintf("%#v", *digester),
	} {
		if formatted != "<content-digester>" {
			t.Fatalf("formatted digester = %q, want redacted marker", formatted)
		}
	}
}

func TestChainHashBindsCanonicalEventAndPreviousHash(t *testing.T) {
	event := canonicalFixture()
	first, err := EventHash(event)
	if err != nil {
		t.Fatalf("EventHash(): %v", err)
	}
	const want = "3f95d3193839105b2a32d6e07d71e44e1546c775b1ae9f1cd77aca4c83dc74da"
	if first.String() != want {
		t.Fatalf("event hash = %s, want %s", first.String(), want)
	}

	equivalent := canonicalFixture()
	equivalent.DecisionReasonCodes = []string{"region_allowed", "policy_allowed"}
	equivalent.PIIMatchCounts = map[string]int64{"tax_id": 1, "email_address": 2}
	equivalentHash, err := EventHash(equivalent)
	if err != nil {
		t.Fatalf("EventHash(equivalent): %v", err)
	}
	if equivalentHash != first {
		t.Fatal("equivalent canonical event produced a different chain hash")
	}

	changedPrevious := canonicalFixture()
	changedPrevious.PreviousEventHash = fixtureDigest(9)
	changedPreviousHash, err := EventHash(changedPrevious)
	if err != nil {
		t.Fatalf("EventHash(changed previous): %v", err)
	}
	if changedPreviousHash == first {
		t.Fatal("changed previous event hash did not change chain hash")
	}

	changedMetadata := canonicalFixture()
	changedMetadata.RequestedModel = "local-medical"
	changedMetadataHash, err := EventHash(changedMetadata)
	if err != nil {
		t.Fatalf("EventHash(changed metadata): %v", err)
	}
	if changedMetadataHash == first {
		t.Fatal("changed event metadata did not change chain hash")
	}
}
