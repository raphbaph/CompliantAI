package audit

import (
	"context"
	"errors"
	"testing"
)

func TestAppendReceiptZeroDoesNotAuthorizeBackend(t *testing.T) {
	var receipt AppendReceipt
	if receipt.Sequence() != 0 {
		t.Fatalf("zero receipt sequence = %d, want 0", receipt.Sequence())
	}
	if receipt.EventHash() != (Digest{}) {
		t.Fatal("zero receipt has event hash")
	}
	if receipt.AuthorizesBackendCall() {
		t.Fatal("zero receipt authorizes backend call")
	}
}

func TestNewRepositoryRejectsNilPool(t *testing.T) {
	repository, err := NewRepository(nil)
	if repository != nil || !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("NewRepository(nil) = (%v, %v), want nil ErrRepositoryUnavailable", repository, err)
	}
}

func TestNilRepositoryAppendFailsClosed(t *testing.T) {
	var repository *Repository
	receipt, err := repository.Append(context.Background(), canonicalFixture())
	if !errors.Is(err, ErrAppend) {
		t.Fatalf("nil Repository.Append() error = %v, want ErrAppend", err)
	}
	if receipt.AuthorizesBackendCall() {
		t.Fatal("failed nil repository append authorizes backend call")
	}
}
