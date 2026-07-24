package audit

import "fmt"

// Record is one persisted event and its stored chain hash.
type Record struct {
	Sequence  int64
	Event     Event
	EventHash Digest
}

// VerificationError reports the first sequence where chain verification failed.
type VerificationError struct {
	Sequence int64
}

// Error returns a content-free verification failure.
func (err *VerificationError) Error() string {
	return fmt.Sprintf("audit chain verification failed at sequence %d", err.Sequence)
}

// VerifyChain verifies sequence continuity, previous-hash links, and canonical event hashes.
func VerifyChain(records []Record) error {
	expectedSequence := int64(1)
	expectedPrevious := Digest{}

	for _, record := range records {
		if record.Sequence != expectedSequence {
			affectedSequence := expectedSequence
			if record.Sequence < affectedSequence {
				affectedSequence = record.Sequence
			}
			return &VerificationError{Sequence: affectedSequence}
		}
		if record.Event.PreviousEventHash != expectedPrevious {
			return &VerificationError{Sequence: record.Sequence}
		}
		computedHash, err := EventHash(record.Event)
		if err != nil || computedHash != record.EventHash {
			return &VerificationError{Sequence: record.Sequence}
		}
		expectedPrevious = record.EventHash
		expectedSequence++
	}
	return nil
}
