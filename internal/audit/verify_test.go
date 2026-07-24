package audit

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestVerifyChainAcceptsContiguousValidRecords(t *testing.T) {
	records := chainRecords(t, 4)
	if err := VerifyChain(records); err != nil {
		t.Fatalf("VerifyChain(): %v", err)
	}
}

func TestVerifyChainReportsFirstAffectedSequence(t *testing.T) {
	const canary = "PROMPT-CONTENT-CANARY-verify-chain"

	tests := []struct {
		name         string
		mutate       func([]Record) []Record
		wantSequence int64
	}{
		{
			name: "edited event",
			mutate: func(records []Record) []Record {
				records[1].Event.RequestedModel = canary
				return records
			},
			wantSequence: 2,
		},
		{
			name: "deleted row",
			mutate: func(records []Record) []Record {
				return append(records[:1], records[2:]...)
			},
			wantSequence: 2,
		},
		{
			name: "inserted row",
			mutate: func(records []Record) []Record {
				insertedEvent := records[1].Event
				insertedEvent.EventID = "00000000-0000-0000-0000-000000000099"
				insertedHash, err := EventHash(insertedEvent)
				if err != nil {
					t.Fatalf("EventHash(inserted): %v", err)
				}
				inserted := Record{Sequence: 2, Event: insertedEvent, EventHash: insertedHash}
				return append(records[:1], append([]Record{inserted}, records[1:]...)...)
			},
			wantSequence: 2,
		},
		{
			name: "reordered rows",
			mutate: func(records []Record) []Record {
				records[0], records[1] = records[1], records[0]
				return records
			},
			wantSequence: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := VerifyChain(test.mutate(chainRecords(t, 4)))
			var verificationError *VerificationError
			if !errors.As(err, &verificationError) {
				t.Fatalf("VerifyChain() error = %v, want VerificationError", err)
			}
			if verificationError.Sequence != test.wantSequence {
				t.Fatalf("affected sequence = %d, want %d", verificationError.Sequence, test.wantSequence)
			}
			if strings.Contains(err.Error(), canary) {
				t.Fatal("verification error exposed event content")
			}
		})
	}
}

func TestVerifyChainRejectsNonzeroGenesisLink(t *testing.T) {
	records := chainRecords(t, 1)
	records[0].Event.PreviousEventHash = fixtureDigest(42)
	records[0].EventHash, _ = EventHash(records[0].Event)

	err := VerifyChain(records)
	var verificationError *VerificationError
	if !errors.As(err, &verificationError) || verificationError.Sequence != 1 {
		t.Fatalf("VerifyChain() error = %v, want sequence 1 VerificationError", err)
	}
}

func TestVerifyChainAcceptsEmptyExport(t *testing.T) {
	if err := VerifyChain(nil); err != nil {
		t.Fatalf("VerifyChain(nil): %v", err)
	}
}

func chainRecords(t *testing.T, count int) []Record {
	t.Helper()
	records := make([]Record, 0, count)
	previous := Digest{}
	for index := 1; index <= count; index++ {
		event := canonicalFixture()
		event.EventID = fmt.Sprintf("00000000-0000-0000-0000-%012d", index)
		event.OccurredAt = event.OccurredAt.Add(time.Duration(index) * time.Microsecond)
		event.PreviousEventHash = previous
		eventHash, err := EventHash(event)
		if err != nil {
			t.Fatalf("EventHash(record %d): %v", index, err)
		}
		records = append(records, Record{Sequence: int64(index), Event: event, EventHash: eventHash})
		previous = eventHash
	}
	return records
}
