package version

import (
	"encoding/json"
	"testing"
)

func TestCurrentHasStableJSONFields(t *testing.T) {
	encoded, err := json.Marshal(Current())
	if err != nil {
		t.Fatalf("marshal version metadata: %v", err)
	}

	const want = `{"version":"dev","commit":"unknown","build_time":"unknown"}`
	if string(encoded) != want {
		t.Fatalf("version metadata JSON = %s, want %s", encoded, want)
	}
}
