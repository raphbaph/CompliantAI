package budget_test

import (
	"math"
	"testing"

	"github.com/raphbaph/CompliantAI/internal/budget"
)

func TestEstimateMaxCostUsesIntegerCeilingWithoutOverflow(t *testing.T) {
	price := budget.ModelPrice{
		InputMicrosPerMillion:  1_000, // 0.001 euro per 1M input tokens in micros... keep simple
		OutputMicrosPerMillion: 2_000,
		MaxOutputTokens:        2_048,
	}
	// 1_500_000 input tokens -> ceil(1500*1000)/1e6 wait:
	// cost = ceil(tokens * microsPerMillion / 1_000_000)
	got, err := budget.EstimateMaxCostMicros(price, 1_500_000)
	if err != nil {
		t.Fatalf("EstimateMaxCostMicros() error = %v", err)
	}
	// input: 1_500_000 * 1000 / 1e6 = 1500
	// output: 2048 * 2000 / 1e6 = 4.096 -> 5 ceiling
	want := int64(1500 + 5)
	if got != want {
		t.Fatalf("cost = %d, want %d", got, want)
	}
}

func TestEstimateMaxCostRejectsInvalidAndOverflow(t *testing.T) {
	valid := budget.ModelPrice{InputMicrosPerMillion: 1, OutputMicrosPerMillion: 1, MaxOutputTokens: 1}
	if _, err := budget.EstimateMaxCostMicros(budget.ModelPrice{}, 1); err != budget.ErrInvalidPrice {
		t.Fatalf("empty price error = %v", err)
	}
	if _, err := budget.EstimateMaxCostMicros(valid, 0); err != budget.ErrInvalidPrice {
		t.Fatalf("zero tokens error = %v", err)
	}
	if _, err := budget.EstimateMaxCostMicros(valid, -1); err != budget.ErrInvalidPrice {
		t.Fatalf("negative tokens error = %v", err)
	}
	huge := budget.ModelPrice{
		InputMicrosPerMillion:  math.MaxInt64,
		OutputMicrosPerMillion: math.MaxInt64,
		MaxOutputTokens:        math.MaxInt64,
	}
	if _, err := budget.EstimateMaxCostMicros(huge, math.MaxInt64); err != budget.ErrInvalidPrice {
		t.Fatalf("overflow error = %v, want ErrInvalidPrice", err)
	}
}

func TestEstimateMaxCostCeilPartialMicros(t *testing.T) {
	price := budget.ModelPrice{
		InputMicrosPerMillion:  3,
		OutputMicrosPerMillion: 3,
		MaxOutputTokens:        1,
	}
	got, err := budget.EstimateMaxCostMicros(price, 1)
	if err != nil {
		t.Fatalf("EstimateMaxCostMicros: %v", err)
	}
	// ceil(3/1e6)=1 each leg => 2
	if got != 2 {
		t.Fatalf("got %d, want 2", got)
	}
}

func TestActualCostAllowsZeroCompletionTokens(t *testing.T) {
	price := budget.ModelPrice{
		InputMicrosPerMillion:  1_000_000,
		OutputMicrosPerMillion: 2_000_000,
		MaxOutputTokens:        128,
	}
	got, err := budget.ActualCostMicros(price, 2, 0)
	if err != nil {
		t.Fatalf("ActualCostMicros: %v", err)
	}
	if got != 2 {
		t.Fatalf("got %d, want 2", got)
	}
}
