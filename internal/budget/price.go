package budget

import "errors"

// Fixed content-free budget errors.
var (
	ErrInvalidPrice       = errors.New("invalid budget price")
	ErrBudgetDenied       = errors.New("budget denied")
	ErrBudgetUnavailable  = errors.New("budget unavailable")
	ErrBudgetNotFound     = errors.New("budget reservation not found")
	ErrInvalidReservation = errors.New("invalid budget reservation")
)

// ModelPrice is the integer pricing contract for one public model.
type ModelPrice struct {
	InputMicrosPerMillion  int64
	OutputMicrosPerMillion int64
	MaxOutputTokens        int64
}

// EstimateMaxCostMicros computes a conservative integer maximum reservation.
// It ceilings each of input and max-output legs independently, then sums.
func EstimateMaxCostMicros(price ModelPrice, inputTokens int64) (int64, error) {
	if price.InputMicrosPerMillion <= 0 || price.OutputMicrosPerMillion <= 0 || price.MaxOutputTokens <= 0 || inputTokens <= 0 {
		return 0, ErrInvalidPrice
	}
	inputCost, err := mulDivCeil(inputTokens, price.InputMicrosPerMillion, 1_000_000)
	if err != nil {
		return 0, err
	}
	outputCost, err := mulDivCeil(price.MaxOutputTokens, price.OutputMicrosPerMillion, 1_000_000)
	if err != nil {
		return 0, err
	}
	sum, ok := addInt64(inputCost, outputCost)
	if !ok || sum <= 0 {
		return 0, ErrInvalidPrice
	}
	return sum, nil
}

func mulDivCeil(tokens, microsPerMillion, million int64) (int64, error) {
	if tokens <= 0 || microsPerMillion <= 0 || million <= 0 {
		return 0, ErrInvalidPrice
	}
	// (tokens * micros + million - 1) / million with overflow checks.
	product, ok := mulInt64(tokens, microsPerMillion)
	if !ok {
		return 0, ErrInvalidPrice
	}
	numerator, ok := addInt64(product, million-1)
	if !ok {
		return 0, ErrInvalidPrice
	}
	return numerator / million, nil
}

func mulInt64(a, b int64) (int64, bool) {
	if a == 0 || b == 0 {
		return 0, true
	}
	result := a * b
	if result/a != b {
		return 0, false
	}
	return result, true
}

func addInt64(a, b int64) (int64, bool) {
	if b > 0 && a > (1<<63-1)-b {
		return 0, false
	}
	if b < 0 && a < (-1<<63)-b {
		return 0, false
	}
	return a + b, true
}
