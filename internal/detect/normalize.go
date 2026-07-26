package detect

import (
	"strings"
	"unicode/utf8"
)

func normalizeInput(raw []byte) (string, error) {
	if len(raw) > MaxInputBytes {
		return "", ErrInputTooLarge
	}
	if !utf8.Valid(raw) {
		return "", ErrInvalidInput
	}
	// Keep original text for structured patterns; only reject NULs.
	if strings.IndexByte(string(raw), 0) >= 0 {
		return "", ErrInvalidInput
	}
	return string(raw), nil
}

func compactAlnumUpper(value string) string {
	var b strings.Builder
	b.Grow(len(value))
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= 'a' && c <= 'z':
			b.WriteByte(c - 'a' + 'A')
		case c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			b.WriteByte(c)
		}
	}
	return b.String()
}
