package detect

import (
	"regexp"
	"strings"
	"unicode"
)

var (
	emailPattern = regexp.MustCompile(`(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,24}\b`)
	phonePattern = regexp.MustCompile(`(?i)(?:\+|00)(49|43)[\s\-./()]*(?:\d[\s\-./()]*){6,13}\d`)
)

// V1 focuses on DE/AT IBAN lengths to avoid ambiguous variable-length scans.
var ibanCountryLengths = map[string]int{
	"DE": 22,
	"AT": 20,
}

func detectPII(text string, sink *aggregator) {
	for _, match := range emailPattern.FindAllString(text, -1) {
		if strings.Count(match, "@") != 1 {
			continue
		}
		sink.add("email_address", "email_basic_v1", 1)
	}

	for _, match := range phonePattern.FindAllString(text, -1) {
		digits := countDigits(match)
		if digits < 8 || digits > 15 {
			continue
		}
		sink.add("phone_number", "phone_e164_de_at_v1", 1)
	}

	compact := compactAlnumUpper(text)
	for i := 0; i+4 <= len(compact); {
		cc := compact[i : i+2]
		length, ok := ibanCountryLengths[cc]
		if !ok || i+length > len(compact) {
			i++
			continue
		}
		candidate := compact[i : i+length]
		if validIBAN(candidate) {
			sink.add("iban", "iban_checksum_v1", 1)
			i += length
			continue
		}
		i++
	}
}

func looksLikeIBAN(candidate string) bool {
	if len(candidate) < 15 || len(candidate) > 34 {
		return false
	}
	if candidate[0] < 'A' || candidate[0] > 'Z' || candidate[1] < 'A' || candidate[1] > 'Z' {
		return false
	}
	if candidate[2] < '0' || candidate[2] > '9' || candidate[3] < '0' || candidate[3] > '9' {
		return false
	}
	for i := 4; i < len(candidate); i++ {
		c := candidate[i]
		if (c < '0' || c > '9') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}

func validIBAN(iban string) bool {
	if !looksLikeIBAN(iban) {
		return false
	}
	if expected, ok := ibanCountryLengths[iban[:2]]; ok && len(iban) != expected {
		return false
	}
	rearranged := iban[4:] + iban[:4]
	var numeric strings.Builder
	numeric.Grow(len(rearranged) * 2)
	for i := 0; i < len(rearranged); i++ {
		c := rearranged[i]
		switch {
		case c >= '0' && c <= '9':
			numeric.WriteByte(c)
		case c >= 'A' && c <= 'Z':
			val := int(c-'A') + 10
			numeric.WriteByte(byte('0' + val/10))
			numeric.WriteByte(byte('0' + val%10))
		default:
			return false
		}
	}
	return mod97(numeric.String()) == 1
}

func mod97(digits string) int {
	rem := 0
	for i := 0; i < len(digits); i++ {
		rem = (rem*10 + int(digits[i]-'0')) % 97
	}
	return rem
}

func countDigits(value string) int {
	count := 0
	for _, r := range value {
		if unicode.IsDigit(r) {
			count++
		}
	}
	return count
}
