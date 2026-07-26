package detect

import (
	"regexp"
)

var (
	privateKeyPattern = regexp.MustCompile(`(?is)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`)
	apiKeyPattern     = regexp.MustCompile(`(?i)\b(?:sk-[A-Za-z0-9]{16,}|cai_api_v1\.[0-9a-f]{32}\.[A-Za-z0-9_\-]{16,}|AKIA[0-9A-Z]{16})\b`)
	jwtPattern        = regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b`)
)

func detectSecrets(text string, sink *aggregator) {
	if n := len(privateKeyPattern.FindAllStringIndex(text, -1)); n > 0 {
		sink.add("private_key", "secret_pem_private_key_v1", n)
	}
	if n := len(apiKeyPattern.FindAllStringIndex(text, -1)); n > 0 {
		sink.add("api_credential", "secret_api_token_shape_v1", n)
	}
	if n := len(jwtPattern.FindAllStringIndex(text, -1)); n > 0 {
		sink.add("jwt_shape", "secret_jwt_shape_v1", n)
	}
}
