package tokenator

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Creds file markers, modeled on the nsc creds format: an operator-issued
// token paired with the tenant seed that must sign requests. The two together
// are everything a client needs.
const (
	tokenBegin = "-----BEGIN TOKENATOR TOKEN-----"
	tokenEnd   = "------END TOKENATOR TOKEN------"
	seedBegin  = "-----BEGIN TOKENATOR SEED-----"
	seedEnd    = "------END TOKENATOR SEED------"
)

// FormatCreds renders a creds file bundling the token and the tenant seed.
func FormatCreds(token string, seed []byte) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n%s\n%s\n\n", tokenBegin, strings.TrimSpace(token), tokenEnd)
	fmt.Fprintf(&b, "%s\n%s\n%s\n", seedBegin, strings.TrimSpace(string(seed)), seedEnd)
	fmt.Fprint(&b, "\n************************* IMPORTANT *************************\n"+
		"Seed lets anyone sign as this tenant. Keep it secret.\n")
	return b.String()
}

// ParseCreds extracts the token and seed from a creds file's contents.
func ParseCreds(contents string) (token string, seed []byte, err error) {
	token, err = between(contents, tokenBegin, tokenEnd)
	if err != nil {
		return "", nil, fmt.Errorf("tokenator: creds token: %w", err)
	}
	s, err := between(contents, seedBegin, seedEnd)
	if err != nil {
		return "", nil, fmt.Errorf("tokenator: creds seed: %w", err)
	}
	return token, []byte(s), nil
}

// LoadCreds reads and parses a creds file.
func LoadCreds(path string) (token string, seed []byte, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", nil, fmt.Errorf("tokenator: read creds: %w", err)
	}
	return ParseCreds(string(raw))
}

// between returns the first non-empty line strictly between a begin and end
// marker.
func between(contents, begin, end string) (string, error) {
	scanner := bufio.NewScanner(strings.NewReader(contents))
	inside := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case line == begin:
			inside = true
		case line == end:
			return "", fmt.Errorf("no content before %q", end)
		case inside && line != "":
			return line, nil
		}
	}
	return "", fmt.Errorf("marker %q not found", begin)
}
