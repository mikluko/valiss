// Package creds implements the client credential bundle file: an
// issuer-signed token paired with the tenant seed that must sign requests,
// modeled on the nsc creds format. The two together are everything a client
// needs.
package creds

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Creds file markers.
const (
	tokenBegin = "-----BEGIN VALISS TOKEN-----"
	tokenEnd   = "------END VALISS TOKEN------"
	seedBegin  = "-----BEGIN VALISS SEED-----"
	seedEnd    = "------END VALISS SEED------"
)

// Format renders a creds file bundling the token and the tenant seed.
func Format(token string, seed []byte) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n%s\n%s\n\n", tokenBegin, strings.TrimSpace(token), tokenEnd)
	fmt.Fprintf(&b, "%s\n%s\n%s\n", seedBegin, strings.TrimSpace(string(seed)), seedEnd)
	fmt.Fprint(&b, "\n************************* IMPORTANT *************************\n"+
		"Seed lets anyone sign as this tenant. Keep it secret.\n")
	return b.String()
}

// Parse extracts the token and seed from a creds file's contents.
func Parse(contents string) (token string, seed []byte, err error) {
	token, err = between(contents, tokenBegin, tokenEnd)
	if err != nil {
		return "", nil, fmt.Errorf("valiss: creds token: %w", err)
	}
	s, err := between(contents, seedBegin, seedEnd)
	if err != nil {
		return "", nil, fmt.Errorf("valiss: creds seed: %w", err)
	}
	return token, []byte(s), nil
}

// Load reads and parses a creds file.
func Load(path string) (token string, seed []byte, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", nil, fmt.Errorf("valiss: read creds: %w", err)
	}
	return Parse(string(raw))
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
