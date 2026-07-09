// Package creds implements the client credentials file: the subject's token
// plus the seed that signs its requests, modeled on the nsc creds format.
// A creds file is everything a client needs.
//
// Account-level creds hold the operator-signed tenant token and the account
// seed. User-level creds hold the account-signed user token and the user
// seed; the server resolves the account token itself. A *bundle* is the kind
// of creds that additionally carries the upstream account token, for servers
// that do not resolve it. Bearer creds carry tokens only: their holder
// cannot sign requests and the server accepts them only when the token
// grants the bearer scope.
package creds

import (
	"fmt"
	"os"
	"strings"
)

// Creds file markers.
const (
	accountTokenBegin = "-----BEGIN VALISS ACCOUNT TOKEN-----"
	accountTokenEnd   = "------END VALISS ACCOUNT TOKEN------"
	userTokenBegin    = "-----BEGIN VALISS USER TOKEN-----"
	userTokenEnd      = "------END VALISS USER TOKEN------"
	seedBegin         = "-----BEGIN VALISS SEED-----"
	seedEnd           = "------END VALISS SEED------"
)

// Creds is the parsed content of a creds file.
type Creds struct {
	// Token is the operator-signed tenant token. User-level creds omit it by
	// default (the server then resolves the account token by other means,
	// like static configuration); a bundle (creds -bundle) embeds it.
	Token string
	// UserToken is the account-signed user token; empty in account-level
	// creds.
	UserToken string
	// Seed signs requests as the creds' subject: the account seed in
	// account-level creds, the user seed in user-level ones. Nil in bearer
	// creds.
	Seed []byte
}

// Format renders the creds file content.
func Format(b Creds) string {
	var sb strings.Builder
	if b.Token != "" {
		fmt.Fprintf(&sb, "%s\n%s\n%s\n", accountTokenBegin, strings.TrimSpace(b.Token), accountTokenEnd)
	}
	if b.UserToken != "" {
		if b.Token != "" {
			sb.WriteString("\n")
		}
		fmt.Fprintf(&sb, "%s\n%s\n%s\n", userTokenBegin, strings.TrimSpace(b.UserToken), userTokenEnd)
	}
	if len(b.Seed) > 0 {
		fmt.Fprintf(&sb, "\n%s\n%s\n%s\n", seedBegin, strings.TrimSpace(string(b.Seed)), seedEnd)
		fmt.Fprint(&sb, "\n************************* IMPORTANT *************************\n"+
			"Seed lets anyone sign as this identity. Keep it secret.\n")
	}
	return sb.String()
}

// Parse extracts the creds from a file's contents. Every section is optional
// on its own, but at least one token must be present.
func Parse(contents string) (Creds, error) {
	var b Creds
	tok, ok, err := between(contents, accountTokenBegin, accountTokenEnd)
	if err != nil {
		return Creds{}, fmt.Errorf("valiss: creds token: %w", err)
	}
	if ok {
		b.Token = tok
	}
	userTok, ok, err := between(contents, userTokenBegin, userTokenEnd)
	if err != nil {
		return Creds{}, fmt.Errorf("valiss: creds user token: %w", err)
	}
	if ok {
		b.UserToken = userTok
	}
	if b.Token == "" && b.UserToken == "" {
		return Creds{}, fmt.Errorf("valiss: creds: no token markers found")
	}
	seed, ok, err := between(contents, seedBegin, seedEnd)
	if err != nil {
		return Creds{}, fmt.Errorf("valiss: creds seed: %w", err)
	}
	if ok {
		b.Seed = []byte(seed)
	}
	return b, nil
}

// Load reads and parses a creds file.
func Load(path string) (Creds, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Creds{}, fmt.Errorf("valiss: read creds: %w", err)
	}
	return Parse(string(raw))
}

// between returns the first non-empty line strictly between a begin and end
// marker. The bool is false when the begin marker is absent; a present but
// empty or unclosed section is an error.
func between(contents, begin, end string) (string, bool, error) {
	inside := false
	for line := range strings.Lines(contents) {
		line = strings.TrimSpace(line)
		switch {
		case line == begin:
			inside = true
		case inside && line == end:
			return "", false, fmt.Errorf("no content before %q", end)
		case inside && line != "":
			return line, true, nil
		}
	}
	if inside {
		return "", false, fmt.Errorf("marker %q not closed", begin)
	}
	return "", false, nil
}
