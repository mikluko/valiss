// Package creds implements the client credential bundle file: the tokens a
// client presents plus the seed that signs its requests, modeled on the nsc
// creds format. A bundle is everything a client needs.
//
// An account-level bundle holds the operator-signed tenant token and the
// account seed. A user-level bundle additionally holds the account-signed
// user token, and its seed is the user's. A bearer bundle carries tokens
// only: its holder cannot sign requests and the server accepts it only when
// the token grants the bearer scope.
package creds

import (
	"fmt"
	"os"
	"strings"
)

// Creds file markers.
const (
	tokenBegin     = "-----BEGIN VALISS TOKEN-----"
	tokenEnd       = "------END VALISS TOKEN------"
	userTokenBegin = "-----BEGIN VALISS USER TOKEN-----"
	userTokenEnd   = "------END VALISS USER TOKEN------"
	seedBegin      = "-----BEGIN VALISS SEED-----"
	seedEnd        = "------END VALISS SEED------"
)

// Bundle is the parsed content of a creds file.
type Bundle struct {
	// Token is the operator-signed tenant token. User-level bundles omit it
	// by default (the server then resolves the account token by other means,
	// like static configuration); creds -with-account-token embeds it.
	Token string
	// UserToken is the account-signed user token; empty in account-level
	// bundles.
	UserToken string
	// Seed signs requests as the bundle's subject: the account seed in an
	// account-level bundle, the user seed in a user-level one. Nil in bearer
	// bundles.
	Seed []byte
}

// Format renders a creds file for the bundle.
func Format(b Bundle) string {
	var sb strings.Builder
	if b.Token != "" {
		fmt.Fprintf(&sb, "%s\n%s\n%s\n", tokenBegin, strings.TrimSpace(b.Token), tokenEnd)
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

// Parse extracts the bundle from a creds file's contents. Every section is
// optional on its own, but at least one token must be present.
func Parse(contents string) (Bundle, error) {
	var b Bundle
	tok, ok, err := between(contents, tokenBegin, tokenEnd)
	if err != nil {
		return Bundle{}, fmt.Errorf("valiss: creds token: %w", err)
	}
	if ok {
		b.Token = tok
	}
	userTok, ok, err := between(contents, userTokenBegin, userTokenEnd)
	if err != nil {
		return Bundle{}, fmt.Errorf("valiss: creds user token: %w", err)
	}
	if ok {
		b.UserToken = userTok
	}
	if b.Token == "" && b.UserToken == "" {
		return Bundle{}, fmt.Errorf("valiss: creds: no token markers found")
	}
	seed, ok, err := between(contents, seedBegin, seedEnd)
	if err != nil {
		return Bundle{}, fmt.Errorf("valiss: creds seed: %w", err)
	}
	if ok {
		b.Seed = []byte(seed)
	}
	return b, nil
}

// Load reads and parses a creds file.
func Load(path string) (Bundle, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Bundle{}, fmt.Errorf("valiss: read creds: %w", err)
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
