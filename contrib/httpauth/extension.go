package httpauth

import (
	"fmt"
	"net/http"
	"slices"

	"github.com/mikluko/valiss"
)

// ExtName is the extension claim name this package issues and enforces.
const ExtName = "http"

// Ext is the HTTP transport extension claim: it binds a token to specific
// hosts, methods, and paths. An empty list leaves that dimension
// unconstrained. The middleware enforces every present extension on both
// chain levels, so an account-level extension bounds all of the account's
// users on top of their own.
type Ext struct {
	// Hosts allowed, matched exactly against the request Host.
	Hosts []string `json:"hosts,omitempty"`
	// Methods allowed, matched exactly (upper-case, e.g. "GET").
	Methods []string `json:"methods,omitempty"`
	// Paths allowed; a trailing "*" is a prefix wildcard, so "/v1/*" covers
	// every path under /v1/.
	Paths []string `json:"paths,omitempty"`
}

// WithExt embeds the HTTP extension into a minted token.
func WithExt(e Ext) valiss.IssueOption {
	return valiss.WithExtension(ExtName, e)
}

// Authorizes reports whether the extension permits the request.
func (e Ext) Authorizes(r *http.Request) bool {
	if len(e.Hosts) > 0 && !slices.Contains(e.Hosts, r.Host) {
		return false
	}
	if len(e.Methods) > 0 && !slices.Contains(e.Methods, r.Method) {
		return false
	}
	if len(e.Paths) > 0 && !valiss.Covered(e.Paths, r.URL.Path) {
		return false
	}
	return true
}

// authorizeExt enforces the HTTP extensions a verified request's tokens
// carry. Tokens without the extension impose no constraint.
func authorizeExt(claims *valiss.Claims, r *http.Request) error {
	for _, exts := range []valiss.Extensions{claims.AccountExt, claims.UserExt} {
		if _, ok := exts[ExtName]; !ok {
			continue
		}
		e, err := valiss.Ext[Ext](exts, ExtName)
		if err != nil {
			return err
		}
		if !e.Authorizes(r) {
			return fmt.Errorf("valiss: token does not permit %s %s", r.Method, r.URL.Path)
		}
	}
	return nil
}
