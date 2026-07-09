package httpauth

import (
	"fmt"
	"net/http"
	"slices"

	"github.com/mikluko/valiss"
)

// Ext is the HTTP transport extension claim: it binds a token to specific
// hosts, methods, and paths. An empty list leaves that dimension
// unconstrained. Mint it with valiss.WithExtension(Ext{...}). The middleware
// enforces every present extension on both chain levels, so an account-level
// extension bounds all of the account's users on top of their own.
type Ext struct {
	// Hosts allowed, matched exactly against the request Host.
	Hosts []string `json:"hosts,omitempty"`
	// Methods allowed, matched exactly (upper-case, e.g. "GET").
	Methods []string `json:"methods,omitempty"`
	// Paths allowed; a trailing "*" is a prefix wildcard, so "/v1/*" covers
	// every path under /v1/.
	Paths []string `json:"paths,omitempty"`
}

// ExtensionName names the claim in the token's ext field.
func (Ext) ExtensionName() string { return "http" }

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
func authorizeExt(id *valiss.Identity, r *http.Request) error {
	exts := []valiss.Extensions{id.Account.Ext}
	if id.User != nil {
		exts = append(exts, id.User.Ext)
	}
	for _, e := range exts {
		ext, ok, err := valiss.ExtOf[Ext](e)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if !ext.Authorizes(r) {
			return fmt.Errorf("valiss: token does not permit %s %s", r.Method, r.URL.Path)
		}
	}
	return nil
}
