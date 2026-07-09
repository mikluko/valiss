package httpauth

import (
	"fmt"
	"net/http"
	"slices"

	"github.com/mikluko/valiss"
)

// Ext is the HTTP transport extension claim: it binds a token to specific
// hosts, methods, and paths. Mint it with valiss.WithExtension(Ext{...}).
//
// Enforcement is fail-closed: every token in the chain must carry the
// extension (unless the middleware was built with AllowMissingExtension),
// and the zero-value extension grants nothing. A non-zero extension leaves
// its empty dimensions unconstrained, so Ext{Paths: []string{"/v1/*"}}
// permits any host and method under /v1/; allow-all is the explicit
// Ext{Paths: []string{"*"}}. Extensions on both chain levels are enforced
// (AND), so an account-level extension bounds all of the account's users on
// top of their own.
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

// Authorizes reports whether the extension permits the request. The
// zero-value extension permits nothing.
func (e Ext) Authorizes(r *http.Request) bool {
	if len(e.Hosts) == 0 && len(e.Methods) == 0 && len(e.Paths) == 0 {
		return false
	}
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
// carry. Every token in the chain must carry the extension and permit the
// request; with allowMissing, tokens without the extension impose no
// constraint instead.
func authorizeExt(id *valiss.Identity, r *http.Request, allowMissing bool) error {
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
			if allowMissing {
				continue
			}
			return fmt.Errorf("valiss: token carries no http extension")
		}
		if !ext.Authorizes(r) {
			return fmt.Errorf("valiss: token does not permit %s %s", r.Method, r.URL.Path)
		}
	}
	return nil
}
