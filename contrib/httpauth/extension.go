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
// Enforcement is fail-closed at the extension level: every token in the
// chain must carry the extension (unless the middleware was built with
// AllowMissingExtension), and the zero-value extension grants nothing.
//
// The three dimensions are independent AND-filters, and each is
// constraining only when populated: a dimension you leave empty imposes no
// restriction on that dimension. This is the natural allow-list reading (the
// constraints you name apply; the ones you omit stay open), but it is a
// footgun if you expect naming one dimension to lock down the others. For
// example:
//
//	Ext{Paths: []string{"/admin/*"}}
//
// permits /admin/* with ANY method and from ANY host — not just reads. To
// scope a read-only admin surface you must name every dimension you care
// about:
//
//	Ext{Methods: []string{"GET"}, Paths: []string{"/admin/*"}}
//
// Allow-all within a dimension is the explicit wildcard, e.g.
// Paths: []string{"*"} or Methods: []string{"*"}. Note this differs from the
// single-dimension grpcauth.Ext, where there are no other dimensions to
// leave open.
//
// Extensions on both chain levels are enforced (AND), so an account-level
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
