package grpcauth

import (
	"fmt"

	"github.com/mikluko/valiss"
)

// ExtName is the extension claim name this package issues and enforces.
const ExtName = "grpc"

// Ext is the gRPC transport extension claim: it binds a token to specific
// methods. An empty list leaves the token unconstrained. The interceptors
// enforce every present extension on both chain levels, so an account-level
// extension bounds all of the account's users on top of their own.
type Ext struct {
	// Methods allowed, as gRPC full method names, e.g.
	// "/example.v1.WidgetService/CreateWidget". A trailing "*" is a prefix
	// wildcard, so "/example.v1.WidgetService/*" covers the whole service.
	Methods []string `json:"methods,omitempty"`
}

// WithExt embeds the gRPC extension into a minted token.
func WithExt(e Ext) valiss.IssueOption {
	return valiss.WithExtension(ExtName, e)
}

// Authorizes reports whether the extension permits the full method.
func (e Ext) Authorizes(fullMethod string) bool {
	return len(e.Methods) == 0 || valiss.Covered(e.Methods, fullMethod)
}

// authorizeExt enforces the gRPC extensions a verified request's tokens
// carry. Tokens without the extension impose no constraint.
func authorizeExt(claims *valiss.Claims, fullMethod string) error {
	for _, exts := range []valiss.Extensions{claims.AccountExt, claims.UserExt} {
		if _, ok := exts[ExtName]; !ok {
			continue
		}
		e, err := valiss.Ext[Ext](exts, ExtName)
		if err != nil {
			return err
		}
		if !e.Authorizes(fullMethod) {
			return fmt.Errorf("valiss: token does not permit %s", fullMethod)
		}
	}
	return nil
}
