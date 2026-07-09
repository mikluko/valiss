package grpcauth

import (
	"fmt"

	"github.com/mikluko/valiss"
)

// Ext is the gRPC transport extension claim: it binds a token to specific
// methods. Mint it with valiss.WithExtension(Ext{...}).
//
// Enforcement is fail-closed: every token in the chain must carry the
// extension (unless the Authenticator was built with
// AllowMissingExtension), an empty Methods list grants nothing, and
// allow-all is the explicit wildcard Methods: []string{"*"}. Extensions on
// both chain levels are enforced (AND), so an account-level extension
// bounds all of the account's users on top of their own.
type Ext struct {
	// Methods allowed, as gRPC full method names, e.g.
	// "/example.v1.WidgetService/CreateWidget". A trailing "*" is a prefix
	// wildcard: "/example.v1.WidgetService/*" covers the whole service and
	// "*" covers everything. Empty grants nothing.
	Methods []string `json:"methods,omitempty"`
}

// ExtensionName names the claim in the token's ext field.
func (Ext) ExtensionName() string { return "grpc" }

// Authorizes reports whether the extension permits the full method. An
// empty Methods list permits nothing.
func (e Ext) Authorizes(fullMethod string) bool {
	return valiss.Covered(e.Methods, fullMethod)
}

// authorizeExt enforces the gRPC extensions a verified request's tokens
// carry. Every token in the chain must carry the extension and permit the
// method; with allowMissing, tokens without the extension impose no
// constraint instead.
func authorizeExt(id *valiss.Identity, fullMethod string, allowMissing bool) error {
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
			return fmt.Errorf("valiss: token carries no grpc extension")
		}
		if !ext.Authorizes(fullMethod) {
			return fmt.Errorf("valiss: token does not permit %s", fullMethod)
		}
	}
	return nil
}
