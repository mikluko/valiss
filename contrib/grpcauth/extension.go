package grpcauth

import (
	"fmt"

	"github.com/mikluko/valiss"
)

// Ext is the gRPC transport extension claim: it binds a token to specific
// methods. An empty list leaves the token unconstrained. Mint it with
// valiss.WithExtension(Ext{...}). The interceptors enforce every present
// extension on both chain levels, so an account-level extension bounds all
// of the account's users on top of their own.
type Ext struct {
	// Methods allowed, as gRPC full method names, e.g.
	// "/example.v1.WidgetService/CreateWidget". A trailing "*" is a prefix
	// wildcard, so "/example.v1.WidgetService/*" covers the whole service.
	Methods []string `json:"methods,omitempty"`
}

// ExtensionName names the claim in the token's ext field.
func (Ext) ExtensionName() string { return "grpc" }

// Authorizes reports whether the extension permits the full method.
func (e Ext) Authorizes(fullMethod string) bool {
	return len(e.Methods) == 0 || valiss.Covered(e.Methods, fullMethod)
}

// authorizeExt enforces the gRPC extensions a verified request's tokens
// carry. Tokens without the extension impose no constraint.
func authorizeExt(id *valiss.Identity, fullMethod string) error {
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
		if !ext.Authorizes(fullMethod) {
			return fmt.Errorf("valiss: token does not permit %s", fullMethod)
		}
	}
	return nil
}
