package valiss

import "fmt"

// GenerationExt is the valiss generation-floor extension claim: it stamps a
// token with the generation of the entity that signed it, an unsigned counter
// the operator store bumps on every invalidating change (key rotation, removal,
// an extension-policy change). The stamp reflects the issuing entity's own
// generation only; there is deliberately no chain vector, so a token states the
// generation of the entity that signed it, not those of its ancestors.
//
// The extension is optional at both ends. An issuer opts in by minting with
// valiss.WithExtension(GenerationExt{Generation: n}) through the same plumbing
// as any other extension; an unstamped token is unaffected. A verifier opts in
// with WithGenerationFloors, and only then rejects a stamped token whose
// generation is below its issuing entity's floor (see FloorList). A token that
// carries no stamp is never rejected by a floor, and a verifier not configured
// for floors ignores the stamp entirely. Adding the extension changes no
// existing verification outcome.
//
// Template carries an optional, concealed reference to the mint template: a
// short digest (four to six characters) of the template name, salted per
// template in the operator store. The library defines and transports the field
// untouched and never resolves it to a name; resolution is an audit-side join
// against the issuance record, off the wire.
type GenerationExt struct {
	// Generation is the issuing entity's own generation at mint time.
	Generation uint64 `json:"gen"`
	// Template is an opaque short digest of the mint template name, or empty
	// when no template was used. The library never resolves it.
	Template string `json:"tpl,omitempty"`
}

// ExtensionName names the claim in a token's ext field.
func (GenerationExt) ExtensionName() string { return "gen" }

// CheckGenerationFloor applies the generation-floor rule of the extension to a
// single token: given the token's extensions and its issuer, it rejects the
// token when it carries a generation stamp below the floor its issuer defines
// in floors. It is the focused decision the Verifier runs per chain token under
// WithGenerationFloors, exposed for tooling and cross-language conformance.
//
// The rule is optional at both ends, expressed here as three passes:
//   - nil floors (enforcement off) passes everything;
//   - a token with no generation stamp passes, whatever the floor;
//   - an issuer with no floor imposes no constraint.
//
// Only a token whose stamp is strictly below its issuer's floor is rejected. A
// malformed stamp is an error, surfacing floor enforcement at verify time.
func CheckGenerationFloor(exts Extensions, issuer string, floors FloorList) error {
	if floors == nil {
		return nil
	}
	ext, ok, err := ExtOf[GenerationExt](exts)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	floor, ok := floors.Floor(issuer)
	if !ok {
		return nil
	}
	if ext.Generation < floor {
		return fmt.Errorf("valiss: token generation %d below floor %d for issuer %s", ext.Generation, floor, issuer)
	}
	return nil
}
