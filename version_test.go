package valiss

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// craftToken assembles a token from raw header and payload JSON with a dummy
// signature. Version dispatch happens before signature verification, so the
// signature need not be valid for version-rejection tests.
func craftToken(header, payload string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(header)) + "." + enc([]byte(payload)) + "." + enc([]byte("sig"))
}

func TestWireVersionDispatch(t *testing.T) {
	op, opPub := issuerKeys(t)

	// A minted token advertises the current wire version and verifies.
	tok, err := IssueOperator(op)
	require.NoError(t, err)
	ver, _, err := peekVersion(tok)
	require.NoError(t, err)
	assert.Equal(t, wireVersion, ver)
	_, err = VerifyOperator(tok, opPub)
	require.NoError(t, err)

	// A future version is recognized and rejected before the payload is
	// parsed, rather than mis-verified under v1 rules.
	v2 := craftToken(`{"typ":"JWT","alg":"ed25519-nkey","ver":2}`, `{"iss":"x"}`)
	_, err = decodeToken(v2)
	require.ErrorContains(t, err, "unsupported wire version 2")

	// A version-0 token (no ver field) — the shape a legacy or alternate
	// version would take — is likewise rejected cleanly. This confirms the
	// dispatcher would slot such a version in via a new case rather than
	// mis-parse it under v1 here.
	v0 := craftToken(`{"typ":"JWT","alg":"ed25519-nkey"}`, `{"iss":"x"}`)
	_, err = decodeToken(v0)
	require.ErrorContains(t, err, "unsupported wire version 0")
}
