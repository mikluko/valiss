package creds

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoundTrip(t *testing.T) {
	token := "eyJhbGciOiJlZDI1NTE5LW5rZXkifQ.payload.signature"
	seed := []byte("SAAEXAMPLESEEDVALUE")

	gotToken, gotSeed, err := Parse(Format(token, seed))
	require.NoError(t, err)
	assert.Equal(t, token, gotToken)
	assert.Equal(t, string(seed), string(gotSeed))
}

func TestLoad(t *testing.T) {
	token := "eyJhbGciOiJlZDI1NTE5LW5rZXkifQ.payload.signature"
	seed := []byte("SAAEXAMPLESEEDVALUE")
	path := filepath.Join(t.TempDir(), "acme.creds")
	require.NoError(t, os.WriteFile(path, []byte(Format(token, seed)), 0o600))

	gotToken, gotSeed, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, token, gotToken)
	assert.Equal(t, string(seed), string(gotSeed))
}

func TestParseMissingMarker(t *testing.T) {
	_, _, err := Parse("no markers here")
	assert.ErrorContains(t, err, "not found")
}
