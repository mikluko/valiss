package creds

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testToken = "eyJhbGciOiJlZDI1NTE5LW5rZXkifQ.payload.signature"

func TestRoundTrip(t *testing.T) {
	t.Run("account creds", func(t *testing.T) {
		b := Creds{Token: testToken, Seed: []byte("SAAEXAMPLESEEDVALUE")}
		got, err := Parse(Format(b))
		require.NoError(t, err)
		assert.Equal(t, b, got)
	})

	t.Run("user bundle (embedded account token)", func(t *testing.T) {
		b := Creds{Token: testToken, UserToken: testToken + "u", Seed: []byte("SUAEXAMPLESEEDVALUE")}
		got, err := Parse(Format(b))
		require.NoError(t, err)
		assert.Equal(t, b, got)
	})

	t.Run("bearer creds have no seed section", func(t *testing.T) {
		b := Creds{Token: testToken, UserToken: testToken + "u"}
		rendered := Format(b)
		assert.NotContains(t, rendered, "SEED")
		got, err := Parse(rendered)
		require.NoError(t, err)
		assert.Equal(t, b, got)
	})

	t.Run("user-only creds have no account token section", func(t *testing.T) {
		b := Creds{UserToken: testToken + "u", Seed: []byte("SUAEXAMPLESEEDVALUE")}
		rendered := Format(b)
		assert.NotContains(t, rendered, "BEGIN VALISS TOKEN")
		got, err := Parse(rendered)
		require.NoError(t, err)
		assert.Equal(t, b, got)
	})
}

func TestLoad(t *testing.T) {
	b := Creds{Token: testToken, Seed: []byte("SAAEXAMPLESEEDVALUE")}
	path := filepath.Join(t.TempDir(), "acme.creds")
	require.NoError(t, os.WriteFile(path, []byte(Format(b)), 0o600))

	got, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, b, got)
}

func TestParseMissingMarker(t *testing.T) {
	_, err := Parse("no markers here")
	assert.ErrorContains(t, err, "no token markers")
}

func TestParseUnclosedSection(t *testing.T) {
	_, err := Parse("-----BEGIN VALISS TOKEN-----\n" + testToken + "\n")
	require.NoError(t, err, "content line closes the read")

	_, err = Parse("-----BEGIN VALISS TOKEN-----\n")
	assert.ErrorContains(t, err, "not closed")
}
