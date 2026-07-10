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
		b := Creds{AccountToken: testToken, Seed: []byte("SAAEXAMPLESEEDVALUE")}
		got, err := Parse(Format(b))
		require.NoError(t, err)
		assert.Equal(t, b, got)
	})

	t.Run("user bundle (embedded account token)", func(t *testing.T) {
		b := Creds{AccountToken: testToken, UserToken: testToken + "u", Seed: []byte("SUAEXAMPLESEEDVALUE")}
		got, err := Parse(Format(b))
		require.NoError(t, err)
		assert.Equal(t, b, got)
	})

	t.Run("bearer creds have no seed section", func(t *testing.T) {
		b := Creds{AccountToken: testToken, UserToken: testToken + "u"}
		rendered := Format(b)
		assert.NotContains(t, rendered, "SEED")
		got, err := Parse(rendered)
		require.NoError(t, err)
		assert.Equal(t, b, got)
	})

	t.Run("user-only creds have no account token section", func(t *testing.T) {
		b := Creds{UserToken: testToken + "u", Seed: []byte("SUAEXAMPLESEEDVALUE")}
		rendered := Format(b)
		assert.NotContains(t, rendered, "BEGIN VALISS ACCOUNT TOKEN")
		got, err := Parse(rendered)
		require.NoError(t, err)
		assert.Equal(t, b, got)
	})
}

func TestLoad(t *testing.T) {
	b := Creds{AccountToken: testToken, Seed: []byte("SAAEXAMPLESEEDVALUE")}
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

func TestParseStrictSection(t *testing.T) {
	const begin = "-----BEGIN VALISS ACCOUNT TOKEN-----"
	const end = "------END VALISS ACCOUNT TOKEN------"

	t.Run("content without the end marker is rejected", func(t *testing.T) {
		_, err := Parse(begin + "\n" + testToken + "\n")
		assert.ErrorContains(t, err, "not closed")
	})

	t.Run("empty section is rejected", func(t *testing.T) {
		_, err := Parse(begin + "\n")
		assert.ErrorContains(t, err, "not closed")
	})

	t.Run("trailing content before the end marker is rejected", func(t *testing.T) {
		_, err := Parse(begin + "\n" + testToken + "\ngarbage\n" + end + "\n")
		assert.ErrorContains(t, err, "unexpected content")
	})

	t.Run("well-formed section parses", func(t *testing.T) {
		got, err := Parse(begin + "\n" + testToken + "\n" + end + "\n")
		require.NoError(t, err)
		assert.Equal(t, testToken, got.AccountToken)
	})
}
