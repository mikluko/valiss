// Command valiss issues tenant credentials for gRPC and HTTP services
// using the issuer/tenant nkey model (NATS operator/user style). It is
// stateless: seeds are printed once at generation and never stored; the
// caller preserves them securely.
//
//	valiss keygen issuer              # one-time: issuer key pair (trust anchor)
//	valiss keygen tenant              # per-tenant key pair
//	valiss issue                      # mint tokens for valiss.yaml entries
//
// issue reads a token manifest (valiss.yaml in the working directory,
// override with -f) declaring the issuer public key and the tokens to mint
// (tenant id, public key, scopes, ttl), signs a token per entry with the
// issuer seed (-seed-file or $VALISS_ISSUER_SEED, which must match the
// manifest issuer), and writes the results to stdout as YAML. The jti of
// each token is what the server-side allowlist accepts.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/nats-io/nkeys"
	"gopkg.in/yaml.v3"

	"github.com/mikluko/valiss/internal/manifest"
	"github.com/mikluko/valiss/pkg/token"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = cmdKeygen(os.Stdout, os.Stderr, os.Args[2:])
	case "issue":
		err = cmdIssue(os.Stdout, os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "valiss: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fatal(err)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: valiss <command> [flags]

commands:
  keygen issuer      generate the issuer key pair (server trust anchor)
  keygen tenant      generate a tenant key pair
  issue              issue tokens for the manifest entries, YAML to stdout
      -f FILE          token manifest (default valiss.yaml)
      -seed-file FILE  issuer seed file (default $VALISS_ISSUER_SEED)

Seeds are never stored: keygen prints them once, preserve them securely.
`)
}

// cmdKeygen generates a key pair and prints it once: the pair to out, the
// handling guidance to msg so redirected output stays parseable.
func cmdKeygen(out, msg io.Writer, args []string) error {
	if len(args) != 1 {
		return errors.New("keygen requires a key type: issuer or tenant")
	}
	var (
		kp   nkeys.KeyPair
		err  error
		hint string
	)
	switch args[0] {
	case "issuer":
		// The issuer role maps to the nkeys operator key type (SO... seed).
		kp, err = nkeys.CreateOperator()
		hint = "Public key is the server trust anchor. The seed signs tenant tokens:\npreserve it securely, it cannot be recovered and is never stored."
	case "tenant":
		kp, err = nkeys.CreateAccount()
		hint = "Public key goes in valiss.yaml. The seed signs requests as this tenant:\nhand it to the tenant securely, it cannot be recovered and is never stored."
	default:
		return fmt.Errorf("unknown key type %q; use issuer or tenant", args[0])
	}
	if err != nil {
		return err
	}
	pub, err := kp.PublicKey()
	if err != nil {
		return err
	}
	seed, err := kp.Seed()
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "public: %s\nseed: %s\n", pub, seed)
	fmt.Fprintf(msg, "\n%s\n", hint)
	return nil
}

// issuedToken is one entry of the issue command's YAML output.
type issuedToken struct {
	// ID is the tenant id the token binds.
	ID string `yaml:"id"`
	// JTI is the token id the server-side allowlist accepts.
	JTI string `yaml:"jti"`
	// Expires is the token expiry, RFC3339.
	Expires string `yaml:"expires"`
	// Token is the signed tenant token.
	Token string `yaml:"token"`
}

func cmdIssue(out io.Writer, args []string) error {
	fs := flag.NewFlagSet("issue", flag.ContinueOnError)
	cfgPath := fs.String("f", "valiss.yaml", "token manifest file")
	seedFile := fs.String("seed-file", "", "issuer seed file (default $VALISS_ISSUER_SEED)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	op, err := issuerKey(*seedFile)
	if err != nil {
		return err
	}
	opPub, err := op.PublicKey()
	if err != nil {
		return err
	}
	m, err := manifest.Load(*cfgPath)
	if err != nil {
		return err
	}
	if opPub != m.Issuer {
		return fmt.Errorf("issuer seed does not match the manifest issuer %s", m.Issuer)
	}

	doc := struct {
		Tokens []issuedToken `yaml:"tokens"`
	}{}
	for _, entry := range m.Tokens {
		tok, err := token.Issue(op, entry.ID, entry.Key, entry.Scopes, entry.TTLOrDefault())
		if err != nil {
			return fmt.Errorf("issue %q: %w", entry.ID, err)
		}
		claims, err := token.Verify(tok, opPub)
		if err != nil {
			return fmt.Errorf("issue %q: %w", entry.ID, err)
		}
		doc.Tokens = append(doc.Tokens, issuedToken{
			ID:      entry.ID,
			JTI:     claims.ID,
			Expires: claims.ExpiresAt.UTC().Format(time.RFC3339),
			Token:   tok,
		})
	}
	enc := yaml.NewEncoder(out)
	defer enc.Close()
	return enc.Encode(doc)
}

// issuerKey loads the issuer seed from the given file, falling back to the
// VALISS_ISSUER_SEED environment variable.
func issuerKey(seedFile string) (nkeys.KeyPair, error) {
	var raw []byte
	switch {
	case seedFile != "":
		b, err := os.ReadFile(seedFile)
		if err != nil {
			return nil, fmt.Errorf("issuer seed: %w", err)
		}
		raw = b
	case os.Getenv("VALISS_ISSUER_SEED") != "":
		raw = []byte(os.Getenv("VALISS_ISSUER_SEED"))
	default:
		return nil, errors.New("issuer seed required: pass -seed-file FILE or set $VALISS_ISSUER_SEED")
	}
	kp, err := nkeys.FromSeed(bytes.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("issuer seed: %w", err)
	}
	if pub, err := kp.PublicKey(); err != nil || !nkeys.IsValidPublicOperatorKey(pub) {
		return nil, errors.New("issuer seed: not an operator-type nkey (expected an SO... seed)")
	}
	return kp, nil
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "valiss: %s\n", err)
	os.Exit(1)
}
