// Command valiss issues tenant credentials for gRPC and HTTP services
// using the operator/account/user nkey model (NATS style). It is stateless:
// key pairs are printed once at generation and never stored; signing seeds
// are supplied via VALISS_SEED_<PUBKEY> environment variables.
//
//	valiss keygen operator            # one-time: operator key pair (trust anchor)
//	valiss keygen account             # per-tenant key pair
//	valiss keygen user                # per-end-user key pair
//	valiss creds ACCOUNT[/USER]       # mint credentials for one entity
//
// creds reads a token manifest (valiss.yaml in the working directory,
// override with -f) declaring the credential tree, resolves every required
// seed from VALISS_SEED_<PUBKEY> environment variables (failing when one is
// missing), and writes the credentials to stdout and their metadata --
// including the jti the server-side allowlist accepts -- to stderr as YAML.
// User creds carry only the user token; -bundle additionally embeds a fresh
// account token for servers that do not resolve account tokens themselves.
// Manifest entries without a key get a fresh key pair generated per
// invocation; the seed ships inside the creds and is never stored.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/nats-io/nkeys"
	"gopkg.in/yaml.v3"

	"github.com/mikluko/valiss"
	"github.com/mikluko/valiss/creds"
	"github.com/mikluko/valiss/examples/cli/manifest"
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
	case "creds":
		err = cmdCreds(os.Stdout, os.Stderr, os.Args[2:])
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
  keygen operator    generate the operator key pair (server trust anchor)
  keygen account     generate an account (tenant) key pair
  keygen user        generate a user key pair
  creds ACCOUNT[/USER]  mint credentials for a manifest entry:
                     creds to stdout, metadata (allowlist jti) to stderr
      -f FILE          token manifest (default valiss.yaml)
      -bundle          also embed a fresh account token in user creds

Seeds are never stored: keygen prints them once, preserve them securely.
creds resolves signing seeds from VALISS_SEED_<PUBKEY> environment variables.
`)
}

// cmdKeygen generates a key pair and prints it once: the pair to out, the
// handling guidance to msg so redirected output stays parseable.
func cmdKeygen(out, msg io.Writer, args []string) error {
	if len(args) != 1 {
		return errors.New("keygen requires a key type: operator, account, or user")
	}
	var (
		kp   nkeys.KeyPair
		err  error
		hint string
	)
	switch args[0] {
	case "operator":
		kp, err = nkeys.CreateOperator()
		hint = "Public key is the server trust anchor. The seed signs account tokens:\npreserve it as VALISS_SEED_<public>, it cannot be recovered and is never stored."
	case "account":
		kp, err = nkeys.CreateAccount()
		hint = "Public key goes in valiss.yaml. The seed signs requests as this tenant\nand its users' tokens: preserve it as VALISS_SEED_<public>."
	case "user":
		kp, err = nkeys.CreateUser()
		hint = "Public key goes in a user entry in valiss.yaml. The seed signs requests\nas this user: hand it to the user securely, it is never stored."
	default:
		return fmt.Errorf("unknown key type %q; use operator, account, or user", args[0])
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

// tokenMeta is the minted-token section of the creds command's metadata
// output.
type tokenMeta struct {
	// Name is the entity the token binds (the token's name field; its sub
	// claim carries the key).
	Name string `yaml:"name"`
	// Key is the entity's nkey public key; absent on bearer entries.
	Key string `yaml:"key,omitempty"`
	// Generated marks a key pair created by this invocation; its seed ships
	// only inside the creds.
	Generated bool `yaml:"generated,omitempty"`
	// JTI is the token id; the account jti is what the server-side allowlist
	// accepts.
	JTI string `yaml:"jti"`
	// Expires is the token expiry, RFC3339; absent means never.
	Expires string `yaml:"expires,omitempty"`
	// NotBefore is the token activation time, RFC3339; absent means
	// immediately valid.
	NotBefore string `yaml:"not_before,omitempty"`
}

// credsMeta is the creds command's metadata output, written to stderr as
// YAML so the creds on stdout stay clean.
type credsMeta struct {
	Account *tokenMeta `yaml:"account,omitempty"`
	User    *tokenMeta `yaml:"user,omitempty"`
}

func cmdCreds(out, msg io.Writer, args []string) error {
	fs := flag.NewFlagSet("creds", flag.ContinueOnError)
	cfgPath := fs.String("f", "valiss.yaml", "token manifest file")
	asBundle := fs.Bool("bundle", false, "embed a freshly minted account token in user creds, for servers that do not resolve account tokens themselves")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("creds requires exactly one ACCOUNT[/USER] argument")
	}
	acctName, userName, wantUser := strings.Cut(fs.Arg(0), "/")
	if acctName == "" || (wantUser && userName == "") {
		return fmt.Errorf("bad entity path %q: want ACCOUNT or ACCOUNT/USER", fs.Arg(0))
	}
	if *asBundle && !wantUser {
		return errors.New("-bundle applies only to user credentials")
	}

	m, err := manifest.Load(*cfgPath)
	if err != nil {
		return err
	}
	acct, err := m.FindAccount(acctName)
	if err != nil {
		return err
	}

	// The operator seed signs account tokens; plain user creds carry
	// only the user token and need just the account seed.
	var operator nkeys.KeyPair
	if !wantUser || *asBundle {
		if operator, err = seedFromEnv(m.Operator); err != nil {
			return err
		}
	}

	if !wantUser {
		return mintAccount(out, msg, operator, acct)
	}
	return mintUser(out, msg, operator, acct, userName)
}

// validity turns the manifest's absolute boundaries into issue options.
func validity(expires, notBefore time.Time) []valiss.IssueOption {
	var opts []valiss.IssueOption
	if !expires.IsZero() {
		opts = append(opts, valiss.WithExpiry(expires))
	}
	if !notBefore.IsZero() {
		opts = append(opts, valiss.WithNotBefore(notBefore))
	}
	return opts
}

// checkNotExpired refuses to mint a manifest entry whose window has already
// closed.
func checkNotExpired(name string, expires time.Time) error {
	if !expires.IsZero() && !expires.After(time.Now()) {
		return fmt.Errorf("%q expired %s: update the manifest before minting", name, expires.Format(time.RFC3339))
	}
	return nil
}

// mintAccount writes account-level creds: the operator-signed account
// token plus the account seed.
func mintAccount(out, msg io.Writer, operator nkeys.KeyPair, acct manifest.Account) error {
	if err := checkNotExpired(acct.Name, acct.Expires); err != nil {
		return err
	}
	subject, generated, err := subjectKey(acct.Key, nkeys.CreateAccount)
	if err != nil {
		return err
	}
	pub, err := subject.PublicKey()
	if err != nil {
		return err
	}
	tok, meta, err := mintToken(func() (string, error) {
		return valiss.Issue(operator, acct.Name, pub, acct.Scopes, validity(acct.Expires, acct.NotBefore)...)
	}, acct.Name, pub, generated)
	if err != nil {
		return err
	}
	seed, err := subject.Seed()
	if err != nil {
		return err
	}
	fmt.Fprint(out, creds.Format(creds.Creds{AccountToken: tok, Seed: seed}))
	return writeMeta(msg, credsMeta{Account: &meta})
}

// mintUser writes user-level creds: the account-signed user token and the
// user seed (absent for bearer users). With a non-nil operator (-bundle)
// the creds also embed a freshly signed account token; without it the
// server resolves the account token by other means.
func mintUser(out, msg io.Writer, operator nkeys.KeyPair, acct manifest.Account, userName string) error {
	user, ok := acct.User(userName)
	if !ok {
		return fmt.Errorf("user %q not found under account %q", userName, acct.Name)
	}
	if err := checkNotExpired(acct.Name, acct.Expires); err != nil {
		return err
	}
	if err := checkNotExpired(acct.Name+"/"+user.Name, user.Expires); err != nil {
		return err
	}
	if acct.Key == "" {
		return fmt.Errorf("account %q has no key in the manifest: user tokens are signed by the account seed, add the key and provide VALISS_SEED_<key>", acct.Name)
	}
	account, err := seedFromEnv(acct.Key)
	if err != nil {
		return err
	}

	var (
		bundle   creds.Creds
		acctMeta *tokenMeta
	)
	if operator != nil {
		tok, meta, err := mintToken(func() (string, error) {
			return valiss.Issue(operator, acct.Name, acct.Key, acct.Scopes, validity(acct.Expires, acct.NotBefore)...)
		}, acct.Name, acct.Key, false)
		if err != nil {
			return err
		}
		bundle.AccountToken = tok
		acctMeta = &meta
	}
	subject, generated, err := subjectKey(user.Key, nkeys.CreateUser)
	if err != nil {
		return err
	}
	userPub, err := subject.PublicKey()
	if err != nil {
		return err
	}
	opts := validity(user.Expires, user.NotBefore)
	if user.Bearer {
		// Bearer creds carry no seed: for a generated pair the seed is
		// discarded, making the token the sole credential.
		opts = append(opts, valiss.WithBearer())
	} else {
		if bundle.Seed, err = subject.Seed(); err != nil {
			return err
		}
	}
	userTok, userMeta, err := mintToken(func() (string, error) {
		return valiss.IssueUser(account, user.Name, userPub, user.Scopes, opts...)
	}, user.Name, userPub, generated)
	if err != nil {
		return err
	}
	bundle.UserToken = userTok

	fmt.Fprint(out, creds.Format(bundle))
	return writeMeta(msg, credsMeta{Account: acctMeta, User: &userMeta})
}

// mintToken mints a token via issue, decodes it back for its jti and
// validity, and builds the metadata entry.
func mintToken(issue func() (string, error), name, pub string, generated bool) (string, tokenMeta, error) {
	tok, err := issue()
	if err != nil {
		return "", tokenMeta{}, fmt.Errorf("mint %q: %w", name, err)
	}
	// The token was minted in-process; decoding only re-reads its claims.
	claims, err := valiss.Decode(tok)
	if err != nil {
		return "", tokenMeta{}, fmt.Errorf("mint %q: %w", name, err)
	}
	meta := tokenMeta{
		Name:      name,
		Key:       pub,
		Generated: generated,
		JTI:       claims.ID,
	}
	if !claims.ExpiresAt.IsZero() {
		meta.Expires = claims.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if !claims.NotBefore.IsZero() {
		meta.NotBefore = claims.NotBefore.UTC().Format(time.RFC3339)
	}
	return tok, meta, nil
}

// subjectKey resolves the subject key pair: from the environment when the
// manifest names a key, freshly generated otherwise.
func subjectKey(pub string, create func() (nkeys.KeyPair, error)) (kp nkeys.KeyPair, generated bool, err error) {
	if pub != "" {
		kp, err = seedFromEnv(pub)
		return kp, false, err
	}
	kp, err = create()
	return kp, true, err
}

// seedFromEnv loads the seed for a public key from VALISS_SEED_<pub> and
// checks that it actually derives that key.
func seedFromEnv(pub string) (nkeys.KeyPair, error) {
	name := "VALISS_SEED_" + pub
	raw := os.Getenv(name)
	if raw == "" {
		return nil, fmt.Errorf("seed for %s required: set $%s", pub, name)
	}
	kp, err := nkeys.FromSeed([]byte(strings.TrimSpace(raw)))
	if err != nil {
		return nil, fmt.Errorf("$%s: %w", name, err)
	}
	derived, err := kp.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("$%s: %w", name, err)
	}
	if derived != pub {
		return nil, fmt.Errorf("$%s: seed derives %s, not %s", name, derived, pub)
	}
	return kp, nil
}

func writeMeta(w io.Writer, meta credsMeta) error {
	enc := yaml.NewEncoder(w)
	defer enc.Close()
	return enc.Encode(meta)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "valiss: %s\n", err)
	os.Exit(1)
}
