// Command tokenator manages tenant credentials for gRPC services using the
// operator/tenant nkey model (see github.com/mikluko/tokenator). It persists
// keys in a keystore so tenants can be managed across invocations, nsc-style.
//
//	tokenator init                                  # create the operator key
//	tokenator pub                                   # print the server trust anchor
//	tokenator add acme -scope 'call:/pkg.Svc/*'     # create tenant + issue token
//	tokenator creds acme > acme.creds               # client credential bundle
//	tokenator issue acme -ttl 168h                  # re-issue a tenant token
//	tokenator list                                  # list tenants
//
// The keystore defaults to $TOKENATOR_HOME or ~/.tokenator; the server reads
// the operator public key (pub) and the allowlist file (allowlist path shown
// by `tokenator allowlist`).
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mikluko/tokenator"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	ks, err := openKeystore()
	if err != nil {
		fatal(err)
	}
	switch os.Args[1] {
	case "init":
		err = cmdInit(ks)
	case "pub":
		err = cmdPub(ks)
	case "add":
		err = cmdAdd(ks, os.Args[2:])
	case "issue":
		err = cmdIssue(ks, os.Args[2:])
	case "creds":
		err = cmdCreds(ks, os.Args[2:])
	case "list":
		err = cmdList(ks)
	case "allowlist":
		fmt.Println(ks.AllowlistPath())
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fatal(err)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: tokenator <command> [flags]

commands:
  init                              create the operator key (trust anchor)
  pub                               print the operator public key (server anchor)
  add ID   [-scope S ...] [-ttl D]  create a tenant, issue a token, allowlist it
  issue ID [-scope S ...] [-ttl D]  re-issue a token for an existing tenant
  creds ID                          print the tenant creds bundle (token + seed)
  list                              list tenants
  allowlist                         print the allowlist file path

keystore: $TOKENATOR_HOME or ~/.tokenator
`)
}

func openKeystore() (*tokenator.Keystore, error) {
	dir := os.Getenv("TOKENATOR_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		dir = filepath.Join(home, ".tokenator")
	}
	return tokenator.OpenKeystore(dir)
}

func cmdInit(ks *tokenator.Keystore) error {
	op, err := ks.InitOperator()
	if err != nil {
		return err
	}
	pub, err := op.PublicKey()
	if err != nil {
		return err
	}
	fmt.Printf("operator ready\npublic key (server trust anchor): %s\n", pub)
	return nil
}

func cmdPub(ks *tokenator.Keystore) error {
	op, err := ks.Operator()
	if err != nil {
		return fmt.Errorf("no operator; run `tokenator init` first: %w", err)
	}
	pub, err := op.PublicKey()
	if err != nil {
		return err
	}
	fmt.Println(pub)
	return nil
}

func cmdAdd(ks *tokenator.Keystore, args []string) error {
	id, scopes, ttl, err := parseIssueFlags("add", args)
	if err != nil {
		return err
	}
	if _, err := ks.CreateTenant(id); err != nil {
		return err
	}
	if _, err := issueFor(ks, id, scopes, ttl); err != nil {
		return err
	}
	fmt.Printf("tenant %q created and allowlisted\nrun `tokenator creds %s` for the client bundle\n", id, id)
	return nil
}

func cmdIssue(ks *tokenator.Keystore, args []string) error {
	id, scopes, ttl, err := parseIssueFlags("issue", args)
	if err != nil {
		return err
	}
	if _, err := ks.Tenant(id); err != nil {
		return fmt.Errorf("unknown tenant %q: %w", id, err)
	}
	if _, err := issueFor(ks, id, scopes, ttl); err != nil {
		return err
	}
	fmt.Printf("re-issued token for %q\n", id)
	return nil
}

func cmdCreds(ks *tokenator.Keystore, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("creds requires a tenant id: creds ID")
	}
	id := args[0]
	tenant, err := ks.Tenant(id)
	if err != nil {
		return fmt.Errorf("unknown tenant %q: %w", id, err)
	}
	token, err := ks.Token(id)
	if err != nil {
		return err
	}
	seed, err := tenant.Seed()
	if err != nil {
		return err
	}
	fmt.Print(tokenator.FormatCreds(token, seed))
	return nil
}

func cmdList(ks *tokenator.Keystore) error {
	ids, err := ks.Tenants()
	if err != nil {
		return err
	}
	for _, id := range ids {
		fmt.Println(id)
	}
	return nil
}

// issueFor mints a token for a tenant and records its id in the allowlist.
func issueFor(ks *tokenator.Keystore, id string, scopes []string, ttl time.Duration) (string, error) {
	op, err := ks.Operator()
	if err != nil {
		return "", fmt.Errorf("no operator; run `tokenator init` first: %w", err)
	}
	tenant, err := ks.Tenant(id)
	if err != nil {
		return "", err
	}
	pub, err := tenant.PublicKey()
	if err != nil {
		return "", err
	}
	token, err := tokenator.Issue(op, id, pub, scopes, ttl)
	if err != nil {
		return "", err
	}
	opPub, err := op.PublicKey()
	if err != nil {
		return "", err
	}
	claims, err := tokenator.Verify(token, opPub)
	if err != nil {
		return "", err
	}
	if err := ks.AppendAllowlist(claims.ID); err != nil {
		return "", err
	}
	if err := ks.WriteToken(id, token); err != nil {
		return "", err
	}
	return token, nil
}

// parseIssueFlags takes the tenant id as the first argument (ID-first), then
// parses the remaining flags; Go's flag package would otherwise stop at the
// positional.
func parseIssueFlags(name string, args []string) (id string, scopes []string, ttl time.Duration, err error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return "", nil, 0, fmt.Errorf("%s requires a tenant id: %s ID [flags]", name, name)
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	var scope multiFlag
	fs.Var(&scope, "scope", "grant a scope (repeatable); e.g. call:/pkg.Svc/* or call:*")
	d := fs.Duration("ttl", 30*24*time.Hour, "token time-to-live")
	if err := fs.Parse(args[1:]); err != nil {
		return "", nil, 0, err
	}
	if fs.NArg() != 0 {
		return "", nil, 0, fmt.Errorf("unexpected arguments after %s ID; flags must follow the id", name)
	}
	return args[0], scope, *d, nil
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "tokenator: %s\n", err)
	os.Exit(1)
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }
