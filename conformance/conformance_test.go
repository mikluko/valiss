// Package conformance runs the language-neutral valiss spec-1 vectors
// (spec/vectors/*.json) against the Go reference implementation. It loads each
// category file, invokes the library entrypoint named by each case's op, and
// asserts the runner contract from vectors/README.md: on expect.ok the op must
// succeed and every claim in expect.claims must match; otherwise it must fail
// and the library error must map to expect.reason (a §7 reason code).
package conformance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"valiss.dev/valiss"
	"valiss.dev/valiss/creds"
)

// reasonSubstrings maps each spec §7 reason code to the substrings the
// reference library's descriptive error must contain for a failure to reduce
// to that code. Each entry is grounded in SPEC-1.md §7, which cites the source
// line that raises the condition; the substrings are the stable fragments of
// those valiss-go error strings.
//
// Substrings are chosen to be mutually unambiguous across the reasons a single
// op can return. Two collisions to note:
//   - "valiss: token signature: <e>" (part-3 base64 decode) reduces to
//     malformed, while "valiss: token signature verification failed" reduces to
//     bad_signature: the trailing colon in the former keeps them distinct.
//   - message.go's "not signed by the chain's user key" is cited by both §7.2
//     wrong_issuer and §7.4 chain_user_mismatch; the more specific message code
//     wins, so it is mapped to chain_user_mismatch here.
var reasonSubstrings = map[string][]string{
	// §7.1 envelope / decode
	"malformed": {
		"malformed token",  // not three parts (token.go:186)
		"token header:",    // header not base64url or not JSON (token.go:190-199)
		"token claims:",    // payload not base64url or not JSON (token.go:229-241)
		"token signature:", // signature not base64url (token.go:247-249)
		// creds envelope (creds.go between/checkVersion)
		"not closed", "unexpected content", "no content before",
	},
	"unsupported_type":    {"unsupported token type"},                          // token.go:201-202
	"unsupported_version": {"unsupported wire version", "unsupported version"}, // token.go:219-220; creds.go:135
	"bad_issuer_key":      {"token issuer:"},                                   // token.go:243-245
	"bad_signature":       {"token signature verification failed"},             // token.go:251-252

	// §7.2 token semantics
	"wrong_type": {
		"not an operator token", "not an account token",
		"not a user token", "not a message token",
	}, // token.go:356/381/406; message.go:294
	"wrong_issuer": {
		"not self-signed by the expected",    // operator (token.go:359)
		"not signed by the expected issuer",  // account (token.go:384)
		"not signed by the expected account", // user (token.go:409)
		"not self-signed by its user key",    // message iss != sub (message.go:297)
	},
	"wrong_subject_role": {"subject is not"}, // token.go:362/387/412; message.go:300

	// §7.3 request / credential
	"missing":                {"no token markers"},                      // creds.go:99 (parse_creds "missing")
	"skew":                   {"skew window", "bad request timestamp"},  // sign.go:64-69
	"bad_signature_encoding": {"bad request signature encoding"},        // sign.go:71-72
	"bad_request_signature":  {"request signature verification failed"}, // sign.go:79-80

	// entity generation floor (ADR 0022)
	"generation_below_floor": {"below floor"}, // generation.go CheckGenerationFloor

	// §7.4 message-specific
	"no_chain":            {"carries no chain"},                   // message.go:22/305
	"chain_mismatch":      {"differs from the supplied chain"},    // message.go:309
	"chain_user_mismatch": {"not signed by the chain's user key"}, // message.go:324
	"wrong_audience":      {"message token audience"},             // message.go:372
	"checksum_missing":    {"carries no checksum"},                // message.go:377/383
	"checksum_mismatch":   {"payload checksum mismatch"},          // message.go:379
}

// mapsToReason reports whether err's message contains any substring registered
// for the expected reason code.
func mapsToReason(err error, reason string) bool {
	subs, ok := reasonSubstrings[reason]
	if !ok {
		return false
	}
	msg := err.Error()
	for _, s := range subs {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// -------- vector schema --------

type vectorFile struct {
	Spec  int          `json:"spec"`
	Cases []vectorCase `json:"cases"`
}

type vectorCase struct {
	ID     string         `json:"id"`
	Desc   string         `json:"desc"`
	Op     string         `json:"op"`
	Input  map[string]any `json:"input"`
	Args   map[string]any `json:"args"`
	Expect struct {
		OK     bool           `json:"ok"`
		Reason string         `json:"reason"`
		Claims map[string]any `json:"claims"`
	} `json:"expect"`
}

func vectorsDir() string {
	if d := os.Getenv("VALISS_VECTORS_DIR"); d != "" {
		return d
	}
	return "../../spec/vectors"
}

func TestConformance(t *testing.T) {
	dir := vectorsDir()
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("vectors dir %q not found (set VALISS_VECTORS_DIR to run): %v", dir, err)
	}
	for _, name := range []string{"tokens.json", "signatures.json", "creds.json", "messages.json", "generations.json"} {
		path := filepath.Join(dir, name)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var vf vectorFile
		require.NoErrorf(t, json.Unmarshal(raw, &vf), "parse %s", path)
		require.Equalf(t, 1, vf.Spec, "%s: unexpected spec version", name)
		require.NotEmptyf(t, vf.Cases, "%s: no cases", name)

		for _, c := range vf.Cases {
			t.Run(c.ID, func(t *testing.T) {
				runCase(t, c)
			})
		}
	}
}

// runCase invokes the op named by c and asserts the runner contract.
func runCase(t *testing.T, c vectorCase) {
	claims, err := invoke(t, c)
	if c.Expect.OK {
		require.NoErrorf(t, err, "%s: expected success", c.ID)
		for key, want := range c.Expect.Claims {
			got, ok := claims[key]
			require.Truef(t, ok, "%s: claim %q not exposed", c.ID, key)
			assert.Truef(t, claimEqual(want, got), "%s: claim %q = %#v, want %#v", c.ID, key, got, want)
		}
		return
	}
	require.Errorf(t, err, "%s: expected failure with reason %q", c.ID, c.Expect.Reason)
	assert.Truef(t, mapsToReason(err, c.Expect.Reason),
		"%s: error %q does not map to reason %q", c.ID, err.Error(), c.Expect.Reason)
}

// invoke dispatches a case to its library entrypoint, returning the exposed
// claims (on success) and any error.
func invoke(t *testing.T, c vectorCase) (map[string]any, error) {
	switch c.Op {
	case "verify_operator":
		oc, err := valiss.VerifyOperator(str(c.Input, "token"), str(c.Args, "operator_pub"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"subject": oc.Subject, "name": oc.Name, "epoch": oc.Epoch}, nil

	case "verify_account":
		ac, err := valiss.VerifyAccount(str(c.Input, "token"), str(c.Args, "operator_pub"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"subject": ac.Subject, "name": ac.Name, "epoch": ac.Epoch}, nil

	case "verify_user":
		uc, err := valiss.VerifyUser(str(c.Input, "token"), str(c.Args, "account_pub"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"subject": uc.Subject, "name": uc.Name, "epoch": uc.Epoch, "bearer": uc.Bearer}, nil

	case "verify_message":
		mc, err := valiss.VerifyMessage(str(c.Input, "token"), str(c.Args, "operator_pub"), messageOpts(t, c.Args)...)
		if err != nil {
			return nil, err
		}
		return map[string]any{"subject": mc.Subject, "audience": mc.Audience, "checksum": mc.Checksum, "epoch": mc.Epoch}, nil

	case "verify_signature":
		err := valiss.VerifySignature(
			str(c.Args, "subject_pub"),
			str(c.Input, "timestamp"),
			str(c.Input, "signature"),
			[]byte(str(c.Args, "context")),
			parseTime(t, str(c.Args, "now")),
			parseDur(t, str(c.Args, "skew")),
		)
		if err != nil {
			return nil, err
		}
		return map[string]any{}, nil

	case "verify_generation_floor":
		ac, err := valiss.VerifyAccount(str(c.Input, "token"), str(c.Args, "operator_pub"))
		if err != nil {
			return nil, err
		}
		// The floor is keyed by the token's issuing entity; enforce toggles
		// whether the verifier applies floors at all (optional at the verifier).
		var floors valiss.FloorList
		if enforce, _ := c.Args["enforce"].(bool); enforce {
			al := valiss.NewStaticAllowlist()
			al.SetFloor(ac.Issuer, uint64(numArg(c.Args, "floor")))
			floors = al
		}
		if err := valiss.CheckGenerationFloor(ac.Ext, ac.Issuer, floors); err != nil {
			return nil, err
		}
		out := map[string]any{"subject": ac.Subject}
		gen, ok, err := valiss.ExtOf[valiss.GenerationExt](ac.Ext)
		if err != nil {
			return nil, err
		}
		if ok {
			out["generation"] = gen.Generation
		}
		return out, nil

	case "parse_creds":
		cr, err := creds.Parse(str(c.Input, "creds"))
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"has_account": cr.AccountToken != "",
			"has_user":    cr.UserToken != "",
			"has_seed":    len(cr.Seed) > 0,
		}, nil

	default:
		t.Fatalf("%s: unknown op %q", c.ID, c.Op)
		return nil, nil
	}
}

// messageOpts builds VerifyMessage options from a case's args.
func messageOpts(t *testing.T, args map[string]any) []valiss.VerifyMessageOption {
	var opts []valiss.VerifyMessageOption
	if v, ok := args["now"]; ok {
		opts = append(opts, valiss.At(parseTime(t, v.(string))))
	}
	if v, ok := args["skew"]; ok {
		opts = append(opts, valiss.WithMessageSkew(parseDur(t, v.(string))))
	}
	if v, ok := args["audience"]; ok {
		opts = append(opts, valiss.ExpectAudience(v.(string)))
	}
	if v, ok := args["require_checksum"]; ok && v.(bool) {
		opts = append(opts, valiss.RequireChecksum())
	}
	if v, ok := args["payload"]; ok {
		opts = append(opts, valiss.WithPayload([]byte(v.(string))))
	}
	acc, accOK := args["chain_account"]
	usr, usrOK := args["chain_user"]
	if accOK && usrOK {
		opts = append(opts, valiss.WithChainTokens(acc.(string), usr.(string)))
	}
	return opts
}

// -------- helpers --------

func str(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// numArg reads a numeric case argument. JSON numbers decode to float64; an
// integer literal set by a Go-side test reads directly.
func numArg(m map[string]any, key string) int {
	switch n := m[key].(type) {
	case float64:
		return int(n)
	case int:
		return n
	default:
		return 0
	}
}

func parseTime(t *testing.T, s string) time.Time {
	ts, err := time.Parse(time.RFC3339Nano, s)
	require.NoErrorf(t, err, "parse time %q", s)
	return ts
}

func parseDur(t *testing.T, s string) time.Duration {
	d, err := time.ParseDuration(s)
	require.NoErrorf(t, err, "parse duration %q", s)
	return d
}

// claimEqual compares an expected claim (as decoded from JSON: string, bool, or
// float64 number) against the value the library exposed (string, bool, or a Go
// integer for epoch).
func claimEqual(want, got any) bool {
	switch w := want.(type) {
	case float64: // JSON number, e.g. epoch
		return fmt.Sprintf("%v", got) == fmt.Sprintf("%d", int64(w))
	default:
		return fmt.Sprintf("%v", want) == fmt.Sprintf("%v", got)
	}
}
