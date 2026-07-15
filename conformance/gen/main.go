// Command gen emits the valiss spec-1 conformance vectors.
//
// It mints valid artifacts with the reference library (valiss.dev/valiss and
// valiss.dev/valiss/creds) from a set of FIXED nkey seeds (below), so the
// public keys, and therefore the vectors, are stable across regenerations
// (token iat is mint-time, so byte-for-byte reproducibility is not a goal; the
// committed vectors are the frozen authority, per vectors/README.md).
//
// Negative cases are produced by targeted corruption of a valid artifact
// (flip a signature byte, rewrite the header version, truncate an envelope) or,
// where the happy-path issuers refuse to mint the needed adversarial shape
// (a wrong-role subject, a mismatched self-issue, a non-nkey issuer), by
// hand-signing a token in the exact version-1 wire format with craft below.
// Every negative targets ONLY a reason its op can actually return, per the
// operations table in vectors/README.md.
//
// Usage: go run ./conformance/gen [target-dir]   (default ../../spec/vectors)
package main

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/nats-io/nkeys"

	"valiss.dev/valiss"
	"valiss.dev/valiss/creds"
)

// Fixed nkey seeds. Generated once (nkeys.CreateOperator/Account/User) and
// pasted verbatim so every regeneration derives the same public keys. operator2
// and account2 stand in as the "wrong" issuer/anchor in cross cases; user2 is a
// second delegate used by the chain-mismatch message cases.
const (
	operatorSeed  = "SOANMXCDVPJNUIJXPXVCDZL6A5EMLCLYPUYEDOHXWW5U5FS4JBLNBZMVYM"
	operator2Seed = "SOAG3POEDOVSNMRENOJ64RTCEO5QWYGZTGWCHJENEVHIXPA2YLKOTOCYX4"
	accountSeed   = "SAAOQP3V6WPJHPL55RZYGMFV54RLRTD4W3TLEZ4BOGPEGIGUUCARECGMY4"
	account2Seed  = "SAAPF6DUWDT7QH4ECQFYYY57PDDXHKYGLBCNXO7JGWSL5VSHLF3AXLXCT4"
	userSeed      = "SUANPK2WISHRP2IRCIEIMPHNKQOXE2JTDPHZ3WVHBYSNLI72A6IGVXOEJQ"
	user2Seed     = "SUAAE6Y4C4WTSMENWSS4TURLALNSYXHVFWN23NAP577HG7CTP7KYF6AJTM"
)

// keyset holds the fixed key material: the seed keypairs and their derived
// public keys.
type keyset struct {
	op, op2   nkeys.KeyPair
	acc, acc2 nkeys.KeyPair
	usr, usr2 nkeys.KeyPair

	opPub, op2Pub   string
	accPub, acc2Pub string
	usrPub, usr2Pub string
}

func mustKP(seed string) nkeys.KeyPair {
	kp, err := nkeys.FromSeed([]byte(seed))
	if err != nil {
		panic(fmt.Sprintf("gen: bad fixed seed %q: %v", seed, err))
	}
	return kp
}

func mustPub(kp nkeys.KeyPair) string {
	pub, err := kp.PublicKey()
	if err != nil {
		panic("gen: public key: " + err.Error())
	}
	return pub
}

func loadKeys() keyset {
	k := keyset{
		op:   mustKP(operatorSeed),
		op2:  mustKP(operator2Seed),
		acc:  mustKP(accountSeed),
		acc2: mustKP(account2Seed),
		usr:  mustKP(userSeed),
		usr2: mustKP(user2Seed),
	}
	k.opPub, k.op2Pub = mustPub(k.op), mustPub(k.op2)
	k.accPub, k.acc2Pub = mustPub(k.acc), mustPub(k.acc2)
	k.usrPub, k.usr2Pub = mustPub(k.usr), mustPub(k.usr2)
	return k
}

// -------- vector schema (mirrors vectors/README.md) --------

type file struct {
	Spec  int    `json:"spec"`
	Cases []kase `json:"cases"`
}

type expect struct {
	OK     bool           `json:"ok"`
	Reason string         `json:"reason,omitempty"`
	Claims map[string]any `json:"claims,omitempty"`
}

type kase struct {
	ID     string         `json:"id"`
	Desc   string         `json:"desc"`
	Op     string         `json:"op"`
	Input  map[string]any `json:"input"`
	Args   map[string]any `json:"args,omitempty"`
	Expect expect         `json:"expect"`
}

// -------- envelope corruption helpers (operate on a real token string) --------

func splitParts(tok string) [3]string {
	p := strings.SplitN(tok, ".", 3)
	if len(p) != 3 {
		panic("gen: token does not have three parts: " + tok)
	}
	return [3]string{p[0], p[1], p[2]}
}

// truncate2 drops the signature part, leaving a two-part envelope (malformed).
func truncate2(tok string) string {
	p := splitParts(tok)
	return p[0] + "." + p[1]
}

// flipSig flips the first byte of the base64url signature so Ed25519
// verification fails (bad_signature).
func flipSig(tok string) string {
	p := splitParts(tok)
	sig, err := base64.RawURLEncoding.DecodeString(p[2])
	if err != nil {
		panic("gen: decode signature: " + err.Error())
	}
	sig[0] ^= 0xFF
	return p[0] + "." + p[1] + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// reHeader replaces the header part with the base64url of headerJSON, leaving
// the payload and (now stale) signature; version/type dispatch is read from the
// header before the signature is checked.
func reHeader(tok, headerJSON string) string {
	p := splitParts(tok)
	return base64.RawURLEncoding.EncodeToString([]byte(headerJSON)) + "." + p[1] + "." + p[2]
}

const (
	headerVer2      = `{"typ":"JWT","alg":"ed25519-nkey","ver":2}`
	headerBadAlg    = `{"typ":"JWT","alg":"ed25519-broken","ver":1}`
	validHeaderJSON = `{"typ":"JWT","alg":"ed25519-nkey","ver":1}`
)

// badHeaderB64 replaces the header with a string that is not valid base64url
// (malformed).
func badHeaderB64(tok string) string {
	p := splitParts(tok)
	return "!!!not-base64!!!" + "." + p[1] + "." + p[2]
}

// -------- hand-signed crafting (for shapes the library refuses to mint) --------

type craftChain struct {
	Account string `json:"account,omitempty"`
	User    string `json:"user,omitempty"`
}

// craftBody mirrors the valiss body across all four levels; unused fields stay
// zero and drop out via omitempty, exactly as the library's per-level bodies do.
type craftBody struct {
	Type     string      `json:"type"`
	Epoch    uint64      `json:"epoch,omitempty"`
	Bearer   bool        `json:"bearer,omitempty"`
	Checksum string      `json:"checksum,omitempty"`
	Chain    *craftChain `json:"chain,omitempty"`
}

// craftWire mirrors valiss's version-1 claims document field-for-field and in
// order, so a crafted token is byte-shaped like a real one.
type craftWire struct {
	ID        string    `json:"jti,omitempty"`
	IssuedAt  int64     `json:"iat,omitempty"`
	Issuer    string    `json:"iss,omitempty"`
	Name      string    `json:"name,omitempty"`
	Subject   string    `json:"sub,omitempty"`
	Audience  string    `json:"aud,omitempty"`
	Expires   int64     `json:"exp,omitempty"`
	NotBefore int64     `json:"nbf,omitempty"`
	Valiss    craftBody `json:"valiss"`
}

// craft hand-signs w with signer in the exact version-1 wire format (the same
// steps as valiss's unexported encodeV1: frozen header, content-derived jti,
// Ed25519 over base64url(header)+"."+base64url(payload)). It sets Issuer from w
// verbatim (not from signer) so a case can mint a token whose iss disagrees with
// the signing key or is not a valid nkey; verification then fails at exactly the
// intended stage.
func craft(signer nkeys.KeyPair, w craftWire) string {
	if w.IssuedAt == 0 {
		w.IssuedAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	}
	w.ID = ""
	unhashed, err := json.Marshal(&w)
	if err != nil {
		panic("gen: craft marshal: " + err.Error())
	}
	digest := sha256.Sum256(unhashed)
	w.ID = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:])
	payload, err := json.Marshal(&w)
	if err != nil {
		panic("gen: craft marshal: " + err.Error())
	}
	signingInput := base64.RawURLEncoding.EncodeToString([]byte(validHeaderJSON)) +
		"." + base64.RawURLEncoding.EncodeToString(payload)
	sig, err := signer.Sign([]byte(signingInput))
	if err != nil {
		panic("gen: craft sign: " + err.Error())
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// -------- shared timing constants for the fixed vectors --------

var (
	// fixedNow is the verification instant the message and signature cases pin.
	fixedNow = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	// farFuture keeps minted-with-real-library artifacts valid at fixedNow.
	farFuture = time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
	skew2m    = "2m"
)

func must[T any](v T, err error) T {
	if err != nil {
		panic("gen: " + err.Error())
	}
	return v
}

// -------- token vectors (verify_operator / verify_account / verify_user) --------

func tokenCases(k keyset) file {
	// Valid artifacts minted with the real library.
	opTok := must(valiss.IssueOperator(k.op, valiss.WithName("acme-trust"), valiss.WithEpoch(7)))
	accTok := must(valiss.IssueAccount(k.op, k.accPub, valiss.WithName("acme"), valiss.WithEpoch(7)))
	accUnnamed := must(valiss.IssueAccount(k.op, k.accPub, valiss.WithEpoch(7)))
	usrTok := must(valiss.IssueUser(k.acc, k.usrPub, valiss.WithName("alice")))
	usrBearer := must(valiss.IssueUser(k.acc, k.usrPub, valiss.WithName("kiosk"), valiss.WithBearer()))

	opArgs := func() map[string]any { return map[string]any{"operator_pub": k.opPub} }
	accArgs := func() map[string]any { return map[string]any{"operator_pub": k.opPub} }
	usrArgs := func() map[string]any { return map[string]any{"account_pub": k.accPub} }

	cases := []kase{
		// --- positives ---
		{
			ID: "operator/valid", Desc: "self-signed operator token with epoch verifies against the pinned operator key",
			Op: "verify_operator", Input: map[string]any{"token": opTok}, Args: opArgs(),
			Expect: expect{OK: true, Claims: map[string]any{"subject": k.opPub, "name": "acme-trust", "epoch": 7}},
		},
		{
			ID: "account/valid", Desc: "operator-signed account token verifies against the pinned operator key",
			Op: "verify_account", Input: map[string]any{"token": accTok}, Args: accArgs(),
			Expect: expect{OK: true, Claims: map[string]any{"subject": k.accPub, "name": "acme", "epoch": 7}},
		},
		{
			ID: "account/unnamed-falls-back-to-subject", Desc: "an account token with no name exposes the subject key as its name",
			Op: "verify_account", Input: map[string]any{"token": accUnnamed}, Args: accArgs(),
			Expect: expect{OK: true, Claims: map[string]any{"subject": k.accPub, "name": k.accPub}},
		},
		{
			ID: "user/valid", Desc: "account-signed user token verifies against the delegating account key",
			Op: "verify_user", Input: map[string]any{"token": usrTok}, Args: usrArgs(),
			Expect: expect{OK: true, Claims: map[string]any{"subject": k.usrPub, "name": "alice", "bearer": false}},
		},
		{
			ID: "user/bearer", Desc: "a bearer user token exposes bearer=true",
			Op: "verify_user", Input: map[string]any{"token": usrBearer}, Args: usrArgs(),
			Expect: expect{OK: true, Claims: map[string]any{"subject": k.usrPub, "name": "kiosk", "bearer": true}},
		},

		// --- malformed (envelope) ---
		{
			ID: "account/malformed-two-parts", Desc: "an envelope truncated to two parts is malformed",
			Op: "verify_account", Input: map[string]any{"token": truncate2(accTok)}, Args: accArgs(),
			Expect: expect{OK: false, Reason: "malformed"},
		},
		{
			ID: "account/malformed-header-not-base64", Desc: "a header that is not valid base64url is malformed",
			Op: "verify_account", Input: map[string]any{"token": badHeaderB64(accTok)}, Args: accArgs(),
			Expect: expect{OK: false, Reason: "malformed"},
		},

		// --- unsupported type / version (header) ---
		{
			ID: "account/unsupported-type", Desc: "an unrecognized alg in the header is an unsupported type",
			Op: "verify_account", Input: map[string]any{"token": reHeader(accTok, headerBadAlg)}, Args: accArgs(),
			Expect: expect{OK: false, Reason: "unsupported_type"},
		},
		{
			ID: "account/unsupported-version", Desc: "a header ver the parser does not implement is an unsupported version",
			Op: "verify_account", Input: map[string]any{"token": reHeader(accTok, headerVer2)}, Args: accArgs(),
			Expect: expect{OK: false, Reason: "unsupported_version"},
		},

		// --- bad issuer key / bad signature ---
		{
			ID: "account/bad-issuer-key", Desc: "an iss that is not a decodable nkey is rejected before signature check",
			Op: "verify_account",
			Input: map[string]any{"token": craft(k.op, craftWire{
				Issuer: "not-an-nkey", Subject: k.accPub, Name: "acme",
				Valiss: craftBody{Type: "account", Epoch: 7},
			})},
			Args: accArgs(), Expect: expect{OK: false, Reason: "bad_issuer_key"},
		},
		{
			ID: "account/bad-signature", Desc: "a flipped signature byte fails Ed25519 verification",
			Op: "verify_account", Input: map[string]any{"token": flipSig(accTok)}, Args: accArgs(),
			Expect: expect{OK: false, Reason: "bad_signature"},
		},

		// --- wrong type ---
		{
			ID: "operator/wrong-type", Desc: "an account token presented to verify_operator is the wrong type",
			Op: "verify_operator", Input: map[string]any{"token": accTok}, Args: opArgs(),
			Expect: expect{OK: false, Reason: "wrong_type"},
		},
		{
			ID: "account/wrong-type", Desc: "a user token presented to verify_account is the wrong type",
			Op: "verify_account", Input: map[string]any{"token": usrTok}, Args: accArgs(),
			Expect: expect{OK: false, Reason: "wrong_type"},
		},
		{
			ID: "user/wrong-type", Desc: "an account token presented to verify_user is the wrong type",
			Op: "verify_user", Input: map[string]any{"token": accTok}, Args: usrArgs(),
			Expect: expect{OK: false, Reason: "wrong_type"},
		},

		// --- wrong issuer ---
		{
			ID: "operator/wrong-issuer", Desc: "an operator token checked against a different pinned key is not self-signed by it",
			Op: "verify_operator", Input: map[string]any{"token": opTok}, Args: map[string]any{"operator_pub": k.op2Pub},
			Expect: expect{OK: false, Reason: "wrong_issuer"},
		},
		{
			ID: "account/wrong-issuer", Desc: "an account token checked against the wrong operator key has the wrong issuer",
			Op: "verify_account", Input: map[string]any{"token": accTok}, Args: map[string]any{"operator_pub": k.op2Pub},
			Expect: expect{OK: false, Reason: "wrong_issuer"},
		},
		{
			ID: "user/wrong-issuer", Desc: "a user token checked against the wrong account key has the wrong issuer",
			Op: "verify_user", Input: map[string]any{"token": usrTok}, Args: map[string]any{"account_pub": k.acc2Pub},
			Expect: expect{OK: false, Reason: "wrong_issuer"},
		},

		// --- wrong subject role (hand-signed: the issuers refuse a wrong-role subject) ---
		{
			ID:   "operator/wrong-subject-role",
			Desc: "a self-signed operator-type token whose key is not an operator-role nkey has the wrong subject role",
			Op:   "verify_operator",
			Input: map[string]any{"token": craft(k.acc, craftWire{
				Issuer: k.accPub, Subject: k.accPub, Name: "impostor",
				Valiss: craftBody{Type: "operator"},
			})},
			Args:   map[string]any{"operator_pub": k.accPub},
			Expect: expect{OK: false, Reason: "wrong_subject_role"},
		},
		{
			ID:   "account/wrong-subject-role",
			Desc: "an operator-signed account-type token whose subject is a user key has the wrong subject role",
			Op:   "verify_account",
			Input: map[string]any{"token": craft(k.op, craftWire{
				Issuer: k.opPub, Subject: k.usrPub, Name: "acme",
				Valiss: craftBody{Type: "account", Epoch: 7},
			})},
			Args:   accArgs(),
			Expect: expect{OK: false, Reason: "wrong_subject_role"},
		},
		{
			ID:   "user/wrong-subject-role",
			Desc: "an account-signed user-type token whose subject is an account key has the wrong subject role",
			Op:   "verify_user",
			Input: map[string]any{"token": craft(k.acc, craftWire{
				Issuer: k.accPub, Subject: k.acc2Pub, Name: "alice",
				Valiss: craftBody{Type: "user"},
			})},
			Args:   usrArgs(),
			Expect: expect{OK: false, Reason: "wrong_subject_role"},
		},
	}
	return file{Spec: 1, Cases: cases}
}

// -------- signature vectors (verify_signature) --------

func signatureCases(k keyset) file {
	// A known context at a known time, signed by the user seed.
	ctx := "http\nGET\napi.example.com\n/v1/widgets\n"
	ts, sig := must2(valiss.SignRequest(k.usr, fixedNow, []byte(ctx)))
	nowStr := fixedNow.Format(time.RFC3339Nano)

	baseArgs := func() map[string]any {
		return map[string]any{"subject_pub": k.usrPub, "context": ctx, "now": nowStr, "skew": skew2m}
	}

	cases := []kase{
		{
			ID: "signature/valid", Desc: "a request signature verifies against the subject key within the skew window",
			Op: "verify_signature", Input: map[string]any{"timestamp": ts, "signature": sig}, Args: baseArgs(),
			Expect: expect{OK: true},
		},
		{
			ID: "signature/skew-outside-window", Desc: "a timestamp far outside the skew window is rejected",
			Op:     "verify_signature",
			Input:  map[string]any{"timestamp": ts, "signature": sig},
			Args:   map[string]any{"subject_pub": k.usrPub, "context": ctx, "now": fixedNow.Add(10 * time.Minute).Format(time.RFC3339Nano), "skew": skew2m},
			Expect: expect{OK: false, Reason: "skew"},
		},
		{
			ID: "signature/skew-unparsable-timestamp", Desc: "an unparsable timestamp is rejected as a skew failure",
			Op:     "verify_signature",
			Input:  map[string]any{"timestamp": "not-a-timestamp", "signature": sig},
			Args:   baseArgs(),
			Expect: expect{OK: false, Reason: "skew"},
		},
		{
			ID: "signature/bad-signature-encoding", Desc: "a signature that is not valid base64std is rejected",
			Op:     "verify_signature",
			Input:  map[string]any{"timestamp": ts, "signature": corruptBase64Std(sig)},
			Args:   baseArgs(),
			Expect: expect{OK: false, Reason: "bad_signature_encoding"},
		},
		{
			ID: "signature/bad-request-signature", Desc: "a signature that decodes but does not verify is rejected",
			Op:     "verify_signature",
			Input:  map[string]any{"timestamp": ts, "signature": flipBase64Std(sig)},
			Args:   baseArgs(),
			Expect: expect{OK: false, Reason: "bad_request_signature"},
		},
		{
			ID: "signature/bad-request-signature-context", Desc: "a valid signature over a different context does not verify",
			Op:     "verify_signature",
			Input:  map[string]any{"timestamp": ts, "signature": sig},
			Args:   map[string]any{"subject_pub": k.usrPub, "context": "http\nPOST\napi.example.com\n/v1/widgets\n", "now": nowStr, "skew": skew2m},
			Expect: expect{OK: false, Reason: "bad_request_signature"},
		},
	}
	return file{Spec: 1, Cases: cases}
}

func must2[A, B any](a A, b B, err error) (A, B) {
	if err != nil {
		panic("gen: " + err.Error())
	}
	return a, b
}

// corruptBase64Std inserts a character outside the standard base64 alphabet so
// decoding fails (bad_signature_encoding).
func corruptBase64Std(sig string) string {
	return "*" + sig[1:]
}

// flipBase64Std changes one alphabet character so the signature still decodes
// (same length, valid base64std) but to different bytes that do not verify
// (bad_request_signature).
func flipBase64Std(sig string) string {
	b := []byte(sig)
	for i, c := range b {
		if c >= 'A' && c <= 'Y' { // stays inside the base64std alphabet, changes the value
			b[i] = c + 1
			return string(b)
		}
	}
	panic("gen: could not flip a base64std character")
}

// -------- creds vectors (parse_creds) --------

func credsCases(k keyset) file {
	accTok := must(valiss.IssueAccount(k.op, k.accPub, valiss.WithName("acme")))
	usrTok := must(valiss.IssueUser(k.acc, k.usrPub, valiss.WithName("alice")))

	accountLevel := creds.Format(creds.Creds{AccountToken: accTok, Seed: []byte(accountSeed)})
	userLevel := creds.Format(creds.Creds{UserToken: usrTok, Seed: []byte(userSeed)})
	bundle := creds.Format(creds.Creds{AccountToken: accTok, UserToken: usrTok, Seed: []byte(userSeed)})
	bearer := creds.Format(creds.Creds{AccountToken: accTok, UserToken: usrTok})

	// A creds file with no version header (absent header reads as current).
	noHeader := "-----BEGIN VALISS ACCOUNT TOKEN-----\n" + accTok + "\n------END VALISS ACCOUNT TOKEN------\n" +
		"\n-----BEGIN VALISS SEED-----\n" + accountSeed + "\n------END VALISS SEED------\n"

	// Negatives.
	missing := "VALISS-CREDS-VERSION: 1\n\njust some notes, no token markers here\n"
	unsupportedVersion := "VALISS-CREDS-VERSION: 2\n\n-----BEGIN VALISS ACCOUNT TOKEN-----\n" + accTok + "\n------END VALISS ACCOUNT TOKEN------\n"
	unclosed := "VALISS-CREDS-VERSION: 1\n\n-----BEGIN VALISS ACCOUNT TOKEN-----\n" + accTok + "\n"
	emptySection := "VALISS-CREDS-VERSION: 1\n\n-----BEGIN VALISS ACCOUNT TOKEN-----\n------END VALISS ACCOUNT TOKEN------\n"
	multiLine := "VALISS-CREDS-VERSION: 1\n\n-----BEGIN VALISS ACCOUNT TOKEN-----\n" + accTok + "\n" + accTok + "\n------END VALISS ACCOUNT TOKEN------\n"

	cases := []kase{
		{
			ID: "creds/account-level", Desc: "account token plus account seed parses as account-level creds",
			Op: "parse_creds", Input: map[string]any{"creds": accountLevel},
			Expect: expect{OK: true, Claims: map[string]any{"has_account": true, "has_user": false, "has_seed": true}},
		},
		{
			ID: "creds/user-level", Desc: "user token plus user seed parses as user-level creds",
			Op: "parse_creds", Input: map[string]any{"creds": userLevel},
			Expect: expect{OK: true, Claims: map[string]any{"has_account": false, "has_user": true, "has_seed": true}},
		},
		{
			ID: "creds/bundle", Desc: "account and user tokens plus a seed parse as a bundle",
			Op: "parse_creds", Input: map[string]any{"creds": bundle},
			Expect: expect{OK: true, Claims: map[string]any{"has_account": true, "has_user": true, "has_seed": true}},
		},
		{
			ID: "creds/bearer", Desc: "tokens with no seed parse as bearer creds",
			Op: "parse_creds", Input: map[string]any{"creds": bearer},
			Expect: expect{OK: true, Claims: map[string]any{"has_account": true, "has_user": true, "has_seed": false}},
		},
		{
			ID: "creds/no-version-header", Desc: "an absent version header reads as the current version",
			Op: "parse_creds", Input: map[string]any{"creds": noHeader},
			Expect: expect{OK: true, Claims: map[string]any{"has_account": true, "has_seed": true}},
		},
		{
			ID: "creds/missing", Desc: "a creds file with no token markers is rejected",
			Op: "parse_creds", Input: map[string]any{"creds": missing},
			Expect: expect{OK: false, Reason: "missing"},
		},
		{
			ID: "creds/unsupported-version", Desc: "a creds version the parser does not implement is rejected",
			Op: "parse_creds", Input: map[string]any{"creds": unsupportedVersion},
			Expect: expect{OK: false, Reason: "unsupported_version"},
		},
		{
			ID: "creds/malformed-unclosed", Desc: "an unclosed section marker is malformed",
			Op: "parse_creds", Input: map[string]any{"creds": unclosed},
			Expect: expect{OK: false, Reason: "malformed"},
		},
		{
			ID: "creds/malformed-empty-section", Desc: "a section with no payload line is malformed",
			Op: "parse_creds", Input: map[string]any{"creds": emptySection},
			Expect: expect{OK: false, Reason: "malformed"},
		},
		{
			ID: "creds/malformed-multiple-payload-lines", Desc: "a section with more than one payload line is malformed",
			Op: "parse_creds", Input: map[string]any{"creds": multiLine},
			Expect: expect{OK: false, Reason: "malformed"},
		},
	}
	return file{Spec: 1, Cases: cases}
}

// -------- message vectors (verify_message) --------

func messageCases(k keyset) file {
	// Chain material: an operator-signed account token and an account-signed
	// user token for the emitter (user), all at the default epoch 0 so no
	// operator policy is needed for the positives.
	accTok := must(valiss.IssueAccount(k.op, k.accPub, valiss.WithName("acme")))
	usrTok := must(valiss.IssueUser(k.acc, k.usrPub, valiss.WithName("alice")))
	// A second user delegated by the same account, for chain-mismatch cases.
	usr2Tok := must(valiss.IssueUser(k.acc, k.usr2Pub, valiss.WithName("bob")))

	payload := []byte("hello world")
	checksum := valiss.Checksum(payload)
	audience := "https://api.example.com/ingest"

	// Message token with an embedded chain, an audience, and a checksum.
	msgFull := must(valiss.IssueMessage(k.usr,
		valiss.WithChain(accTok, usrTok),
		valiss.WithAudience(audience),
		valiss.WithChecksum(checksum),
		valiss.WithExpiry(farFuture),
	))
	// Chainless message (chain supplied out of band on verify).
	msgChainless := must(valiss.IssueMessage(k.usr,
		valiss.WithAudience(audience),
		valiss.WithExpiry(farFuture),
	))
	// Message with an audience but no checksum, for the checksum-missing case.
	msgNoChecksum := must(valiss.IssueMessage(k.usr,
		valiss.WithChain(accTok, usrTok),
		valiss.WithAudience(audience),
		valiss.WithExpiry(farFuture),
	))
	// Message with a checksum, for the checksum-mismatch case.
	msgSum := must(valiss.IssueMessage(k.usr,
		valiss.WithChain(accTok, usrTok),
		valiss.WithChecksum(checksum),
		valiss.WithExpiry(farFuture),
	))

	base := func() map[string]any {
		return map[string]any{"operator_pub": k.opPub, "now": fixedNow.Format(time.RFC3339Nano), "skew": skew2m}
	}
	withArg := func(extra map[string]any) map[string]any {
		m := base()
		for key, v := range extra {
			m[key] = v
		}
		return m
	}

	cases := []kase{
		// --- positives ---
		{
			ID: "message/valid", Desc: "a message token with chain, audience, and checksum verifies and binds to the payload",
			Op:    "verify_message",
			Input: map[string]any{"token": msgFull},
			Args:  withArg(map[string]any{"audience": audience, "payload": string(payload)}),
			Expect: expect{OK: true, Claims: map[string]any{
				"subject": k.usrPub, "audience": audience, "checksum": checksum, "epoch": 0,
			}},
		},
		{
			ID: "message/valid-no-bindings", Desc: "a message token verifies with only the pinned operator key when no bindings are required",
			Op:     "verify_message",
			Input:  map[string]any{"token": msgFull},
			Args:   base(),
			Expect: expect{OK: true, Claims: map[string]any{"subject": k.usrPub, "audience": audience}},
		},
		{
			ID: "message/valid-chain-supplied", Desc: "a chainless message verifies when the chain is supplied out of band",
			Op:     "verify_message",
			Input:  map[string]any{"token": msgChainless},
			Args:   withArg(map[string]any{"chain_account": accTok, "chain_user": usrTok}),
			Expect: expect{OK: true, Claims: map[string]any{"subject": k.usrPub, "audience": audience}},
		},

		// --- message-specific negatives ---
		{
			ID: "message/no-chain", Desc: "a chainless message with no chain supplied fails with no_chain",
			Op: "verify_message", Input: map[string]any{"token": msgChainless}, Args: base(),
			Expect: expect{OK: false, Reason: "no_chain"},
		},
		{
			ID: "message/chain-mismatch", Desc: "an embedded chain that differs from the supplied chain is rejected",
			Op:     "verify_message",
			Input:  map[string]any{"token": msgFull},
			Args:   withArg(map[string]any{"chain_account": accTok, "chain_user": usr2Tok}),
			Expect: expect{OK: false, Reason: "chain_mismatch"},
		},
		{
			ID: "message/chain-user-mismatch", Desc: "a supplied chain whose user is not the message signer is rejected",
			Op:     "verify_message",
			Input:  map[string]any{"token": msgChainless},
			Args:   withArg(map[string]any{"chain_account": accTok, "chain_user": usr2Tok}),
			Expect: expect{OK: false, Reason: "chain_user_mismatch"},
		},
		{
			ID: "message/wrong-audience", Desc: "a message bound to a different audience than expected is rejected",
			Op:     "verify_message",
			Input:  map[string]any{"token": msgFull},
			Args:   withArg(map[string]any{"audience": "https://evil.example.com/ingest"}),
			Expect: expect{OK: false, Reason: "wrong_audience"},
		},
		{
			ID: "message/wrong-audience-absent", Desc: "a message bound to no audience is rejected when one is expected",
			Op:     "verify_message",
			Input:  map[string]any{"token": msgChainlessWithChain(k, accTok, usrTok, farFuture)},
			Args:   withArg(map[string]any{"audience": audience}),
			Expect: expect{OK: false, Reason: "wrong_audience"},
		},
		{
			ID: "message/checksum-missing", Desc: "a message with no checksum is rejected when a checksum is required",
			Op:     "verify_message",
			Input:  map[string]any{"token": msgNoChecksum},
			Args:   withArg(map[string]any{"require_checksum": true}),
			Expect: expect{OK: false, Reason: "checksum_missing"},
		},
		{
			ID: "message/checksum-mismatch", Desc: "a checksum that does not match the supplied payload is rejected",
			Op:     "verify_message",
			Input:  map[string]any{"token": msgSum},
			Args:   withArg(map[string]any{"payload": "different payload"}),
			Expect: expect{OK: false, Reason: "checksum_mismatch"},
		},

		// --- envelope / semantic negatives ---
		{
			ID: "message/malformed-two-parts", Desc: "a message envelope truncated to two parts is malformed",
			Op: "verify_message", Input: map[string]any{"token": truncate2(msgFull)}, Args: base(),
			Expect: expect{OK: false, Reason: "malformed"},
		},
		{
			ID: "message/unsupported-type", Desc: "an unrecognized alg in a message header is an unsupported type",
			Op: "verify_message", Input: map[string]any{"token": reHeader(msgFull, headerBadAlg)}, Args: base(),
			Expect: expect{OK: false, Reason: "unsupported_type"},
		},
		{
			ID: "message/unsupported-version", Desc: "a message header ver the parser does not implement is unsupported",
			Op: "verify_message", Input: map[string]any{"token": reHeader(msgFull, headerVer2)}, Args: base(),
			Expect: expect{OK: false, Reason: "unsupported_version"},
		},
		{
			ID: "message/bad-signature", Desc: "a flipped signature byte on a message token fails verification",
			Op: "verify_message", Input: map[string]any{"token": flipSig(msgFull)}, Args: base(),
			Expect: expect{OK: false, Reason: "bad_signature"},
		},
		{
			ID: "message/bad-issuer-key", Desc: "a message iss that is not a decodable nkey is rejected",
			Op: "verify_message",
			Input: map[string]any{"token": craft(k.usr, craftWire{
				Issuer: "not-an-nkey", Subject: "not-an-nkey", Audience: audience, Expires: farFuture.Unix(),
				Valiss: craftBody{Type: "message"},
			})},
			Args: base(), Expect: expect{OK: false, Reason: "bad_issuer_key"},
		},
		{
			ID: "message/wrong-type", Desc: "an account token presented to verify_message is the wrong type",
			Op: "verify_message", Input: map[string]any{"token": accTok}, Args: base(),
			Expect: expect{OK: false, Reason: "wrong_type"},
		},
		{
			ID:   "message/wrong-issuer-not-self-signed",
			Desc: "a message token whose iss differs from its sub is not self-signed by its user key",
			Op:   "verify_message",
			Input: map[string]any{"token": craft(k.usr, craftWire{
				Issuer: k.usrPub, Subject: k.usr2Pub, Audience: audience, Expires: farFuture.Unix(),
				Valiss: craftBody{Type: "message"},
			})},
			Args: base(), Expect: expect{OK: false, Reason: "wrong_issuer"},
		},
		{
			ID:   "message/wrong-subject-role",
			Desc: "a self-signed message-type token whose key is not a user-role nkey has the wrong subject role",
			Op:   "verify_message",
			Input: map[string]any{"token": craft(k.acc, craftWire{
				Issuer: k.accPub, Subject: k.accPub, Audience: audience, Expires: farFuture.Unix(),
				Valiss: craftBody{Type: "message"},
			})},
			Args: base(), Expect: expect{OK: false, Reason: "wrong_subject_role"},
		},
	}
	return file{Spec: 1, Cases: cases}
}

// msgChainlessWithChain mints a message token with an embedded chain but no
// audience, for the wrong-audience-absent case.
func msgChainlessWithChain(k keyset, accTok, usrTok string, exp time.Time) string {
	return must(valiss.IssueMessage(k.usr,
		valiss.WithChain(accTok, usrTok),
		valiss.WithExpiry(exp),
	))
}

// -------- keys.json --------

func keysFile(k keyset) map[string]any {
	named := func(seed, pub string) map[string]any { return map[string]any{"seed": seed, "pub": pub} }
	return map[string]any{
		"spec": 1,
		"keys": map[string]any{
			"operator":  named(operatorSeed, k.opPub),
			"operator2": named(operator2Seed, k.op2Pub),
			"account":   named(accountSeed, k.accPub),
			"account2":  named(account2Seed, k.acc2Pub),
			"user":      named(userSeed, k.usrPub),
			"user2":     named(user2Seed, k.usr2Pub),
		},
	}
}

// -------- main --------

func writeJSON(dir, name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(filepath.Join(dir, name), b, 0o644)
}

// defaultTarget resolves the sibling spec repo's vectors dir relative to this
// generator's own source file, so `go run ./conformance/gen` lands there
// regardless of the working directory. From valiss-go/conformance/gen that is
// ../../../spec/vectors (up to conformance, valiss-go, the workspace root, then
// into the spec repo). The literal default in the runner is "../../spec/vectors"
// relative to the conformance package dir; both point at the same directory.
func defaultTarget() string {
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		return "../../spec/vectors"
	}
	return filepath.Join(filepath.Dir(self), "..", "..", "..", "spec", "vectors")
}

func main() {
	target := defaultTarget()
	if len(os.Args) > 1 {
		target = os.Args[1]
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}

	k := loadKeys()

	outputs := []struct {
		name string
		v    any
	}{
		{"keys.json", keysFile(k)},
		{"tokens.json", tokenCases(k)},
		{"signatures.json", signatureCases(k)},
		{"creds.json", credsCases(k)},
		{"messages.json", messageCases(k)},
	}
	for _, o := range outputs {
		if err := writeJSON(target, o.name, o.v); err != nil {
			fmt.Fprintln(os.Stderr, "gen:", err)
			os.Exit(1)
		}
		fmt.Printf("wrote %s\n", filepath.Join(target, o.name))
	}
}
