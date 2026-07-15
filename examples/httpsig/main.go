// Example httpsig shows per-message proofs of origin over HTTP: an emitter
// posts a webhook through the httpsig transport, the receiver's middleware
// verifies the token offline against the operator public key, and an auditor
// re-verifies the stored message after the token has expired using
// verification-at-instant. Runs self-contained against a local listener.
package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/nats-io/nkeys"

	"valiss.dev/valiss"
	"valiss.dev/valiss/contrib/httpsig"
	"valiss.dev/valiss/creds"
)

func main() {
	// Operator side: the trust anchor plus a tenant account and a delegated
	// user for the emitting service, all stamped with the domain epoch.
	const epoch = 1
	operator, err := nkeys.CreateOperator()
	check(err)
	operatorPub, err := operator.PublicKey()
	check(err)
	account, err := nkeys.CreateAccount()
	check(err)
	accountPub, err := account.PublicKey()
	check(err)
	user, err := nkeys.CreateUser()
	check(err)
	userPub, err := user.PublicKey()
	check(err)
	userSeed, err := user.Seed()
	check(err)

	accountToken, err := valiss.IssueAccount(operator, accountPub, valiss.WithName("acme"),
		valiss.WithEpoch(epoch), valiss.WithTTL(time.Hour))
	check(err)
	userToken, err := valiss.IssueUser(account, userPub, valiss.WithName("webhook-emitter"),
		valiss.WithEpoch(epoch), valiss.WithTTL(time.Hour))
	check(err)

	// Receiver side: the operator public key is all it needs — no allowlist,
	// no token resolver, no shared state with the emitter.
	var stored struct {
		token   string
		payload []byte
		at      time.Time
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/hook", func(w http.ResponseWriter, r *http.Request) {
		claims, _ := valiss.MessageFromContext(r.Context())
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Keep the raw material an auditor needs to re-verify later.
		stored.token = r.Header.Get(valiss.HeaderMessageToken)
		stored.payload = body
		stored.at = time.Now()
		log.Printf("webhook from tenant %q, user %q: %s",
			claims.Account.Name, claims.User.Name, body)
	})
	mw := httpsig.NewMiddleware(operatorPub)
	srv := httptest.NewServer(mw(mux))
	defer srv.Close()

	// Emitter side: bundle creds (chain tokens + user seed) drive the
	// message transport, which mints one short-lived proof per request.
	bundle := creds.Creds{AccountToken: accountToken, UserToken: userToken, Seed: userSeed}
	transport, err := httpsig.NewTransport(bundle, nil,
		httpsig.WithTTL(5*time.Second))
	check(err)
	client := &http.Client{Transport: transport}

	payload := []byte(`{"event":"widget.created","id":42}`)
	resp, err := client.Post(srv.URL+"/hook", "application/json", bytes.NewReader(payload))
	check(err)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("expected 200 for the signed webhook, got: %s", resp.Status)
	}
	fmt.Println("signed webhook accepted as expected:", resp.Status)

	// A tampered payload no longer matches the token's checksum.
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/hook",
		bytes.NewReader([]byte(`{"event":"widget.created","id":666}`)))
	check(err)
	req.Header.Set(valiss.HeaderMessageToken, stored.token)
	resp, err = http.DefaultClient.Do(req)
	check(err)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		log.Fatalf("expected 401 for the tampered payload, got: %s", resp.Status)
	}
	fmt.Println("tampered payload rejected as expected:", resp.Status)

	// The same token captured at one destination fails at another.
	req, err = http.NewRequest(http.MethodPost, srv.URL+"/other-hook", bytes.NewReader(payload))
	check(err)
	req.Header.Set(valiss.HeaderMessageToken, stored.token)
	resp, err = http.DefaultClient.Do(req)
	check(err)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		log.Fatalf("expected 401 for the cross-destination replay, got: %s", resp.Status)
	}
	fmt.Println("cross-destination replay rejected as expected:", resp.Status)

	// Auditor side, long after the 5s token has expired: the stored message
	// still verifies as of the instant it was received. Only the operator
	// public key and the receipt time are needed.
	longAfter := stored.at.Add(24 * time.Hour)
	if _, err := valiss.VerifyMessage(stored.token, operatorPub,
		valiss.At(longAfter),
		valiss.WithPayload(stored.payload),
	); err == nil {
		log.Fatal("expected the expired token to fail verification at a later instant")
	}
	claims, err := valiss.VerifyMessage(stored.token, operatorPub,
		valiss.At(stored.at),
		valiss.WithPayload(stored.payload),
	)
	check(err)
	fmt.Printf("stored message re-verified at its receipt instant: tenant %q, user %q, checksum %s\n",
		claims.Account.Name, claims.User.Name, claims.Checksum[:12]+"…")
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
