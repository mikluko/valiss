// Example httpauth shows the full tenant-auth wiring for net/http: an
// operator signs an account token carrying an HTTP extension, the server
// wraps its mux with the auth middleware, and the client signs every request
// via the transport. Runs self-contained against a local listener.
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/mikluko/valiss"
	"github.com/mikluko/valiss/contrib/httpauth"
	"github.com/mikluko/valiss/creds"
)

func main() {
	// Operator side: mint the trust anchor, a tenant account key, and an
	// account token bound to GET requests under /v1/ by the HTTP extension.
	operator, err := nkeys.CreateOperator()
	check(err)
	operatorPub, err := operator.PublicKey()
	check(err)
	account, err := nkeys.CreateAccount()
	check(err)
	accountPub, err := account.PublicKey()
	check(err)
	accountSeed, err := account.Seed()
	check(err)

	tok, err := valiss.Issue(operator, "acme", accountPub, nil,
		httpauth.WithExt(httpauth.Ext{Methods: []string{"GET"}, Paths: []string{"/v1/*"}}),
		valiss.WithTTL(time.Hour),
	)
	check(err)
	claims, err := valiss.VerifyAccount(tok, operatorPub)
	check(err)
	rendered := creds.Format(creds.Creds{AccountToken: tok, Seed: accountSeed})

	// Server side: the operator public key and the allowlist are all the
	// server needs; it never sees any seeds.
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/whoami", func(w http.ResponseWriter, r *http.Request) {
		// The middleware injected the verified tenant; the handler reads it
		// for logging and data segmentation.
		c, _ := valiss.TenantFromContext(r.Context())
		log.Printf("tenant %q calls %s", c.TenantID, r.URL.Path)
		fmt.Fprintf(w, "hello, tenant %q\n", c.TenantID)
	})
	mux.HandleFunc("/admin/", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "admin area\n")
	})
	mw := httpauth.NewMiddleware(valiss.NewVerifier(operatorPub, valiss.NewStaticAllowlist(claims.ID)))
	srv := httptest.NewServer(mw(mux))
	defer srv.Close()

	// Client side: parse the creds and sign every request via the transport.
	clientCreds, err := creds.Parse(rendered)
	check(err)
	transport, err := httpauth.NewTransport(clientCreds, nil)
	check(err)
	client := &http.Client{Transport: transport}

	resp, err := client.Get(srv.URL + "/v1/whoami")
	check(err)
	body, err := io.ReadAll(resp.Body)
	check(err)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("expected 200 for the in-extension request, got: %s", resp.Status)
	}
	fmt.Printf("in-extension request allowed as expected: %s -> %s", resp.Status, body)

	// A path outside the extension is denied.
	resp, err = client.Get(srv.URL + "/admin/")
	check(err)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		log.Fatalf("expected 403 for the out-of-extension path, got: %s", resp.Status)
	}
	fmt.Println("out-of-extension path denied as expected:", resp.Status)

	// So is a method outside the extension.
	resp, err = client.Post(srv.URL+"/v1/whoami", "text/plain", strings.NewReader("hi"))
	check(err)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		log.Fatalf("expected 403 for the out-of-extension method, got: %s", resp.Status)
	}
	fmt.Println("out-of-extension method denied as expected:", resp.Status)

	// No credential at all is rejected outright.
	resp, err = http.Get(srv.URL + "/v1/whoami")
	check(err)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		log.Fatalf("expected 401 without a credential, got: %s", resp.Status)
	}
	fmt.Println("missing credential rejected as expected:", resp.Status)
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
