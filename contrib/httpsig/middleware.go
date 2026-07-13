package httpsig

import (
	"bytes"
	"io"
	"net/http"

	"github.com/mikluko/valiss"
)

type middleware struct {
	operatorPubKey string
	opts           []valiss.VerifyMessageOption
	next           http.Handler
}

// NewMiddleware returns a middleware that requires every request to carry a
// message token (valiss-message-token header) proving the origin of its
// exact body at this destination: the token is verified against the
// operator public key with the audience pinned to the incoming host and
// path (Audience) and the checksum compared to the received bytes. Failures
// get 401. Handlers read the verified claims with valiss.MessageFromContext
// and the body as usual.
//
// The audience and payload bindings are appended after opts, so they cannot
// be weakened; pass options like valiss.WithOperatorPolicy or
// valiss.WithChainTokens to tighten or supply out-of-band material.
func NewMiddleware(operatorPubKey string, opts ...valiss.VerifyMessageOption) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return &middleware{operatorPubKey: operatorPubKey, opts: opts, next: next}
	}
}

func (m *middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tok := r.Header.Get(valiss.HeaderMessageToken)
	if tok == "" {
		http.Error(w, "missing message token", http.StatusUnauthorized)
		return
	}
	var body []byte
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "reading request body", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	opts := append(append([]valiss.VerifyMessageOption{}, m.opts...),
		valiss.ExpectAudience(Audience(r)),
		valiss.WithPayload(body),
	)
	claims, err := valiss.VerifyMessage(tok, m.operatorPubKey, opts...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	m.next.ServeHTTP(w, r.WithContext(valiss.ContextWithMessage(r.Context(), claims)))
}
