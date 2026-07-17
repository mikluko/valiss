package valiss

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerationExtRoundTrip(t *testing.T) {
	op, opPub := issuerKeys(t)
	_, accountPub := tenantKeys(t)

	assert.Equal(t, "gen", GenerationExt{}.ExtensionName())

	tok, err := IssueAccount(op, accountPub, WithName("acme"),
		WithExtension(GenerationExt{Generation: 8, Template: "a1b2c3"}))
	require.NoError(t, err)

	ac, err := VerifyAccount(tok, opPub)
	require.NoError(t, err)

	got, ok, err := ExtOf[GenerationExt](ac.Ext)
	require.NoError(t, err)
	require.True(t, ok, "stamped token exposes the generation extension")
	assert.Equal(t, uint64(8), got.Generation)
	assert.Equal(t, "a1b2c3", got.Template, "template digest travels opaquely")
}

func TestGenerationExtAbsent(t *testing.T) {
	op, opPub := issuerKeys(t)
	_, accountPub := tenantKeys(t)

	tok, err := IssueAccount(op, accountPub, WithName("acme"))
	require.NoError(t, err)
	ac, err := VerifyAccount(tok, opPub)
	require.NoError(t, err)

	_, ok, err := ExtOf[GenerationExt](ac.Ext)
	require.NoError(t, err)
	assert.False(t, ok, "an unstamped token carries no generation extension")
}

func TestStaticAllowlistFloors(t *testing.T) {
	a := NewStaticAllowlist("jti-1")

	_, ok := a.Floor("O_ENTITY")
	assert.False(t, ok, "no floor set by default")

	a.SetFloor("O_ENTITY", 8)
	gen, ok := a.Floor("O_ENTITY")
	assert.True(t, ok)
	assert.Equal(t, uint64(8), gen)

	a.SetFloor("O_ENTITY", 0)
	_, ok = a.Floor("O_ENTITY")
	assert.False(t, ok, "a zero floor clears the constraint")

	a.SetFloors(map[string]uint64{"A_ENTITY": 3, "B_ENTITY": 0})
	gen, ok = a.Floor("A_ENTITY")
	assert.True(t, ok)
	assert.Equal(t, uint64(3), gen)
	_, ok = a.Floor("B_ENTITY")
	assert.False(t, ok, "zero entries are dropped on bulk set")

	// StaticAllowlist satisfies FloorList.
	var _ FloorList = a
}

func TestCheckGenerationFloor(t *testing.T) {
	op, opPub := issuerKeys(t)
	_, accountPub := tenantKeys(t)

	stamped, err := IssueAccount(op, accountPub, WithExtension(GenerationExt{Generation: 5}))
	require.NoError(t, err)
	sc, err := VerifyAccount(stamped, opPub)
	require.NoError(t, err)

	unstamped, err := IssueAccount(op, accountPub)
	require.NoError(t, err)
	uc, err := VerifyAccount(unstamped, opPub)
	require.NoError(t, err)

	floors := NewStaticAllowlist()
	floors.SetFloor(opPub, 8)

	t.Run("nil floors passes (enforcement off)", func(t *testing.T) {
		assert.NoError(t, CheckGenerationFloor(sc.Ext, sc.Issuer, nil))
	})
	t.Run("stamp below floor is rejected", func(t *testing.T) {
		err := CheckGenerationFloor(sc.Ext, sc.Issuer, floors)
		assert.ErrorContains(t, err, "below floor")
	})
	t.Run("unstamped token passes any floor", func(t *testing.T) {
		assert.NoError(t, CheckGenerationFloor(uc.Ext, uc.Issuer, floors))
	})
	t.Run("issuer without a floor passes", func(t *testing.T) {
		other := NewStaticAllowlist()
		other.SetFloor("O_SOMEONE_ELSE", 99)
		assert.NoError(t, CheckGenerationFloor(sc.Ext, sc.Issuer, other))
	})
	t.Run("stamp at or above floor passes", func(t *testing.T) {
		low := NewStaticAllowlist()
		low.SetFloor(opPub, 5)
		assert.NoError(t, CheckGenerationFloor(sc.Ext, sc.Issuer, low))
		low.SetFloor(opPub, 4)
		assert.NoError(t, CheckGenerationFloor(sc.Ext, sc.Issuer, low))
	})
}

// TestGenerationFloorEnforcement drives the four conformance behaviors through
// the full request verifier: a stamped account token checked against a floor
// keyed by its issuing operator.
func TestGenerationFloorEnforcement(t *testing.T) {
	op, opPub := issuerKeys(t)
	account, accountPub := tenantKeys(t)

	mint := func(gen uint64) (string, string) {
		tok, err := IssueAccount(op, accountPub, WithName("acme"),
			WithExtension(GenerationExt{Generation: gen}), WithTTL(time.Hour))
		require.NoError(t, err)
		ac, err := VerifyAccount(tok, opPub)
		require.NoError(t, err)
		return tok, ac.ID
	}
	unstampedTok := func() (string, string) {
		tok, err := IssueAccount(op, accountPub, WithName("acme"), WithTTL(time.Hour))
		require.NoError(t, err)
		ac, err := VerifyAccount(tok, opPub)
		require.NoError(t, err)
		return tok, ac.ID
	}
	signed := func(tok string) Request {
		ts, sig, err := SignRequest(account, time.Now(), nil)
		require.NoError(t, err)
		return Request{AccountToken: tok, Timestamp: ts, Signature: sig}
	}

	t.Run("stamped at floor accepted", func(t *testing.T) {
		tok, jti := mint(8)
		al := NewStaticAllowlist(jti)
		al.SetFloor(opPub, 8)
		v := NewVerifier(opPub, al, WithGenerationFloors())
		id, err := v.VerifyRequest(signed(tok))
		require.NoError(t, err)
		assert.Equal(t, "acme", id.Account.Name)
	})

	t.Run("stamped above floor accepted", func(t *testing.T) {
		tok, jti := mint(9)
		al := NewStaticAllowlist(jti)
		al.SetFloor(opPub, 8)
		v := NewVerifier(opPub, al, WithGenerationFloors())
		_, err := v.VerifyRequest(signed(tok))
		assert.NoError(t, err)
	})

	t.Run("stamped below floor rejected", func(t *testing.T) {
		tok, jti := mint(7)
		al := NewStaticAllowlist(jti)
		al.SetFloor(opPub, 8)
		v := NewVerifier(opPub, al, WithGenerationFloors())
		_, err := v.VerifyRequest(signed(tok))
		require.Error(t, err)
		assert.ErrorContains(t, err, "below floor")
	})

	t.Run("unstamped accepted regardless of floor", func(t *testing.T) {
		tok, jti := unstampedTok()
		al := NewStaticAllowlist(jti)
		al.SetFloor(opPub, 8)
		v := NewVerifier(opPub, al, WithGenerationFloors())
		_, err := v.VerifyRequest(signed(tok))
		assert.NoError(t, err, "an unstamped token is never rejected by a floor")
	})

	t.Run("non-enforcing verifier accepts a low stamp", func(t *testing.T) {
		tok, jti := mint(1)
		al := NewStaticAllowlist(jti)
		al.SetFloor(opPub, 8)
		// No WithGenerationFloors: the stamp is ignored entirely.
		v := NewVerifier(opPub, al)
		_, err := v.VerifyRequest(signed(tok))
		assert.NoError(t, err, "a verifier not configured for floors ignores the stamp")
	})

	t.Run("floors ignored when the allowlist carries none", func(t *testing.T) {
		tok, _ := mint(1)
		// AllowAll does not implement FloorList: WithGenerationFloors finds no
		// floors and enforces nothing.
		v := NewVerifier(opPub, AllowAll{}, WithGenerationFloors())
		_, err := v.VerifyRequest(signed(tok))
		assert.NoError(t, err)
	})
}

// TestGenerationFloorUserToken enforces a floor on the user level, keyed by the
// delegating account (the user token's issuing entity).
func TestGenerationFloorUserToken(t *testing.T) {
	op, opPub := issuerKeys(t)
	account, accountPub := tenantKeys(t)
	user, userPub := userKeys(t)

	acctTok, err := IssueAccount(op, accountPub, WithName("acme"), WithTTL(time.Hour))
	require.NoError(t, err)
	acctClaims, err := VerifyAccount(acctTok, opPub)
	require.NoError(t, err)

	mintUser := func(gen uint64) string {
		tok, err := IssueUser(account, userPub, WithName("alice"),
			WithExtension(GenerationExt{Generation: gen}), WithTTL(time.Hour))
		require.NoError(t, err)
		return tok
	}
	signed := func(userTok string) Request {
		ts, sig, err := SignRequest(user, time.Now(), nil)
		require.NoError(t, err)
		return Request{AccountToken: acctTok, UserToken: userTok, Timestamp: ts, Signature: sig}
	}

	newVerifier := func(userFloor uint64) *Verifier {
		al := NewStaticAllowlist(acctClaims.ID)
		al.SetFloor(accountPub, userFloor) // floor keyed by the delegating account
		return NewVerifier(opPub, al, WithGenerationFloors())
	}

	t.Run("user stamp at floor accepted", func(t *testing.T) {
		_, err := newVerifier(4).VerifyRequest(signed(mintUser(4)))
		assert.NoError(t, err)
	})
	t.Run("user stamp below floor rejected", func(t *testing.T) {
		_, err := newVerifier(4).VerifyRequest(signed(mintUser(3)))
		assert.ErrorContains(t, err, "below floor")
	})
}
