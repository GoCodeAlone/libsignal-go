package kem

import (
	"crypto/aes"
	"crypto/sha256"
	"fmt"
	"testing"
)

// formatVerb renders v with the given fmt verb; a test helper for redaction
// checks.
func formatVerb(verb string, v any) string {
	return fmt.Sprintf(verb, v)
}

// katDRBG is the NIST AES-256-CTR DRBG (no derivation function) used by the
// PQC Known-Answer-Test generator, ported from NIST's PQCgenKAT.c randombytes.
// It is identical to cloudflare/circl's internal/nist.DRBG, which is itself a
// port of the reference KAT RNG; we re-implement it here (rather than import the
// internal package) so the KAT is self-contained.
type katDRBG struct {
	key [32]byte
	v   [16]byte
}

func (g *katDRBG) incV() {
	for j := 15; j >= 0; j-- {
		if g.v[j] == 255 {
			g.v[j] = 0
		} else {
			g.v[j]++
			break
		}
	}
}

// update implements AES256_CTR_DRBG_Update(pd, key, v).
func (g *katDRBG) update(pd *[48]byte) {
	var buf [48]byte
	b, _ := aes.NewCipher(g.key[:])
	for i := 0; i < 3; i++ {
		g.incV()
		b.Encrypt(buf[i*16:(i+1)*16], g.v[:])
	}
	if pd != nil {
		for i := 0; i < 48; i++ {
			buf[i] ^= pd[i]
		}
	}
	copy(g.key[:], buf[:32])
	copy(g.v[:], buf[32:])
}

// newKATDRBG implements randombytes_init(seed, NULL, 256).
func newKATDRBG(seed *[48]byte) (g katDRBG) {
	g.update(seed)
	return
}

// fill implements randombytes(x).
func (g *katDRBG) fill(x []byte) {
	var block [16]byte
	b, _ := aes.NewCipher(g.key[:])
	for len(x) > 0 {
		g.incV()
		b.Encrypt(block[:], g.v[:])
		if len(x) < 16 {
			copy(x[:], block[:len(x)])
			break
		}
		copy(x[:], block[:])
		x = x[16:]
	}
	g.update(nil)
}

// TestKyber1024KAT runs the NIST round-3 Kyber1024 Known-Answer-Test.
//
// It reproduces the exact PQCgenKAT_kem procedure: a NIST AES-CTR DRBG seeded
// with bytes 0..47 drives 100 deterministic (DeriveKeyPair,
// EncapsulateDeterministically) iterations, each also checked for
// decapsulate-consistency. The SHA-256 over the formatted KAT response file
// must equal the expected digest.
//
// Expected digest source: cloudflare/circl v1.6.3
// kem/kyber/kat_test.go (TestPQCgenKATKem, "Kyber1024" entry), which states the
// value is "Computed from reference implementation" — i.e. the pq-crystals
// round-3 Kyber reference KAT
// (https://pq-crystals.org/kyber/data/kyber-specification-round3.pdf).
func TestKyber1024KAT(t *testing.T) {
	const expectedDigest = "89248f2f33f7f4f7051729111f3049c409a933ec904aedadf035f30fa5646cd5"

	params := kyber1024Parameters{}
	seedSize := params.seedSize()
	encSeedSize := params.encapsulationSeedSize()

	var seed [48]byte
	for i := 0; i < 48; i++ {
		seed[i] = byte(i)
	}
	kseed := make([]byte, seedSize)
	eseed := make([]byte, encSeedSize)

	f := sha256.New()
	g := newKATDRBG(&seed)
	mustFprintf(t, f, "# %s\n\n", "Kyber1024")

	for i := 0; i < 100; i++ {
		g.fill(seed[:])
		mustFprintf(t, f, "count = %d\n", i)
		mustFprintf(t, f, "seed = %X\n", seed)

		g2 := newKATDRBG(&seed)
		// Round-3 Kyber's reference keygen calls randombytes twice (the two
		// 32-byte halves of the 64-byte key seed); this differs from ML-KEM.
		g2.fill(kseed[:32])
		g2.fill(kseed[32:])
		g2.fill(eseed)

		pub, sec, err := params.generate(kseed)
		if err != nil {
			t.Fatalf("iter %d: generate: %v", i, err)
		}
		ss, ct, err := params.encapsulateDeterministically(pub, eseed)
		if err != nil {
			t.Fatalf("iter %d: encapsulate: %v", i, err)
		}
		ss2, err := params.decapsulate(sec, ct)
		if err != nil {
			t.Fatalf("iter %d: decapsulate: %v", i, err)
		}
		if string(ss) != string(ss2) {
			t.Fatalf("iter %d: shared secrets differ", i)
		}

		mustFprintf(t, f, "pk = %X\n", pub)
		mustFprintf(t, f, "sk = %X\n", sec)
		mustFprintf(t, f, "ct = %X\n", ct)
		mustFprintf(t, f, "ss = %X\n\n", ss)
	}

	got := fmt.Sprintf("%x", f.Sum(nil))
	if got != expectedDigest {
		t.Fatalf("Kyber1024 KAT digest = %s, want %s", got, expectedDigest)
	}
}

func mustFprintf(t *testing.T, f interface{ Write([]byte) (int, error) }, format string, data any) {
	t.Helper()
	if _, err := fmt.Fprintf(f, format, data); err != nil {
		t.Fatalf("write KAT output: %v", err)
	}
}
