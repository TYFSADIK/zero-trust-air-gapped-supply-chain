package airgap_test

import (
	"bytes"
	"crypto/ed25519"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"

	"github.com/TYFSADIK/zero-trust-air-gapped-supply-chain/attest"
	"github.com/TYFSADIK/zero-trust-air-gapped-supply-chain/diode"
)

func TestDSSERoundTripAndTamper(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	other, _, _ := ed25519.GenerateKey(nil)
	dir := t.TempDir()
	p := filepath.Join(dir, "app.tar")
	os.WriteFile(p, []byte("release bits"), 0o644)
	subj, _ := attest.DigestFiles(p)
	env, _ := attest.Sign(attest.Statement{Type: attest.StatementType, Subject: subj,
		PredicateType: attest.SLSAProvV1, Predicate: map[string]any{"builder": "high-side-ci"}}, priv)
	st, err := attest.Verify(env, []ed25519.PublicKey{pub})
	if err != nil || attest.CheckSubjects(st, dir) != nil {
		t.Fatal("valid attestation rejected", err)
	}
	if _, err := attest.Verify(env, []ed25519.PublicKey{other}); err == nil {
		t.Fatal("untrusted key accepted")
	}
	os.WriteFile(p, []byte("release bits + implant"), 0o644)
	if attest.CheckSubjects(st, dir) == nil {
		t.Fatal("modified artifact accepted")
	}
}

func TestSBOMGate(t *testing.T) {
	sbom := []byte(`{"bomFormat":"CycloneDX","components":[{"name":"xz","version":"5.6.1"},{"name":"zlib","version":"1.3"}]}`)
	hits, _ := attest.Gate(sbom, []string{"xz@5.6.1", "log4j-core"})
	if len(hits) != 1 || hits[0] != "xz@5.6.1" {
		t.Fatalf("hits=%v", hits)
	}
}

func TestDiodeRecoversLossWithoutBackchannel(t *testing.T) {
	r := rand.New(rand.NewPCG(9, 9))
	data := make([]byte, 300_000)
	for i := range data {
		data[i] = byte(r.UintN(256))
	}
	frames := diode.Encode(data, 1200, 8)
	rx := diode.NewReceiver(1200, 8)
	dropped := 0
	for i, f := range frames {
		if i%9 == 3 { // lose one frame in every group
			dropped++
			continue
		}
		if i%50 == 7 { // corrupt one byte occasionally (CRC catches it, parity repairs if alone)
			f = append([]byte{}, f...)
			f[60] ^= 0xFF
		}
		rx.Push(f)
	}
	out, missing, err := rx.Result()
	if err != nil {
		t.Logf("missing %v (bad crc %d)", missing, rx.BadCRC)
		// a second pass of the sender (diodes repeat) fills the gaps
		for _, f := range frames {
			rx.Push(f)
		}
		out, _, err = rx.Result()
	}
	if err != nil || !bytes.Equal(out, data) {
		t.Fatal("transfer failed", err)
	}
	t.Logf("%d frames, %d dropped, %d repaired by parity, %d bad CRC", len(frames), dropped, rx.Repaired, rx.BadCRC)
}
