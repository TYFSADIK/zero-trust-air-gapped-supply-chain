// Package attest builds in-toto v1 Statements wrapped in DSSE envelopes, signed with Ed25519.
// This is the same envelope format cosign/sigstore use, so attestations made here can be
// verified with `cosign verify-blob-attestation` later.
package attest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	PayloadType   = "application/vnd.in-toto+json"
	StatementType = "https://in-toto.io/Statement/v1"
	SLSAProvV1    = "https://slsa.dev/provenance/v1"
	CycloneDX     = "https://cyclonedx.org/bom"
)

type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type Statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     any       `json:"predicate"`
}

type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

// PAE is DSSE's pre-authentication encoding: what actually gets signed.
func PAE(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload))
}

func KeyID(pub ed25519.PublicKey) string { s := sha256.Sum256(pub); return hex.EncodeToString(s[:8]) }

func Sign(st Statement, priv ed25519.PrivateKey) (Envelope, error) {
	p, err := json.Marshal(st)
	if err != nil {
		return Envelope{}, err
	}
	sig := ed25519.Sign(priv, PAE(PayloadType, p))
	return Envelope{PayloadType, base64.StdEncoding.EncodeToString(p),
		[]Signature{{KeyID(priv.Public().(ed25519.PublicKey)), base64.StdEncoding.EncodeToString(sig)}}}, nil
}

var ErrNoValidSig = errors.New("no valid signature from a trusted key")

// Verify checks the envelope against trusted keys and returns the statement.
func Verify(env Envelope, trusted []ed25519.PublicKey) (Statement, error) {
	var st Statement
	p, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return st, err
	}
	ok := false
	for _, s := range env.Signatures {
		sig, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil {
			continue
		}
		for _, k := range trusted {
			if ed25519.Verify(k, PAE(env.PayloadType, p), sig) {
				ok = true
			}
		}
	}
	if !ok {
		return st, ErrNoValidSig
	}
	return st, json.Unmarshal(p, &st)
}

// DigestFiles makes subjects for files (sha256).
func DigestFiles(paths ...string) ([]Subject, error) {
	var out []Subject
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		s := sha256.Sum256(b)
		out = append(out, Subject{filepath.Base(p), map[string]string{"sha256": hex.EncodeToString(s[:])}})
	}
	return out, nil
}

// CheckSubjects confirms every file on the low side matches the attested digest.
func CheckSubjects(st Statement, dir string) error {
	for _, s := range st.Subject {
		b, err := os.ReadFile(filepath.Join(dir, s.Name))
		if err != nil {
			return fmt.Errorf("%s: %w", s.Name, err)
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != s.Digest["sha256"] {
			return fmt.Errorf("%s: digest mismatch", s.Name)
		}
	}
	return nil
}
