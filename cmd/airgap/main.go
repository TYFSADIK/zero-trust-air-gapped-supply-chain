// airgap: high-side attest + send, low-side receive + verify.
//
//	airgap keygen  -key keys/high.key
//	airgap attest  -key keys/high.key -sbom sbom.cdx.json -o bundle.att.json  app.tar ...
//	airgap send    -in bundle.tar -o frames.bin       (frames to push through the diode, repeated -n times)
//	airgap recv    -in frames.bin -o bundle.tar
//	airgap verify  -pub keys/high.pub -att bundle.att.json -dir ./received [-deny deny.txt -sbom sbom.cdx.json]
package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/TYFSADIK/zero-trust-air-gapped-supply-chain/attest"
	"github.com/TYFSADIK/zero-trust-air-gapped-supply-chain/diode"
)

const mtu, k = 1200, 8

func die(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...); os.Exit(1) }
func hexfile(p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		die("%v", err)
	}
	v, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		die("%v", err)
	}
	return v
}

func main() {
	if len(os.Args) < 2 {
		die("usage: airgap keygen|attest|send|recv|verify")
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	key := fs.String("key", "keys/high.key", "")
	pub := fs.String("pub", "keys/high.pub", "")
	sbom := fs.String("sbom", "", "CycloneDX SBOM json")
	out := fs.String("o", "", "")
	in := fs.String("in", "", "")
	att := fs.String("att", "", "")
	dir := fs.String("dir", ".", "")
	deny := fs.String("deny", "", "deny list file")
	reps := fs.Int("n", 3, "repetitions of the whole transfer")
	fs.Parse(os.Args[2:])

	switch os.Args[1] {
	case "keygen":
		p, s, _ := ed25519.GenerateKey(nil)
		os.MkdirAll(filepath.Dir(*key), 0o700)
		os.WriteFile(*key, []byte(hex.EncodeToString(s)), 0o600)
		os.WriteFile(strings.TrimSuffix(*key, ".key")+".pub", []byte(hex.EncodeToString(p)), 0o644)
	case "attest":
		subj, err := attest.DigestFiles(fs.Args()...)
		if err != nil {
			die("%v", err)
		}
		pred := map[string]any{"buildType": "high-side-ci", "sbom": nil}
		if *sbom != "" {
			s, _ := attest.DigestFiles(*sbom)
			pred["sbom"] = s[0]
		}
		env, _ := attest.Sign(attest.Statement{Type: attest.StatementType, Subject: subj,
			PredicateType: attest.SLSAProvV1, Predicate: pred}, ed25519.PrivateKey(hexfile(*key)))
		b, _ := json.MarshalIndent(env, "", " ")
		os.WriteFile(*out, b, 0o644)
	case "send":
		data, err := os.ReadFile(*in)
		if err != nil {
			die("%v", err)
		}
		f, _ := os.Create(*out)
		w := bufio.NewWriter(f)
		frames := diode.Encode(data, mtu, k)
		for r := 0; r < *reps; r++ {
			for _, fr := range frames {
				binary.Write(w, binary.BigEndian, uint16(len(fr)))
				w.Write(fr)
			}
		}
		w.Flush()
		f.Close()
		fmt.Printf("%d frames x %d reps\n", len(frames), *reps)
	case "recv":
		f, err := os.Open(*in)
		if err != nil {
			die("%v", err)
		}
		rx := diode.NewReceiver(mtu, k)
		r := bufio.NewReader(f)
		for {
			var n uint16
			if binary.Read(r, binary.BigEndian, &n) != nil {
				break
			}
			b := make([]byte, n)
			if _, err := io.ReadFull(r, b); err != nil {
				break
			}
			rx.Push(b)
		}
		data, missing, err := rx.Result()
		if err != nil {
			die("%v (missing %d frames)", err, len(missing))
		}
		os.WriteFile(*out, data, 0o644)
		fmt.Printf("OK %d bytes, repaired %d, bad crc %d\n", len(data), rx.Repaired, rx.BadCRC)
	case "verify":
		var env attest.Envelope
		b, _ := os.ReadFile(*att)
		if json.Unmarshal(b, &env) != nil {
			die("bad attestation")
		}
		st, err := attest.Verify(env, []ed25519.PublicKey{hexfile(*pub)})
		if err != nil {
			die("REJECT: %v", err)
		}
		if err := attest.CheckSubjects(st, *dir); err != nil {
			die("REJECT: %v", err)
		}
		if *deny != "" && *sbom != "" {
			d, _ := os.ReadFile(*deny)
			s, _ := os.ReadFile(*sbom)
			hits, err := attest.Gate(s, strings.Fields(string(d)))
			if err != nil || len(hits) > 0 {
				die("REJECT: denied components %v %v", hits, err)
			}
		}
		fmt.Printf("ACCEPT: %d subjects verified\n", len(st.Subject))
	default:
		die("unknown command")
	}
}
