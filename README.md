# Zero-Trust Air-Gapped Supply Chain

Private research repo. SBOM generation with syft, signing with sigstore/cosign-compatible envelopes, and reproducible builds, moved across a simulated data diode into an offline Harbor registry.

Written in **Go**: standard library only, so the verifier itself has no dependencies to trust.

Full write-up: [`docs/project-page.md`](docs/project-page.md)

## Flow

```
HIGH SIDE (connected)                       DIODE (one way)          LOW SIDE (offline)
build (reproducible) -> syft SBOM ->   frames + CRC + XOR FEC ->   reassemble -> verify DSSE ->
in-toto/DSSE attestation (Ed25519)        repeated N times          check digests -> SBOM gate -> Harbor
```

## What's here

| Path | Purpose |
|---|---|
| `attest/dsse.go` | in-toto v1 Statement, **DSSE envelope** with PAE encoding (the format cosign uses), trusted-key verify, digest checks |
| `attest/sbom.go` | syft wrapper (CycloneDX) and SBOM deny-list gate (e.g. `xz@5.6.1`) |
| `diode/diode.go` | One-way framing: per-frame CRC32, XOR parity per K frames, whole-file SHA-256. Repairs a lost frame with no back channel |
| `cmd/airgap` | `keygen`, `attest`, `send`, `recv`, `verify` |
| `scripts/repro-check.sh` | Builds twice in different directories and requires identical SHA-256 |
| `scripts/harbor-offline-push.sh` | Low side: push verified OCI tarballs to Harbor and `cosign verify` |

## Quickstart

```bash
make test    # DSSE tamper tests, SBOM gate, diode with loss + corruption
make demo    # attest -> diode send -> recv -> verify
make repro   # reproducible-build check
```

## Next steps
- [ ] Replace XOR parity with Reed-Solomon (`klauspost/reedsolomon`) to survive bursts
- [ ] Send frames over real UDP through a one-way link (a Pi with the TX wire only, or a cut RX pair)
- [ ] Carry an offline grype vulnerability DB snapshot across, and gate on CVEs instead of a static deny list
- [ ] Two-person rule: require two trusted signatures in the envelope before ACCEPT
- [ ] SLSA provenance predicate filled from the CI run (commit, builder, materials)
