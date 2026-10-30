package attest

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// Component is the subset of CycloneDX we gate on.
type Component struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

type BOM struct {
	BomFormat  string      `json:"bomFormat"`
	Components []Component `json:"components"`
}

// Syft generates a CycloneDX SBOM for a directory or image (requires syft on PATH, works offline).
func Syft(target string) ([]byte, error) {
	out, err := exec.Command("syft", target, "-o", "cyclonedx-json", "-q").Output()
	if err != nil {
		return nil, fmt.Errorf("syft: %w", err)
	}
	return out, nil
}

// Gate rejects SBOMs that contain denied packages (name or name@version, matched against purl/name).
// Feed `deny` from an offline vulnerability export (e.g. grype DB snapshot carried across the diode).
func Gate(sbom []byte, deny []string) ([]string, error) {
	var b BOM
	if err := json.Unmarshal(sbom, &b); err != nil {
		return nil, err
	}
	var hits []string
	for _, c := range b.Components {
		for _, d := range deny {
			name, ver, hasVer := strings.Cut(d, "@")
			if c.Name == name && (!hasVer || c.Version == ver) {
				hits = append(hits, c.Name+"@"+c.Version)
			}
		}
	}
	return hits, nil
}
