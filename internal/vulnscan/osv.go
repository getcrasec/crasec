package vulnscan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

// osvOutput mirrors the subset of OSV-Scanner's JSON output format
// (https://google.github.io/osv-scanner/output/#json) needed to build
// Findings; fields not read here are left unmapped.
type osvOutput struct {
	Results []osvResult `json:"results"`
}

type osvResult struct {
	Packages []osvPackageResult `json:"packages"`
}

type osvPackageResult struct {
	Package         osvPackageInfo     `json:"package"`
	Vulnerabilities []osvVulnerability `json:"vulnerabilities"`
}

type osvPackageInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

type osvVulnerability struct {
	ID       string        `json:"id"`
	Aliases  []string      `json:"aliases"`
	Severity []osvSeverity `json:"severity"`
	Affected []osvAffected `json:"affected"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Ranges []osvRange `json:"ranges"`
}

type osvRange struct {
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Fixed string `json:"fixed,omitempty"`
}

// RunOSVScanner runs the osv-scanner CLI (https://github.com/google/osv-scanner)
// against the CycloneDX SBOM at sbomPath and returns one Finding per
// vulnerability/component pair it reports. Unlike Grype's NVD-based
// database, OSV-Scanner queries OSV.dev directly, which tends to have
// better coverage for Go modules, Python packages, Rust crates, and several
// Linux distro advisories.
//
// osv-scanner is a CLI tool rather than a Go library, so it must already be
// installed and on PATH:
//
//	go install github.com/google/osv-scanner/cmd/osv-scanner@latest
func RunOSVScanner(ctx context.Context, sbomPath string) ([]Finding, error) {
	if _, err := exec.LookPath("osv-scanner"); err != nil {
		return nil, fmt.Errorf("osv-scanner not found on PATH (install with 'go install github.com/google/osv-scanner/cmd/osv-scanner@latest'): %w", err)
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "osv-scanner", "--sbom", sbomPath, "--format", "json")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// osv-scanner exits 1 when it finds vulnerabilities (not just on real
	// failures), so a non-nil error here only matters if stdout didn't come
	// back as valid JSON.
	runErr := cmd.Run()

	var out osvOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		if runErr != nil {
			return nil, fmt.Errorf("running osv-scanner: %w: %s", runErr, strings.TrimSpace(stderr.String()))
		}
		return nil, fmt.Errorf("parsing osv-scanner output: %w", err)
	}

	var findings []Finding
	for _, result := range out.Results {
		for _, pkg := range result.Packages {
			for _, vuln := range pkg.Vulnerabilities {
				findings = append(findings, toOSVFinding(pkg.Package, vuln))
			}
		}
	}
	return findings, nil
}

// toOSVFinding converts one OSV-Scanner package/vulnerability pair into a
// Finding. When the vulnerability carries a CVE alias, that CVE becomes the
// primary VulnerabilityID (mirroring Grype's NormalizeByCVE behavior) so
// findings from both scanners key the same way during merge; whichever ID
// OSV-Scanner reported natively is kept in AliasIDs.
func toOSVFinding(pkg osvPackageInfo, vuln osvVulnerability) Finding {
	f := Finding{
		VulnerabilityID: vuln.ID,
		PackageName:     pkg.Name,
		PackageVersion:  pkg.Version,
		FixState:        "unknown",
		DataSource:      "osv.dev",
		Scanners:        []string{ScannerOSV},
	}

	primaryIsCVE := strings.HasPrefix(f.VulnerabilityID, "CVE-")
	aliases := make([]string, 0, len(vuln.Aliases))
	for _, alias := range vuln.Aliases {
		if !primaryIsCVE && strings.HasPrefix(alias, "CVE-") {
			aliases = append(aliases, f.VulnerabilityID)
			f.VulnerabilityID = alias
			primaryIsCVE = true
			continue
		}
		aliases = append(aliases, alias)
	}
	f.AliasIDs = aliases

	f.CVSSScore, f.CVSSVector = bestOSVCVSS(vuln.Severity)
	if f.CVSSScore > 0 {
		if rating, err := gocvss31.Rating(f.CVSSScore); err == nil {
			f.Severity = titleCase(rating)
		}
	}

	fixVersions := map[string]struct{}{}
	for _, affected := range vuln.Affected {
		for _, r := range affected.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					fixVersions[e.Fixed] = struct{}{}
				}
			}
		}
	}
	for v := range fixVersions {
		f.FixVersions = append(f.FixVersions, v)
	}
	if len(f.FixVersions) > 0 {
		f.FixState = "fixed"
	}

	return f
}

// bestOSVCVSS picks the highest CVSS base score across all severity entries
// OSV-Scanner reports for a vulnerability, computing the score itself since
// OSV publishes only the vector string, not the numeric score.
func bestOSVCVSS(severities []osvSeverity) (float64, string) {
	var bestScore float64
	var bestVector string
	for _, s := range severities {
		score, err := parseCVSSVectorScore(s.Score)
		if err != nil {
			continue
		}
		if score > bestScore {
			bestScore = score
			bestVector = s.Score
		}
	}
	return bestScore, bestVector
}

// parseCVSSVectorScore computes the base score for a CVSS vector string of
// any version (2.0 through 4.0).
func parseCVSSVectorScore(vector string) (float64, error) {
	switch {
	case strings.HasPrefix(vector, "CVSS:4.0/"):
		c, err := gocvss40.ParseVector(vector)
		if err != nil {
			return 0, err
		}
		return c.Score(), nil
	case strings.HasPrefix(vector, "CVSS:3.1/"):
		c, err := gocvss31.ParseVector(vector)
		if err != nil {
			return 0, err
		}
		return c.BaseScore(), nil
	case strings.HasPrefix(vector, "CVSS:3.0/"):
		c, err := gocvss30.ParseVector(vector)
		if err != nil {
			return 0, err
		}
		return c.BaseScore(), nil
	case vector != "":
		c, err := gocvss20.ParseVector(vector)
		if err != nil {
			return 0, err
		}
		return c.BaseScore(), nil
	default:
		return 0, errors.New("empty CVSS vector")
	}
}

// titleCase capitalizes s the way CVSS rating strings ("HIGH", "CRITICAL")
// should read alongside Grype's severity strings ("High", "Critical").
func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
}
