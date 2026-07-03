// Package csafpublish implements the CSAF 2.0 "well-known" discovery
// mechanism: publishing an advisory into a directory tree served at
// https://<domain>/.well-known/csaf/, per
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#7-distributing-csaf-documents.
// This is how downstream tools, aggregators, and market-surveillance
// authorities find a manufacturer's advisories without knowing a specific
// URL in advance. ENISA expects CRA vulnerability disclosures to be
// reachable this way.
package csafpublish

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	csaf "github.com/gocsaf/csaf/v3/csaf"
	"github.com/gocsaf/csaf/v3/util"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

// Options controls where and how an advisory is published.
type Options struct {
	// WellKnownRoot is the directory that will contain .well-known/csaf/,
	// e.g. "./public" for a site rooted there.
	WellKnownRoot string
	// BaseURL is the public origin the directory will be served from,
	// e.g. "https://crasec.io" (no trailing slash, no path).
	BaseURL string
	// Role is the CSAF provider role: csaf_publisher, csaf_provider, or
	// csaf_trusted_provider. crasec signs with Sigstore rather than the
	// OpenPGP detached signatures CSAF's "trusted provider" conformance
	// requires, so csaf_provider (checksums, no PGP) is the honest default.
	Role string

	ListOnAggregators   bool
	MirrorOnAggregators bool
}

// Result summarizes what Publish did, for the CLI to report.
type Result struct {
	TrackingID           string
	AdvisoryPath         string
	ProviderMetadataPath string
	IndexPath            string
	AdvisoryCount        int
}

// Publish validates advisoryPath against the CSAF 2.0 schema, then:
//  1. copies it into opts.WellKnownRoot/.well-known/csaf/advisories/ under a
//     filename derived from document.tracking.id (per the CSAF filename
//     convention: lowercased, invalid runes collapsed to "_"), alongside
//     SHA-256/SHA-512 checksums and, if present, its Sigstore .sig bundle;
//  2. regenerates index.txt to list every advisory currently in that
//     directory (not just the one just published);
//  3. creates or refreshes provider-metadata.json, carrying forward any
//     fields (e.g. public_openpgp_keys) a prior run or human left there.
//
// Nothing is written until the source advisory passes schema validation.
func Publish(advisoryPath string, opts Options) (*Result, error) {
	data, err := os.ReadFile(advisoryPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", advisoryPath, err)
	}

	adv, trackingID, err := parseAndValidateAdvisory(data, advisoryPath)
	if err != nil {
		return nil, err
	}

	role := csaf.MetadataRole(orDefault(opts.Role, string(csaf.MetadataRoleProvider)))
	switch role {
	case csaf.MetadataRolePublisher, csaf.MetadataRoleProvider, csaf.MetadataRoleTrustedProvider:
	default:
		return nil, fmt.Errorf("invalid role %q: must be csaf_publisher, csaf_provider, or csaf_trusted_provider", opts.Role)
	}
	base := strings.TrimSuffix(opts.BaseURL, "/")
	if base == "" {
		return nil, errors.New("base URL is required, e.g. https://crasec.io")
	}

	csafDir := filepath.Join(opts.WellKnownRoot, ".well-known", "csaf")
	advisoriesDir := filepath.Join(csafDir, "advisories")
	if err := os.MkdirAll(advisoriesDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating %s: %w", advisoriesDir, err)
	}

	filename := util.CleanFileName(trackingID)
	destPath := filepath.Join(advisoriesDir, filename)
	if err := publishAdvisoryFiles(advisoryPath, destPath, filename, data); err != nil {
		return nil, err
	}

	indexPath, count, err := regenerateIndex(csafDir, advisoriesDir)
	if err != nil {
		return nil, err
	}

	pmdPath, err := writeProviderMetadata(csafDir, base, role, adv, opts)
	if err != nil {
		return nil, err
	}

	return &Result{
		TrackingID:           trackingID,
		AdvisoryPath:         destPath,
		ProviderMetadataPath: pmdPath,
		IndexPath:            indexPath,
		AdvisoryCount:        count,
	}, nil
}

// parseAndValidateAdvisory validates data against the CSAF 2.0 schema and
// extracts document.tracking.id, needed to derive the published filename.
func parseAndValidateAdvisory(data []byte, sourcePath string) (*csaf.Advisory, string, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return nil, "", fmt.Errorf("parsing %s as JSON: %w", sourcePath, err)
	}
	violations, err := csaf.ValidateCSAF(doc)
	if err != nil {
		return nil, "", fmt.Errorf("validating %s against CSAF 2.0 schema: %w", sourcePath, err)
	}
	if len(violations) > 0 {
		return nil, "", fmt.Errorf("%s failed CSAF 2.0 schema validation:\n  %s", sourcePath, strings.Join(violations, "\n  "))
	}

	var adv csaf.Advisory
	if err := json.Unmarshal(data, &adv); err != nil {
		return nil, "", fmt.Errorf("parsing %s: %w", sourcePath, err)
	}
	if adv.Document == nil || adv.Document.Tracking == nil || adv.Document.Tracking.ID == nil || *adv.Document.Tracking.ID == "" {
		return nil, "", fmt.Errorf("%s is missing document.tracking.id", sourcePath)
	}
	return &adv, string(*adv.Document.Tracking.ID), nil
}

// publishAdvisoryFiles writes the advisory, its SHA-256/SHA-512 checksums,
// and (if present next to the source) its Sigstore .sig bundle into the
// advisories directory.
func publishAdvisoryFiles(srcPath, destPath, filename string, data []byte) error {
	if err := os.WriteFile(destPath, data, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", destPath, err)
	}

	sum256 := sha256.Sum256(data)
	if err := os.WriteFile(destPath+".sha256", []byte(fmt.Sprintf("%s  %s\n", hex.EncodeToString(sum256[:]), filename)), 0o644); err != nil {
		return fmt.Errorf("writing %s.sha256: %w", destPath, err)
	}
	sum512 := sha512.Sum512(data)
	if err := os.WriteFile(destPath+".sha512", []byte(fmt.Sprintf("%s  %s\n", hex.EncodeToString(sum512[:]), filename)), 0o644); err != nil {
		return fmt.Errorf("writing %s.sha512: %w", destPath, err)
	}

	if sig, err := os.ReadFile(srcPath + ".sig"); err == nil {
		if err := os.WriteFile(destPath+".sig", sig, 0o644); err != nil {
			return fmt.Errorf("writing %s.sig: %w", destPath, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("reading %s.sig: %w", srcPath, err)
	}

	return nil
}

// regenerateIndex rewrites csafDir/index.txt to list every advisory
// currently in advisoriesDir (a fresh listing, not an append-only log), one
// path relative to csafDir per line, sorted for a stable diff.
func regenerateIndex(csafDir, advisoriesDir string) (string, int, error) {
	matches, err := filepath.Glob(filepath.Join(advisoriesDir, "*.json"))
	if err != nil {
		return "", 0, fmt.Errorf("listing %s: %w", advisoriesDir, err)
	}
	names := make([]string, len(matches))
	for i, m := range matches {
		names[i] = filepath.Base(m)
	}
	sort.Strings(names)

	var buf bytes.Buffer
	for _, name := range names {
		fmt.Fprintf(&buf, "advisories/%s\n", name)
	}

	indexPath := filepath.Join(csafDir, "index.txt")
	if err := os.WriteFile(indexPath, buf.Bytes(), 0o644); err != nil {
		return "", 0, fmt.Errorf("writing %s: %w", indexPath, err)
	}
	return indexPath, len(names), nil
}

// writeProviderMetadata creates or refreshes provider-metadata.json:
// canonical_url/publisher/role/last_updated/the aggregator flags are always
// set fresh from adv and opts; any other fields already present in an
// existing file (e.g. a manually added public_openpgp_keys) are preserved.
func writeProviderMetadata(csafDir, baseURL string, role csaf.MetadataRole, adv *csaf.Advisory, opts Options) (string, error) {
	pmdPath := filepath.Join(csafDir, "provider-metadata.json")

	pmd, err := loadExistingProviderMetadata(pmdPath)
	if err != nil {
		return "", err
	}
	if pmd == nil {
		pmd = &csaf.ProviderMetadata{}
	}

	canonical := csaf.ProviderURL(baseURL + "/.well-known/csaf/provider-metadata.json")
	metaVersion := csaf.MetadataVersion20
	now := csaf.TimeStamp(time.Now().UTC())

	pmd.CanonicalURL = &canonical
	pmd.LastUpdated = &now
	pmd.MetadataVersion = &metaVersion
	pmd.ListOnCSAFAggregators = ptr(opts.ListOnAggregators)
	pmd.MirrorOnCSAFAggregators = ptr(opts.MirrorOnAggregators)
	pmd.Role = &role
	if pub := publisherFromAdvisory(adv); pub != nil {
		pmd.Publisher = pub
	}
	pmd.AddDirectoryDistribution(baseURL + "/.well-known/csaf/")

	data, err := json.MarshalIndent(pmd, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshaling provider metadata: %w", err)
	}

	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("re-parsing provider metadata for schema validation: %w", err)
	}
	violations, err := csaf.ValidateProviderMetadata(doc)
	if err != nil {
		return "", fmt.Errorf("validating provider metadata against CSAF 2.0 schema: %w", err)
	}
	if len(violations) > 0 {
		return "", fmt.Errorf("generated provider-metadata.json failed CSAF 2.0 schema validation:\n  %s", strings.Join(violations, "\n  "))
	}

	if err := os.WriteFile(pmdPath, data, 0o644); err != nil {
		return "", fmt.Errorf("writing %s: %w", pmdPath, err)
	}
	return pmdPath, nil
}

func loadExistingProviderMetadata(path string) (*csaf.ProviderMetadata, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var pmd csaf.ProviderMetadata
	if err := json.Unmarshal(data, &pmd); err != nil {
		return nil, fmt.Errorf("parsing existing %s: %w", path, err)
	}
	return &pmd, nil
}

// publisherFromAdvisory carries the advisory's own document.publisher over
// to provider-metadata.json's publisher block: the same manufacturer is
// issuing both, so there's no reason to ask the operator to repeat
// name/namespace/contact as separate flags.
func publisherFromAdvisory(adv *csaf.Advisory) *csaf.Publisher {
	if adv.Document == nil || adv.Document.Publisher == nil {
		return nil
	}
	dp := adv.Document.Publisher
	p := &csaf.Publisher{
		Category:  dp.Category,
		Name:      dp.Name,
		Namespace: dp.Namespace,
	}
	if dp.ContactDetails != nil {
		p.ContactDetails = *dp.ContactDetails
	}
	return p
}

func ptr[T any](v T) *T { return &v }

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
