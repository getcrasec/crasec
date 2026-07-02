package vulnscan

import "strings"

// MergeFindings combines Findings from multiple scanners (Correlate,
// RunOSVScanner, ...) into one deduplicated slice. Findings are matched by
// vulnerability ID (including any aliases, e.g. a GHSA ID and the CVE it
// maps to) together with the affected package. When the same
// vulnerability/package pair is reported by more than one scanner, the
// results are merged into a single Finding whose Scanners field lists every
// scanner that reported it (for auditability) and whose other fields prefer
// whichever scanner is known to be more reliable for that field:
// OSV-Scanner for fix versions, Grype for CVSS data.
func MergeFindings(sources ...[]Finding) []Finding {
	index := map[string]*Finding{}
	var merged []*Finding

	for _, findings := range sources {
		for _, f := range findings {
			pkg := packageKey(f)
			ids := append([]string{f.VulnerabilityID}, f.AliasIDs...)

			var existing *Finding
			for _, id := range ids {
				if e, ok := index[mergeIndexKey(id, pkg)]; ok {
					existing = e
					break
				}
			}

			if existing == nil {
				fCopy := f
				existing = &fCopy
				merged = append(merged, existing)
			} else {
				scanner := ScannerGrype
				if len(f.Scanners) > 0 {
					scanner = f.Scanners[0]
				}
				mergeInto(existing, f, scanner)
			}

			for _, id := range ids {
				index[mergeIndexKey(id, pkg)] = existing
			}
		}
	}

	result := make([]Finding, len(merged))
	for i, f := range merged {
		result[i] = *f
	}
	return result
}

// mergeInto folds incoming (reported by scanner) into existing, which
// already holds data from at least one other scanner run.
func mergeInto(existing *Finding, incoming Finding, scanner string) {
	existing.Scanners = appendUnique(existing.Scanners, scanner)
	existing.AliasIDs = appendUnique(existing.AliasIDs, incoming.VulnerabilityID)
	for _, a := range incoming.AliasIDs {
		existing.AliasIDs = appendUnique(existing.AliasIDs, a)
	}
	existing.AliasIDs = removeString(existing.AliasIDs, existing.VulnerabilityID)

	if existing.PackagePURL == "" {
		existing.PackagePURL = incoming.PackagePURL
	}
	if existing.Severity == "" {
		existing.Severity = incoming.Severity
	}
	if existing.DataSource == "" {
		existing.DataSource = incoming.DataSource
	}

	switch scanner {
	case ScannerGrype:
		// Grype's CVSS data draws on more sources (NVD plus vendor scores)
		// and picks the highest base score across them; prefer it whenever
		// it has an opinion.
		if incoming.CVSSScore > 0 {
			existing.CVSSScore = incoming.CVSSScore
			existing.CVSSVector = incoming.CVSSVector
		}
		if len(existing.FixVersions) == 0 {
			existing.FixVersions = incoming.FixVersions
			existing.FixState = incoming.FixState
		}
	case ScannerOSV:
		// OSV.dev fix data tends to be more current/accurate (advisories
		// are maintained closer to upstream release tags); prefer it
		// whenever it has an opinion.
		if len(incoming.FixVersions) > 0 {
			existing.FixVersions = incoming.FixVersions
			existing.FixState = incoming.FixState
		}
		if existing.CVSSScore == 0 && incoming.CVSSScore > 0 {
			existing.CVSSScore = incoming.CVSSScore
			existing.CVSSVector = incoming.CVSSVector
		}
	}
}

// packageKey identifies the affected package for dedup purposes. OSV-Scanner
// findings never carry a PURL (osv-scanner reports ecosystem+name+version,
// not the original PURL), so PURL can't be used as the key or Grype and
// OSV-Scanner findings for the same package would never match; name+version
// is what both scanners derive from the same SBOM component, so it's used
// consistently for every source.
func packageKey(f Finding) string {
	return strings.ToLower(f.PackageName) + "@" + f.PackageVersion
}

func mergeIndexKey(id, pkg string) string {
	return strings.ToUpper(id) + "|" + pkg
}

func appendUnique(list []string, s string) []string {
	if s == "" || containsString(list, s) {
		return list
	}
	return append(list, s)
}

func containsString(list []string, s string) bool {
	for _, existing := range list {
		if existing == s {
			return true
		}
	}
	return false
}

func removeString(list []string, s string) []string {
	out := list[:0]
	for _, existing := range list {
		if existing != s {
			out = append(out, existing)
		}
	}
	return out
}
