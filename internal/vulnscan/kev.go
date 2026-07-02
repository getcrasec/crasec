package vulnscan

import "github.com/getcrasec/crasec/internal/kev"

// ApplyKEV cross-references findings against the CISA KEV catalog by
// vulnerability ID (checking aliases too, since Grype and OSV-Scanner don't
// always agree on which ID is primary) and flags matches as actively
// exploited. It mutates findings in place.
//
// This only sets the exploitation flag; it does not compute the CRA
// relevance score, since that also needs EPSS data. Call ApplyCRAScore
// afterward (see cra_score.go) to (re)compute it from the now-current
// ActivelyExploited value.
func ApplyKEV(findings []Finding, catalog *kev.Catalog) {
	for i := range findings {
		f := &findings[i]

		ids := append([]string{f.VulnerabilityID}, f.AliasIDs...)
		for _, id := range ids {
			entry, ok := catalog.Lookup(id)
			if !ok {
				continue
			}
			f.ActivelyExploited = true
			f.KEVDateAdded = entry.DateAdded
			f.KEVDueDate = entry.DueDate
			break
		}
	}
}
