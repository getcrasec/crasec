package vulnscan

import "github.com/getcrasec/crasec/internal/kev"

// Article14Threshold is the CRARelevanceScore a finding must meet or exceed
// for Article14ReportRequired to be set. A KEV match always forces the
// score to 100, i.e. above threshold; nothing else currently does.
const Article14Threshold = 90.0

// ApplyKEV cross-references findings against the CISA KEV catalog by
// vulnerability ID (checking aliases too, since Grype and OSV-Scanner don't
// always agree on which ID is primary), flags matches as actively
// exploited, and recomputes each finding's CRA relevance score/Article 14
// flag accordingly. It mutates findings in place.
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

		f.CRARelevanceScore = craRelevanceScore(*f)
		f.Article14ReportRequired = f.CRARelevanceScore >= Article14Threshold
	}
}

// craRelevanceScore scales CVSS (0-10) to a 0-100 triage score, forcing 100
// whenever the finding is a confirmed KEV match regardless of CVSS.
func craRelevanceScore(f Finding) float64 {
	if f.ActivelyExploited {
		return 100
	}
	score := f.CVSSScore * 10
	if score > 100 {
		score = 100
	}
	return score
}
