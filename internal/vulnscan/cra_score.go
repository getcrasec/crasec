package vulnscan

import "strings"

// CRA relevance categories, in descending urgency order.
const (
	CRACategoryCritical = "CRA-CRITICAL" // score > craCriticalThreshold: Article 14 trigger
	CRACategoryMonitor  = "MONITOR"      // craMonitorThreshold <= score <= craCriticalThreshold
	CRACategoryLow      = "LOW"          // score < craMonitorThreshold
)

// Formula constants for the CRA-relevance score:
//
//	CRA Score = CVSS Base Score × KEV Multiplier × EPSS Weight
//
// CVSS Base Score is Finding.CVSSScore (0-10, the best available score
// across Grype/OSV-Scanner sources — see MergeFindings). KEV Multiplier
// rewards confirmed active exploitation; EPSS Weight rewards a high
// predicted probability of exploitation in the next 30 days. Max possible
// score is 10 × 2.0 × 1.5 = 30.
const (
	kevMultiplierExploited    = 2.0
	kevMultiplierNotExploited = 1.0

	epssHighProbabilityThreshold = 0.7
	epssWeightHighProbability    = 1.5
	epssWeightDefault            = 1.0

	// craCriticalThreshold and craMonitorThreshold partition the score
	// range into CRACategoryCritical (> craCriticalThreshold),
	// CRACategoryMonitor ([craMonitorThreshold, craCriticalThreshold]),
	// and CRACategoryLow (< craMonitorThreshold).
	craCriticalThreshold = 14.0
	craMonitorThreshold  = 7.0
)

// ApplyCRAScore computes each finding's CRA relevance score, category, and
// Article14ReportRequired flag. It mutates findings in place and should run
// after ApplyKEV (so ActivelyExploited reflects the current KEV catalog)
// and after fetching epssScores (so the EPSS weight reflects current
// exploitation-probability data); either input may be a zero-value
// map/all-false if that data source is unavailable or disabled for this
// run, in which case the corresponding multiplier/weight is left at its
// default (1.0) rather than the finding being skipped.
//
// epssScores maps CVE ID (uppercased) to EPSS probability (0-1), as
// returned by epss.Client.FetchScores; a finding whose vulnerability ID (or
// aliases) has no entry is treated as having no EPSS data.
func ApplyCRAScore(findings []Finding, epssScores map[string]float64) {
	for i := range findings {
		f := &findings[i]

		kevMultiplier := kevMultiplierNotExploited
		if f.ActivelyExploited {
			kevMultiplier = kevMultiplierExploited
		}

		f.EPSSScore = epssScoreFor(*f, epssScores)
		epssWeight := epssWeightDefault
		if f.EPSSScore > epssHighProbabilityThreshold {
			epssWeight = epssWeightHighProbability
		}

		f.CRARelevanceScore = f.CVSSScore * kevMultiplier * epssWeight
		f.CRACategory = craCategoryFor(f.CRARelevanceScore)
		f.Article14ReportRequired = f.CRACategory == CRACategoryCritical
	}
}

func epssScoreFor(f Finding, epssScores map[string]float64) float64 {
	ids := append([]string{f.VulnerabilityID}, f.AliasIDs...)
	for _, id := range ids {
		if p, ok := epssScores[strings.ToUpper(id)]; ok {
			return p
		}
	}
	return 0
}

func craCategoryFor(score float64) string {
	switch {
	case score > craCriticalThreshold:
		return CRACategoryCritical
	case score >= craMonitorThreshold:
		return CRACategoryMonitor
	default:
		return CRACategoryLow
	}
}
