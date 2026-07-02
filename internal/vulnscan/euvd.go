package vulnscan

import (
	"context"
	"math"
	"strings"

	"github.com/getcrasec/crasec/internal/euvd"
)

// severityDisagreementThreshold is how far apart two CVSS base scores (on
// the standard 0-10 scale) must be before they're flagged as a genuine
// disagreement, rather than routine cross-source rounding noise.
const severityDisagreementThreshold = 1.0

// ApplyEUVD cross-references findings against ENISA's EU Vulnerability
// Database by CVE ID (checking aliases too, since Grype/OSV-Scanner and
// EUVD don't always agree on which ID is primary) and attaches any EU
// severity assessment it finds, without overwriting the finding's existing
// CVSS data. It mutates findings in place.
//
// EUVD's API is in beta and can be unreachable; the first lookup failure
// (a transport error or non-200 response, as opposed to "no EUVD record
// for this CVE") is treated as the API being down and aborts immediately
// rather than repeating the failure across every remaining finding. The
// caller should treat a non-nil error as "EUVD enrichment unavailable this
// run" and continue without it, not as fatal to the whole correlation.
func ApplyEUVD(ctx context.Context, findings []Finding, client *euvd.Client) error {
	cache := map[string]*euvd.Entry{}

	for i := range findings {
		f := &findings[i]

		entry, err := lookupEUVD(ctx, client, cache, *f)
		if err != nil {
			return err
		}
		if entry == nil {
			continue
		}

		f.EUVDID = entry.ID
		f.EUVDBaseScoreVersion = entry.BaseScoreVersion
		f.EUVDBaseScoreVector = entry.BaseScoreVector
		f.EUVDExploitedSince = entry.ExploitedSince
		if entry.HasBaseScore {
			f.EUVDBaseScore = entry.BaseScore
			if f.CVSSScore > 0 {
				f.SeverityDisagreement = math.Abs(entry.BaseScore-f.CVSSScore) >= severityDisagreementThreshold
			}
		}
	}
	return nil
}

// lookupEUVD tries the finding's vulnerability ID and each alias in turn
// (EUVD only indexes CVE IDs), caching results across findings since the
// same CVE commonly affects multiple components in an SBOM.
func lookupEUVD(ctx context.Context, client *euvd.Client, cache map[string]*euvd.Entry, f Finding) (*euvd.Entry, error) {
	ids := append([]string{f.VulnerabilityID}, f.AliasIDs...)
	for _, id := range ids {
		if !strings.HasPrefix(strings.ToUpper(id), "CVE-") {
			continue
		}
		if entry, ok := cache[id]; ok {
			if entry != nil {
				return entry, nil
			}
			continue
		}
		entry, err := client.LookupCVE(ctx, id)
		if err != nil {
			return nil, err
		}
		cache[id] = entry
		if entry != nil {
			return entry, nil
		}
	}
	return nil, nil
}
