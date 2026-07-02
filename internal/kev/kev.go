// Package kev fetches, caches, and looks up entries in CISA's Known
// Exploited Vulnerabilities (KEV) catalog. A CVE's presence in KEV means
// CISA has confirmed it is being actively exploited in the wild, which is
// the signal CRA Article 14's 24-hour ENISA reporting deadline keys off.
package kev

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// catalogURL is CISA's published feed; it's regenerated daily.
const catalogURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// refreshInterval controls how stale the on-disk cache may be before Load
// re-downloads the catalog, matching CISA's own daily update cadence.
const refreshInterval = 24 * time.Hour

// Catalog is CISA's KEV feed, indexed by CVE ID for fast lookup.
type Catalog struct {
	CatalogVersion  string  `json:"catalogVersion"`
	DateReleased    string  `json:"dateReleased"`
	Count           int     `json:"count"`
	Vulnerabilities []Entry `json:"vulnerabilities"`

	byCVE map[string]Entry
}

// Entry is one CISA KEV catalog record.
type Entry struct {
	CVEID                      string `json:"cveID"`
	VendorProject              string `json:"vendorProject"`
	Product                    string `json:"product"`
	VulnerabilityName          string `json:"vulnerabilityName"`
	DateAdded                  string `json:"dateAdded"`
	ShortDescription           string `json:"shortDescription"`
	RequiredAction             string `json:"requiredAction"`
	DueDate                    string `json:"dueDate"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	Notes                      string `json:"notes"`
}

// Load returns the KEV catalog, serving it from the on-disk cache at
// cachePath when the cache is younger than refreshInterval, and downloading
// a fresh copy from CISA (rewriting the cache) otherwise. If a fresh
// download fails, Load falls back to a stale cache rather than failing
// outright, since a day-old KEV catalog is still far better than none.
func Load(ctx context.Context, cachePath string) (*Catalog, error) {
	if info, err := os.Stat(cachePath); err == nil && time.Since(info.ModTime()) < refreshInterval {
		if c, err := loadFromFile(cachePath); err == nil {
			return c, nil
		}
	}

	c, raw, err := download(ctx)
	if err != nil {
		if c, ferr := loadFromFile(cachePath); ferr == nil {
			return c, nil
		}
		return nil, err
	}

	if mkErr := os.MkdirAll(filepath.Dir(cachePath), 0o755); mkErr == nil {
		_ = os.WriteFile(cachePath, raw, 0o644)
	}

	return c, nil
}

func download(ctx context.Context) (*Catalog, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, catalogURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("building KEV catalog request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("downloading KEV catalog: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("downloading KEV catalog: unexpected status %s", resp.Status)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("reading KEV catalog response: %w", err)
	}

	c, err := ParseCatalog(raw)
	if err != nil {
		return nil, nil, err
	}
	return c, raw, nil
}

func loadFromFile(path string) (*Catalog, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseCatalog(raw)
}

// ParseCatalog parses raw KEV catalog JSON (as downloaded from CISA, or
// read from a local copy) into a Catalog ready for Lookup.
func ParseCatalog(raw []byte) (*Catalog, error) {
	var c Catalog
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parsing KEV catalog: %w", err)
	}
	c.byCVE = make(map[string]Entry, len(c.Vulnerabilities))
	for _, e := range c.Vulnerabilities {
		c.byCVE[strings.ToUpper(e.CVEID)] = e
	}
	return &c, nil
}

// Lookup returns the KEV entry for cveID, if CISA lists it as actively
// exploited. It's safe to call on a nil Catalog.
func (c *Catalog) Lookup(cveID string) (Entry, bool) {
	if c == nil {
		return Entry{}, false
	}
	e, ok := c.byCVE[strings.ToUpper(cveID)]
	return e, ok
}

// DefaultCachePath returns where the KEV catalog is cached when the caller
// has no more specific location in mind: alongside crasec's other local
// state, in ~/.crasec/cache.
func DefaultCachePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving home directory for KEV cache: %w", err)
	}
	return filepath.Join(home, ".crasec", "cache", "kev.json"), nil
}
