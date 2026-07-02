// Package euvd is a client for ENISA's EU Vulnerability Database (EUVD),
// the CRA's own authoritative vulnerability source and the database behind
// ENISA's Single Reporting Platform. It's kept isolated in its own package,
// separate from the vulnscan cross-referencing logic that uses it, because
// the API is in beta: ENISA's published spec at
// https://euvd.enisa.europa.eu/apidoc covers only what's implemented here
// (client-side filtering over the /search endpoint, since there's no
// dedicated exact-CVE-lookup parameter) and is expected to change before
// the API is finalized. When that happens, only this package should need
// to change.
package euvd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// searchURL is EUVD's actual API host, distinct from the euvd.enisa.europa.eu
// web app (which serves the browsable catalog UI, not the API).
const searchURL = "https://euvdservices.enisa.europa.eu/api/search"

// searchPageSize bounds how many candidate records a text search returns
// before client-side filtering for an exact alias match.
const searchPageSize = 50

// Client queries the EUVD API.
type Client struct {
	httpClient *http.Client
	searchURL  string
}

// NewClient returns a Client using EUVD's live search endpoint.
func NewClient() *Client {
	return NewClientWithURL(searchURL)
}

// NewClientWithURL returns a Client that queries the given search endpoint
// instead of EUVD's live one, for testing against a mock server.
func NewClientWithURL(url string) *Client {
	return &Client{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		searchURL:  url,
	}
}

// Entry is one EUVD catalog record, normalized from the API's raw shape
// (which represents aliases/references as newline-delimited strings rather
// than arrays, and baseScore as a nullable number).
type Entry struct {
	ID               string
	Description      string
	DatePublished    string
	DateUpdated      string
	BaseScore        float64
	HasBaseScore     bool
	BaseScoreVersion string
	BaseScoreVector  string
	References       []string
	Aliases          []string
	Assigner         string
	EPSS             float64
	ExploitedSince   string
}

type searchResponse struct {
	Items []rawEntry `json:"items"`
	Total int        `json:"total"`
}

// rawEntry mirrors the EUVD /search response fields actually observed from
// the live (beta) API, not the documented spec, which was unavailable at
// the time this was written.
type rawEntry struct {
	ID               string   `json:"id"`
	Description      string   `json:"description"`
	DatePublished    string   `json:"datePublished"`
	DateUpdated      string   `json:"dateUpdated"`
	BaseScore        *float64 `json:"baseScore"`
	BaseScoreVersion string   `json:"baseScoreVersion"`
	BaseScoreVector  string   `json:"baseScoreVector"`
	References       string   `json:"references"`
	Aliases          string   `json:"aliases"`
	Assigner         string   `json:"assigner"`
	EPSS             float64  `json:"epss"`
	ExploitedSince   string   `json:"exploitedSince"`
}

func (r rawEntry) toEntry() Entry {
	e := Entry{
		ID:               r.ID,
		Description:      r.Description,
		DatePublished:    r.DatePublished,
		DateUpdated:      r.DateUpdated,
		BaseScoreVersion: r.BaseScoreVersion,
		BaseScoreVector:  r.BaseScoreVector,
		References:       splitNonEmptyLines(r.References),
		Aliases:          splitNonEmptyLines(r.Aliases),
		Assigner:         r.Assigner,
		EPSS:             r.EPSS,
		ExploitedSince:   r.ExploitedSince,
	}
	if r.BaseScore != nil {
		e.BaseScore = *r.BaseScore
		e.HasBaseScore = true
	}
	return e
}

func splitNonEmptyLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// LookupCVE searches EUVD for the vulnerability record whose aliases (or ID)
// exactly match cveID, or returns (nil, nil) if EUVD has no such record.
//
// EUVD's beta /search endpoint has no dedicated CVE-lookup parameter, only
// a free-text "text" search that matches on description content too — a
// search for a well-known CVE ID can return unrelated records that merely
// mention it (e.g. "this is not the Log4Shell vulnerability"). To get an
// exact match, this fetches candidates via text search and filters
// client-side for a record whose own alias list contains cveID.
func (c *Client) LookupCVE(ctx context.Context, cveID string) (*Entry, error) {
	items, err := c.search(ctx, url.Values{
		"text": {cveID},
		"size": {fmt.Sprint(searchPageSize)},
	})
	if err != nil {
		return nil, err
	}

	for _, item := range items {
		entry := item.toEntry()
		if strings.EqualFold(entry.ID, cveID) || containsFold(entry.Aliases, cveID) {
			return &entry, nil
		}
	}
	return nil, nil
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

func (c *Client) search(ctx context.Context, params url.Values) ([]rawEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.searchURL+"?"+params.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("building EUVD search request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("querying EUVD: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("querying EUVD: unexpected status %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var sr searchResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return nil, fmt.Errorf("parsing EUVD search response: %w", err)
	}
	return sr.Items, nil
}
