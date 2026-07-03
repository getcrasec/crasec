// Package epss is a client for FIRST.org's Exploit Prediction Scoring
// System (EPSS) API, which publishes a daily-updated 0-1 probability that
// a given CVE will be exploited in the wild in the next 30 days. It's one
// input to crasec's CRA-relevance scoring formula (see
// internal/vulnscan/cra_score.go): a high EPSS probability raises a
// finding's urgency independent of CVSS severity alone.
package epss

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// endpoint is FIRST.org's EPSS API, as published at
// https://api.first.org/data/v1/epss.
const endpoint = "https://api.first.org/data/v1/epss"

// batchSize caps how many CVEs are queried per request. FIRST.org's
// response is paginated with a default page size of 100 records; batching
// any larger than that risks silently truncated results since this client
// doesn't paginate within a batch.
const batchSize = 100

// Client queries the EPSS API.
type Client struct {
	httpClient *http.Client
	endpoint   string
}

// NewClient returns a Client using FIRST.org's live EPSS endpoint.
func NewClient() *Client {
	return NewClientWithURL(endpoint)
}

// NewClientWithURL returns a Client that queries the given endpoint
// instead of the live one, for testing against a mock server.
func NewClientWithURL(url string) *Client {
	return &Client{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		endpoint:   url,
	}
}

type response struct {
	Data []record `json:"data"`
}

// record mirrors the EPSS API's response shape; epss/percentile come back
// as strings (e.g. "0.999990000"), not JSON numbers.
type record struct {
	CVE        string `json:"cve"`
	EPSS       string `json:"epss"`
	Percentile string `json:"percentile"`
	Date       string `json:"date"`
}

// FetchScores returns EPSS exploitation-probability scores (0-1) for the
// given CVE IDs, keyed by uppercased CVE ID. Non-CVE IDs (GHSA, OSV, etc.)
// are ignored, since EPSS only scores CVEs. A CVE with no EPSS record (not
// yet scored, or simply nonexistent) is absent from the map rather than
// treated as an error.
//
// Requests are batched (the EPSS API accepts a comma-separated CVE list)
// to keep this to a handful of round trips even for large SBOMs. A batch
// request failure aborts the whole call; the caller should treat a non-nil
// error as "EPSS unavailable this run" and degrade to no EPSS data rather
// than fail its own operation outright.
func (c *Client) FetchScores(ctx context.Context, cveIDs []string) (map[string]float64, error) {
	unique := dedupeCVEs(cveIDs)
	scores := make(map[string]float64, len(unique))

	for _, batch := range chunk(unique, batchSize) {
		recs, err := c.fetchBatch(ctx, batch)
		if err != nil {
			return nil, err
		}
		for _, r := range recs {
			p, err := strconv.ParseFloat(r.EPSS, 64)
			if err != nil {
				continue
			}
			scores[strings.ToUpper(r.CVE)] = p
		}
	}
	return scores, nil
}

func (c *Client) fetchBatch(ctx context.Context, cveIDs []string) ([]record, error) {
	if len(cveIDs) == 0 {
		return nil, nil
	}

	params := url.Values{"cve": {strings.Join(cveIDs, ",")}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+"?"+params.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("building EPSS request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("querying EPSS: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only handle; nothing to flush on close

	if resp.StatusCode != http.StatusOK {
		// Best-effort: body is only for the error message below, so a read
		// failure just means an empty snippet, not a reason to fail differently.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096)) //nolint:errcheck
		return nil, fmt.Errorf("querying EPSS: unexpected status %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var r response
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, fmt.Errorf("parsing EPSS response: %w", err)
	}
	return r.Data, nil
}

func dedupeCVEs(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	var out []string
	for _, id := range ids {
		upper := strings.ToUpper(id)
		if !strings.HasPrefix(upper, "CVE-") {
			continue
		}
		if _, ok := seen[upper]; ok {
			continue
		}
		seen[upper] = struct{}{}
		out = append(out, upper)
	}
	return out
}

func chunk(ids []string, size int) [][]string {
	var chunks [][]string
	for i := 0; i < len(ids); i += size {
		end := i + size
		if end > len(ids) {
			end = len(ids)
		}
		chunks = append(chunks, ids[i:end])
	}
	return chunks
}
