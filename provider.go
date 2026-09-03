// Copyright (c) the go-aiquota authors.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-browserhttp/browserhttp"

	"github.com/go-aiquota/proto/quotapb"
)

const (
	providerName = "claude"
	loginURL     = "https://claude.ai/login"
	cookieDomain = "claude.ai"

	// orgUUIDKey is the one non-cookie field this provider needs alongside
	// the claude.ai session cookies in FetchQuotaRequest.Credential — the
	// proto's own doc comment for Credential anticipates exactly this
	// ("or other credential fields for a future non-cookie provider").
	// The usage endpoint is per-organization, and there is no page a
	// scripted client can hit to rediscover an org's UUID from cookies
	// alone the way the real web app does on load (that path itself needs
	// a real browser to get past); the org UUID is visible in the login
	// response instead (memberships[].organization.uuid), so go-aiquota/tray's
	// onboarding flow is expected to capture it there and store it under
	// this key next to the cookies.
	orgUUIDKey = "org_uuid"

	requestTimeout = 20 * time.Second
)

// baseURL is claude.ai's own origin — a var, not a const, so a same-process
// unit test can point FetchQuota at an httptest server instead of the real
// site. baseURLEnv overrides it at startup for a subprocess-level
// integration test, which — being a separately built and launched binary —
// cannot reach into this process's variables the way a same-process test
// can.
var baseURL = "https://claude.ai"

const baseURLEnv = "PLUGIN_CLAUDE_BASE_URL"

func init() {
	if v := os.Getenv(baseURLEnv); v != "" {
		baseURL = v
	}
}

// newHTTPClient builds the client FetchQuota uses. Production uses
// browserhttp's Chrome-TLS-fingerprinted client (already-established,
// shared fleet infrastructure — see github.com/go-browserhttp/browserhttp),
// since claude.ai's edge is known to challenge non-browser-shaped clients;
// tests override this to a plain client, irrelevant against a local
// httptest server and slower to build for no benefit there.
var newHTTPClient = func() *http.Client { return browserhttp.NewClient(requestTimeout) }

// Provider implements quotapb.QuotaProviderServer for Claude.
type Provider struct {
	quotapb.UnimplementedQuotaProviderServer
}

// Describe returns where go-aiquota/tray's onboarding browser should open
// to start a login, and which domain's cookies to capture once it
// completes.
func (Provider) Describe(context.Context, *quotapb.DescribeRequest) (*quotapb.ProviderInfo, error) {
	return &quotapb.ProviderInfo{
		Name:         providerName,
		LoginUrl:     loginURL,
		CookieDomain: cookieDomain,
	}, nil
}

// FetchQuota turns req's cookies (plus orgUUIDKey) into a live usage
// snapshot by calling claude.ai's own account-usage endpoint — the same
// one its web app calls to show the usage bar in Settings — and mapping
// each of its reported limits into a QuotaWindow.
func (Provider) FetchQuota(ctx context.Context, req *quotapb.FetchQuotaRequest) (*quotapb.QuotaSnapshot, error) {
	orgUUID := req.GetCredential()[orgUUIDKey]
	if orgUUID == "" {
		return nil, fmt.Errorf("plugin-claude: credential is missing %q — the account must be re-added so onboarding can capture it alongside the claude.ai cookies", orgUUIDKey)
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("plugin-claude: parsing base URL %q: %w", baseURL, err)
	}

	client := newHTTPClient()
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("plugin-claude: building a cookie jar: %w", err)
	}
	client.Jar = jar
	setCookies(jar, base, req.GetCredential())

	usageURL := baseURL + "/api/organizations/" + url.PathEscape(orgUUID) + "/usage"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, usageURL, nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", browserhttp.DefaultUserAgent)

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("plugin-claude: fetching usage: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("plugin-claude: reading usage response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("plugin-claude: usage request returned %d — the account's session has likely expired; re-add it", resp.StatusCode)
	}
	if isChallengePage(body) {
		return nil, fmt.Errorf("plugin-claude: usage request was met with a bot-challenge page instead of JSON")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("plugin-claude: usage request returned %d: %s", resp.StatusCode, truncate(body, 200))
	}

	var usage usageResponse
	if err := json.Unmarshal(body, &usage); err != nil {
		return nil, fmt.Errorf("plugin-claude: parsing usage response: %w", err)
	}
	return snapshotFrom(req.GetAccountLabel(), usage), nil
}

// setCookies loads every credential entry except orgUUIDKey into jar as a
// cookie for u (the same URL requests are actually sent to — base, not a
// hardcoded cookieDomain, so a test pointing baseURL at an httptest server
// gets cookies that actually match what it requests) — req.Credential is
// go-aiquota/tray's onboarding handing back the WHOLE cookie jar it
// captured (it doesn't know which cookie claude.ai actually needs), so this
// provider is the one place that decides: all of them, since a stray extra
// cookie is harmless and guessing wrong about which ONE matters is not.
func setCookies(jar http.CookieJar, u *url.URL, credential map[string]string) {
	cookies := make([]*http.Cookie, 0, len(credential))
	for name, value := range credential {
		if name == orgUUIDKey {
			continue
		}
		cookies = append(cookies, &http.Cookie{Name: name, Value: value})
	}
	jar.SetCookies(u, cookies)
}

// usageResponse is the subset of GET /api/organizations/{uuid}/usage's
// response shape this provider maps — captured live against a real
// account. The endpoint returns many more fields (per-model breakdowns,
// prepaid credit balances, spend limits) that are null for a plan without
// them; only limits[] is mapped for v1, since it is the one part every
// plan kind observed so far actually populates.
type usageResponse struct {
	Limits []usageLimit `json:"limits"`
}

type usageLimit struct {
	// Kind is claude.ai's own name for the window, e.g. "session",
	// "weekly_all", "weekly_scoped" — used as QuotaWindow.Label directly
	// (the proto's own doc comment allows a "provider-defined" label, and
	// translating these into something else would risk masking a real
	// distinction, e.g. weekly_scoped being tied to one model).
	Kind     string  `json:"kind"`
	Percent  float64 `json:"percent"`
	ResetsAt *string `json:"resets_at"`
}

// snapshotFrom maps one usageResponse into a QuotaSnapshot. Every entry in
// limits[] becomes a window at Used=percent out of Limit=100 ("%", per the
// proto's own Unit examples) — including inactive/scoped ones: the host's
// menubar package already treats "worst window wins" for severity, so a
// currently-harmless scoped window costs nothing to include and a future
// one that stops being harmless is not silently missing.
func snapshotFrom(accountLabel string, usage usageResponse) *quotapb.QuotaSnapshot {
	snap := &quotapb.QuotaSnapshot{
		AccountLabel:  accountLabel,
		FetchedAtUnix: time.Now().Unix(),
	}
	for _, l := range usage.Limits {
		w := &quotapb.QuotaWindow{
			Label: l.Kind,
			Used:  l.Percent,
			Limit: 100,
			Unit:  "%",
		}
		if l.ResetsAt != nil {
			if t, err := time.Parse(time.RFC3339, *l.ResetsAt); err == nil {
				w.ResetsAtUnix = t.Unix()
			}
		}
		snap.Windows = append(snap.Windows, w)
	}
	return snap
}

// challengeMarkers mirror go-webengine/engine's own botChallengeMarkers:
// body fragments that identify a Cloudflare-style interstitial rather than
// real JSON — so a challenged API call fails with a clear, specific error
// instead of a confusing JSON-parse error.
var challengeMarkers = []string{
	"just a moment",
	"cf-browser-verification",
	"challenge-platform",
	"performing security verification",
}

func isChallengePage(body []byte) bool {
	lower := strings.ToLower(string(body))
	for _, marker := range challengeMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func truncate(b []byte, n int) string {
	s := string(b)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
