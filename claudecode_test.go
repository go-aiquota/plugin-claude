// Copyright (c) the go-aiquota authors.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/go-aiquota/proto/quotapb"
)

const fakeToken = "sk-ant-oat01-FAKEFAKEFAKEFAKEFAKEFAKEFAKE0123456789"

func credJSON(expiresInMs int64, plan string) []byte {
	exp := time.Now().UnixMilli() + expiresInMs
	return []byte(fmt.Sprintf(`{"claudeAiOauth":{"accessToken":%q,"refreshToken":"sk-ant-ort01-REFRESHREFRESHREFRESH0123456789","expiresAt":%d,"scopes":["user:inference","user:profile"],"subscriptionType":%q}}`, fakeToken, exp, plan))
}

// oauthFixture has the shape of the extension's schema Ft: windows, and a
// limits[] with a model-scoped entry.
const oauthFixture = `{
 "five_hour": {"utilization": 37.9, "resets_at": "2026-11-09T13:00:00.000000+00:00"},
 "seven_day": {"utilization": 52.0, "resets_at": "2026-11-12T02:00:00+00:00"},
 "seven_day_opus": null,
 "seven_day_sonnet": {"utilization": 8.5, "resets_at": "2026-11-12T02:00:00+00:00"},
 "extra_usage": {"is_enabled": false, "monthly_limit": null, "used_credits": null, "utilization": null},
 "limits": [
  {"kind":"weekly_scoped","group":"weekly","percent":61.2,"resets_at":"2026-11-12T02:00:00+00:00","severity":"ok","is_active":true,"scope":{"model":{"display_name":"Fable"}}},
  {"kind":"weekly_scoped","group":"weekly","percent":8.5,"resets_at":"2026-11-12T02:00:00+00:00","severity":"ok","is_active":true,"scope":{"model":{"display_name":"Sonnet"}}}
 ]
}`

func serve(t *testing.T, h http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	oldBase, oldAny, oldClient, oldRead := apiBase, allowAnyHost, claudeCodeClient, readCredential
	apiBase, allowAnyHost = srv.URL, true
	claudeCodeClient = func() *http.Client {
		c := srv.Client()
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		return c
	}
	t.Cleanup(func() { apiBase, allowAnyHost, claudeCodeClient, readCredential = oldBase, oldAny, oldClient, oldRead })
}

func withCred(b []byte) {
	readCredential = func(context.Context) ([]byte, error) { return b, nil }
}

// req asks for every window the endpoint returns (the default view); overlayReq
// asks for exactly the panel's rows.
func req() *quotapb.FetchQuotaRequest {
	return &quotapb.FetchQuotaRequest{AccountLabel: "Claude Code", Credential: map[string]string{sourceKey: sourceClaudeCode}}
}

func overlayReq() *quotapb.FetchQuotaRequest {
	return &quotapb.FetchQuotaRequest{AccountLabel: "Claude Code", Credential: map[string]string{sourceKey: sourceClaudeCode, viewKey: viewOverlay}}
}

// dynamicFixture is what the live endpoint looks like (2026-11-09): two
// windows with a value, known windows that are null, dozens of unrelated
// null fields, a non-window object, and a limits[] that repeats the two
// standard windows and adds a model-scoped one; plus the shapes it may take
// tomorrow: an unknown top-level window, a limits[] entry without a model,
// a window with a null utilization.
const dynamicFixture = `{
 "five_hour": {"utilization": 2.0, "resets_at": "2026-11-09T19:30:00.041358+00:00", "limit_dollars": null},
 "seven_day": {"utilization": 17.0, "resets_at": "2026-11-14T22:00:00.041377+00:00"},
 "seven_day_oauth_apps": {"utilization": 12.5, "resets_at": "2026-11-14T22:00:00+00:00"},
 "seven_day_opus": null,
 "seven_day_sonnet": null,
 "seven_day_cowork": {"utilization": null, "resets_at": null},
 "tangelo": null,
 "pace": null,
 "extra_usage": {"is_enabled": false, "utilization": null, "currency": null},
 "limits": [
  {"kind":"session","group":"session","percent":2,"severity":"normal","resets_at":"2026-11-09T19:30:00.041358+00:00","scope":null,"is_active":false},
  {"kind":"weekly_all","group":"weekly","percent":17,"severity":"normal","resets_at":"2026-11-14T22:00:00.041377+00:00","scope":null,"is_active":true},
  {"kind":"weekly_scoped","group":"weekly","percent":0,"severity":"normal","resets_at":"2026-11-14T22:00:00+00:00","scope":{"model":{"id":null,"display_name":"Fable"},"surface":null},"is_active":false},
  {"kind":"monthly_all","group":"monthly","percent":40,"severity":"warning","resets_at":"2026-12-01T00:00:00+00:00","scope":null,"is_active":true},
  {"kind":"weekly_scoped","group":"weekly","percent":61,"severity":"normal","scope":{"model":null,"surface":"cowork"}}
 ]
}`

func TestEveryWindowTheEndpointReturnsIsShown(t *testing.T) {
	serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/oauth/usage" {
			_, _ = w.Write([]byte(dynamicFixture))
		}
	})
	withCred(credJSON(3600_000, "team"))
	snap, err := Provider{}.FetchQuota(context.Background(), req())
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		label string
		used  float64
		limit float64
		unit  string
	}
	want := []row{
		{"Session (5hr)", 2, 100, "%"},
		{"Weekly (7 day)", 17, 100, "%"},
		{"Weekly Sonnet", 0, 0, "n/a"},                // known, null
		{"Weekly Opus", 0, 0, "n/a"},                  // known, null: never shown by the panel
		{"Weekly (7 day) cowork", 0, 0, "n/a"},        // unknown field, null utilization
		{"Weekly (7 day) oauth apps", 12.5, 100, "%"}, // unknown field with a value
		{"Weekly Fable", 0, 100, "%"},                 // limits[] with a model
		{"Monthly", 40, 100, "%"},                     // limits[] without a model
		{"Weekly cowork", 61, 100, "%"},               // limits[] scoped to a surface
	}
	var got []row
	for _, w := range snap.Windows {
		got = append(got, row{w.Label, w.Used, w.Limit, w.Unit})
	}
	// unknown fields come sorted by name: cowork before oauth_apps.
	if len(got) != len(want) {
		t.Fatalf("windows:\n got %v\nwant %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d: got %v want %v", i, got[i], want[i])
		}
	}
	joined := strings.Join(snap.Warnings, "\n")
	for _, w := range []string{"Weekly Sonnet: not available", "Weekly Opus: not available", "Weekly (7 day) cowork: not available", "Monthly: severity warning"} {
		if !strings.Contains(joined, w) {
			t.Errorf("warnings lack %q:\n%s", w, joined)
		}
	}
	if strings.Contains(joined, "Weekly Fable: severity") {
		t.Errorf("a normal severity is not a warning:\n%s", joined)
	}
}

func TestOverlayViewReproducesThePanelExactly(t *testing.T) {
	serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/oauth/usage" {
			_, _ = w.Write([]byte(dynamicFixture))
		}
	})
	withCred(credJSON(3600_000, "team"))
	snap, err := Provider{}.FetchQuota(context.Background(), overlayReq())
	if err != nil {
		t.Fatal(err)
	}
	var labels []string
	for _, w := range snap.Windows {
		labels = append(labels, w.Label)
	}
	// The panel: Session, Weekly, (Sonnet is null: hidden), then model-scoped limits only.
	if got := strings.Join(labels, "|"); got != "Session (5hr)|Weekly (7 day)|Weekly Fable" {
		t.Errorf("overlay rows: %s", got)
	}
}

func TestTheSameWindowInTwoPlacesIsDrawnOnceAndTheValueWins(t *testing.T) {
	u, err := decodeUsage([]byte(`{
	 "seven_day_sonnet": null,
	 "five_hour": {"utilization": 3, "resets_at": null},
	 "limits": [
	  {"kind":"session","group":"session","percent":99},
	  {"kind":"weekly_scoped","group":"weekly","percent":8.5,"scope":{"model":{"display_name":"Sonnet"}}}
	 ]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(u.Windows) != 2 {
		t.Fatalf("%+v", u.Windows)
	}
	if u.Windows[0].Label != "Session (5hr)" || *u.Windows[0].Percent != 3 {
		t.Errorf("the top-level window stands: %+v", u.Windows[0])
	}
	if u.Windows[1].Label != "Weekly Sonnet" || u.Windows[1].Percent == nil || *u.Windows[1].Percent != 8.5 {
		t.Errorf("a null top-level window takes the limits[] value: %+v", u.Windows[1])
	}
}

func TestMalformedKnownWindowIsAnErrorButUnknownOnesAreSkipped(t *testing.T) {
	if _, err := decodeUsage([]byte(`{"five_hour":{"utilization":"x","resets_at":null}}`)); err == nil {
		t.Error("a malformed known window must be an error")
	}
	u, err := decodeUsage([]byte(`{"seven_day_new":{"utilization":"x","resets_at":null},"seven_day":{"utilization":1,"resets_at":null},"limits":[{"percent":"a"},{"kind":"session","percent":5}]}`))
	if err != nil || len(u.Windows) != 2 {
		t.Fatalf("%v %+v", err, u.Windows)
	}
}

func TestLabelsDerivedFromKeys(t *testing.T) {
	for k, want := range map[string]string{
		"seven_day_oauth_apps": "Weekly (7 day) oauth apps",
		"five_hour_burst":      "Session (5hr) burst",
		"seven_day":            "Weekly (7 day)",
		"monthly_credits":      "Monthly credits",
	} {
		if got := fieldLabel(k); got != want {
			t.Errorf("fieldLabel(%q) = %q, want %q", k, got, want)
		}
	}
}

func TestAtMostMaxWindows(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{`)
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&b, `"w%03d":{"utilization":1,"resets_at":null},`, i)
	}
	b.WriteString(`"x":1}`)
	u, err := decodeUsage([]byte(b.String()))
	if err != nil || len(u.Windows) != maxWindows {
		t.Fatalf("%v %d", err, len(u.Windows))
	}
}

func TestRawUsageIsTheBodyWithoutTheToken(t *testing.T) {
	serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/oauth/usage" {
			_, _ = w.Write([]byte(dynamicFixture))
		}
	})
	withCred(credJSON(3600_000, "team"))
	b, err := RawUsage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, `"seven_day_oauth_apps"`) || !strings.Contains(s, `"tangelo": null`) || strings.Contains(s, "FAKEFAKE") || strings.Contains(s, "REFRESH") {
		t.Errorf("raw usage:\n%s", s)
	}
}

// The panel's rows, in its order and with its labels (webview/index.js WDn).
func TestWindowsMatchThePanelRowsAndOrder(t *testing.T) {
	var gotAuth, gotBeta, gotUA, gotPath string
	serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/oauth/usage" {
			return // the plan-confirmation call: covered by its own tests
		}
		gotAuth, gotBeta, gotUA, gotPath = r.Header.Get("Authorization"), r.Header.Get("anthropic-beta"), r.Header.Get("User-Agent"), r.URL.Path
		_, _ = w.Write([]byte(oauthFixture))
	})
	withCred(credJSON(3600_000, "max"))
	snap, err := Provider{}.FetchQuota(context.Background(), overlayReq())
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer "+fakeToken || gotBeta != "oauth-2025-04-20" || !strings.HasPrefix(gotUA, "claude-code/") || gotPath != "/api/oauth/usage" {
		t.Errorf("request: %q %q %q %q", gotAuth, gotBeta, gotUA, gotPath)
	}
	if snap.PlanKind != "max" {
		t.Errorf("plan %q", snap.PlanKind)
	}
	want := []struct {
		label string
		used  float64
	}{{"Session (5hr)", 37.9}, {"Weekly (7 day)", 52}, {"Weekly Sonnet", 8.5}, {"Weekly Fable", 61.2}}
	if len(snap.Windows) != len(want) {
		t.Fatalf("windows %v", snap.Windows)
	}
	for i, w := range want {
		g := snap.Windows[i]
		if g.Label != w.label || g.Used != w.used || g.Limit != 100 || g.ResetsAtUnix == 0 {
			t.Errorf("row %d: %v, want %s %.1f", i, g, w.label, w.used)
		}
	}
	if snap.Windows[0].ResetsAtUnix != time.Date(2026, 11, 9, 13, 0, 0, 0, time.UTC).Unix() {
		t.Errorf("reset %d", snap.Windows[0].ResetsAtUnix)
	}
}

func TestWeeklySonnetRowOnlyForMaxTeamOrUnknown(t *testing.T) {
	serve(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(oauthFixture)) })
	withCred(credJSON(3600_000, "pro"))
	snap, err := Provider{}.FetchQuota(context.Background(), overlayReq())
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range snap.Windows {
		if w.Label == "Weekly Sonnet" {
			t.Error("pro plan must not show Weekly Sonnet")
		}
	}
}

// The panel hides a null window; the default view keeps it, as "n/a".
func TestNullWindowIsHiddenByTheOverlayAndKeptAsNotAvailableOtherwise(t *testing.T) {
	serve(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"five_hour":{"utilization":null,"resets_at":null},"seven_day":{"utilization":3,"resets_at":null}}`))
	})
	withCred(credJSON(3600_000, "max"))
	snap, err := Provider{}.FetchQuota(context.Background(), overlayReq())
	if err != nil || len(snap.Windows) != 1 || snap.Windows[0].Label != "Weekly (7 day)" || snap.Windows[0].ResetsAtUnix != 0 {
		t.Fatalf("%v %v", snap, err)
	}
	snap, err = Provider{}.FetchQuota(context.Background(), req())
	if err != nil || len(snap.Windows) != 2 || snap.Windows[0].Label != "Session (5hr)" || snap.Windows[0].Unit != unitNotAvailable || snap.Windows[0].Limit != 0 {
		t.Fatalf("%v %v", snap, err)
	}
}

func TestExpiredTokenIsReportedNotRefreshed(t *testing.T) {
	called := false
	serve(t, func(w http.ResponseWriter, r *http.Request) { called = true })
	withCred(credJSON(-1000, "max"))
	_, err := Provider{}.FetchQuota(context.Background(), req())
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "token expired, open Claude Code") {
		t.Fatalf("err %v", err)
	}
	if called {
		t.Error("an expired token must not be sent anywhere (and never refreshed)")
	}
}

func TestRejectedTokenAndErrorsNeverCarryTheToken(t *testing.T) {
	for _, code := range []int{401, 403, 429, 500} {
		serve(t, func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "echo "+r.Header.Get("Authorization"), code)
		})
		withCred(credJSON(3600_000, "max"))
		_, err := Provider{}.FetchQuota(context.Background(), req())
		if err == nil {
			t.Fatalf("%d: no error", code)
		}
		if strings.Contains(err.Error(), "FAKEFAKE") {
			t.Errorf("%d: token leaked: %v", code, err)
		}
	}
}

func TestTokenRedactedFromTransportErrors(t *testing.T) {
	apiBase, allowAnyHost = "https://127.0.0.1:1", true
	defer func() { apiBase, allowAnyHost = "https://"+claudeCodeHost, false }()
	withCred(credJSON(3600_000, "max"))
	_, err := Provider{}.FetchQuota(context.Background(), req())
	if err == nil || strings.Contains(err.Error(), "FAKEFAKE") {
		t.Fatalf("err %v", err)
	}
}

func TestRedirectIsRefused(t *testing.T) {
	var hit bool
	serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			hit = true
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	})
	withCred(credJSON(3600_000, "max"))
	if _, err := (Provider{}).FetchQuota(context.Background(), req()); err == nil || hit {
		t.Fatalf("redirect followed (hit %v) or no error (%v)", hit, err)
	}
}

func TestOversizedResponseIsRefused(t *testing.T) {
	serve(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"x":"` + strings.Repeat("a", maxUsageBody+10) + `"}`))
	})
	withCred(credJSON(3600_000, "max"))
	_, err := Provider{}.FetchQuota(context.Background(), req())
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("err %v", err)
	}
}

func TestOnlyTheDocumentedHostReceivesTheToken(t *testing.T) {
	old := apiBase
	defer func() { apiBase = old }()
	withCred(credJSON(3600_000, "max"))
	for _, base := range []string{"https://evil.example", "http://api.anthropic.com"} {
		apiBase = base
		if _, err := (Provider{}).FetchQuota(context.Background(), req()); err == nil {
			t.Errorf("%s accepted", base)
		}
	}
}

func TestMissingLoginIsNotFound(t *testing.T) {
	old := readCredential
	defer func() { readCredential = old }()
	readCredential = func(context.Context) ([]byte, error) { return nil, errNoClaudeCode() }
	if _, err := (Provider{}).FetchQuota(context.Background(), req()); status.Code(err) != codes.NotFound {
		t.Fatalf("err %v", err)
	}
	withCred([]byte(`{"mcpOAuth":{}}`))
	if _, err := (Provider{}).FetchQuota(context.Background(), req()); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err %v", err)
	}
}

func TestServiceNameFollowsClaudeConfigDir(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	if claudeCodeService() != "Claude Code-credentials" {
		t.Error(claudeCodeService())
	}
	t.Setenv("CLAUDE_CONFIG_DIR", "/x/y")
	if s := claudeCodeService(); !strings.HasPrefix(s, "Claude Code-credentials-") || len(s) != len("Claude Code-credentials-")+8 {
		t.Error(s)
	}
}

func FuzzDecodeUsage(f *testing.F) {
	f.Add([]byte(oauthFixture))
	f.Add([]byte(`{"five_hour":{"utilization":"x"}}`))
	f.Add([]byte(`{"limits":[{"percent":"a"}]}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(``))
	f.Add([]byte(dynamicFixture))
	f.Add([]byte(`{"seven_day_x":{"utilization":null,"resets_at":null},"limits":[{"kind":"k","scope":{"model":null,"surface":{"a":1}}},{"kind":"k","scope":null,"percent":null}]}`))
	f.Add([]byte(`{"limits":{"kind":"x"},"five_hour":[],"seven_day":{"utilization":1e999}}`))
	f.Add([]byte(`{"a":{"utilization":null,"resets_at":null},"a":{"utilization":1,"resets_at":"x"}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		u, err := decodeUsage(b)
		if err != nil {
			return
		}
		if len(u.Windows) > maxWindows {
			t.Fatalf("%d windows", len(u.Windows))
		}
		keys := map[string]bool{}
		for _, w := range u.Windows {
			if keys[w.Key] {
				t.Fatalf("window key %q drawn twice", w.Key)
			}
			keys[w.Key] = true
			if w.Label == "" {
				t.Fatalf("window without a label: %+v", w)
			}
		}
		_ = overlayWindows(u, "max")
		_ = overlayWindows(u, "pro")
		_ = allWindows(u)
		_ = windowNotes(u)
	})
}

func FuzzDecodeCredential(f *testing.F) {
	f.Add(credJSON(1000, "max"))
	f.Add([]byte(`{"claudeAiOauth":{"accessToken":"","expiresAt":-1}}`))
	f.Add([]byte(`{"claudeAiOauth":null}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, b []byte) {
		l, err := decodeCredential(b)
		if err != nil {
			return
		}
		if s := fmt.Sprintf("%v %+v", l.token, l); strings.Contains(s, "sk-ant") {
			t.Errorf("secret printed: %s", s)
		}
	})
}

func credWithPlan(plan, source string, verifiedMs int64) []byte {
	exp := time.Now().UnixMilli() + 3600_000
	extra := ""
	if source != "" {
		extra += fmt.Sprintf(`,"subscriptionTypeSource":%q`, source)
	}
	if verifiedMs > 0 {
		extra += fmt.Sprintf(`,"subscriptionTypeVerifiedAt":%d`, verifiedMs)
	}
	return []byte(fmt.Sprintf(`{"claudeAiOauth":{"accessToken":%q,"expiresAt":%d,"scopes":["user:profile"],"subscriptionType":%q%s}}`, fakeToken, exp, plan, extra))
}

func profileServer(t *testing.T, profileStatus int, profileBody string) *int {
	t.Helper()
	calls := new(int)
	serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/oauth/profile" {
			*calls++
			if r.Header.Get("Authorization") != "Bearer "+fakeToken || r.Header.Get("Cache-Control") != "no-cache" {
				t.Errorf("profile request headers: %v", r.Header)
			}
			w.WriteHeader(profileStatus)
			_, _ = w.Write([]byte(profileBody))
			return
		}
		_, _ = w.Write([]byte(oauthFixture))
	})
	return calls
}

func warnings(t *testing.T) []string {
	t.Helper()
	// The overlay view: the window notes of the default view are not what these
	// tests are about, the plan note is.
	snap, err := (Provider{}).FetchQuota(context.Background(), overlayReq())
	if err != nil {
		t.Fatal(err)
	}
	return snap.Warnings
}

// A plan change: the stored login still says team, the profile says max.
func TestStalePlanIsSaidNotAsserted(t *testing.T) {
	calls := profileServer(t, 200, `{"organization":{"organization_type":"claude_max","rate_limit_tier":"x"}}`)
	withCred(credWithPlan("team", "sign_in", 0))
	ws := warnings(t)
	if *calls != 1 || len(ws) != 1 {
		t.Fatalf("calls %d warnings %v", *calls, ws)
	}
	for _, want := range []string{"plan mismatch", `"team"`, "sign_in", "never re-verified", `"max"`, "has not refreshed"} {
		if !strings.Contains(ws[0], want) {
			t.Errorf("warning lacks %q: %s", want, ws[0])
		}
	}
	snap, _ := (Provider{}).FetchQuota(context.Background(), req())
	if snap.PlanKind != "team" {
		t.Errorf("PlanKind %q: must stay the stored value the panel shows", snap.PlanKind)
	}
}

func TestVerifiedTimeIsShown(t *testing.T) {
	profileServer(t, 200, `{"organization":{"organization_type":"claude_pro"}}`)
	withCred(credWithPlan("max", "profile", time.Date(2026, 11, 8, 9, 30, 0, 0, time.UTC).UnixMilli()))
	ws := warnings(t)
	if len(ws) != 1 || !strings.Contains(ws[0], "last verified 2026-11-08") || !strings.Contains(ws[0], "profile") {
		t.Fatalf("%v", ws)
	}
}

func TestAgreeingPlanHasNoNote(t *testing.T) {
	profileServer(t, 200, `{"organization":{"organization_type":"claude_team"}}`)
	withCred(credWithPlan("team", "profile", 1))
	if ws := warnings(t); len(ws) != 0 {
		t.Fatalf("%v", ws)
	}
}

func TestUnreadableProfileIsSaidAndWindowsStillServed(t *testing.T) {
	profileServer(t, 500, `boom`)
	withCred(credWithPlan("team", "", 0))
	snap, err := (Provider{}).FetchQuota(context.Background(), overlayReq())
	if err != nil || len(snap.Windows) == 0 {
		t.Fatalf("%v %v", snap, err)
	}
	if len(snap.Warnings) != 1 || !strings.Contains(snap.Warnings[0], "could not be read to confirm") || !strings.Contains(snap.Warnings[0], "unrecorded source") {
		t.Fatalf("%v", snap.Warnings)
	}
}

func TestUnknownProfileTypeMakesNoClaim(t *testing.T) {
	profileServer(t, 200, `{"organization":{"organization_type":"something_new"}}`)
	withCred(credWithPlan("team", "sign_in", 0))
	if ws := warnings(t); len(ws) != 0 {
		t.Fatalf("%v", ws)
	}
}

func TestProfileNeverCalledWithAnExpiredToken(t *testing.T) {
	calls := profileServer(t, 200, `{}`)
	withCred(credJSON(-1000, "team"))
	_, _ = (Provider{}).FetchQuota(context.Background(), req())
	if *calls != 0 {
		t.Error("profile read with an expired token")
	}
}

func FuzzDecodeProfilePlan(f *testing.F) {
	f.Add([]byte(`{"organization":{"organization_type":"claude_max"}}`))
	f.Add([]byte(`{"organization":null}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, b []byte) { _ = decodeProfilePlan(b) })
}
