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

func req() *quotapb.FetchQuotaRequest {
	return &quotapb.FetchQuotaRequest{AccountLabel: "Claude Code", Credential: map[string]string{sourceKey: sourceClaudeCode}}
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
	snap, err := Provider{}.FetchQuota(context.Background(), req())
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
	snap, err := Provider{}.FetchQuota(context.Background(), req())
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range snap.Windows {
		if w.Label == "Weekly Sonnet" {
			t.Error("pro plan must not show Weekly Sonnet")
		}
	}
}

func TestNullWindowIsNotShown(t *testing.T) {
	serve(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"five_hour":{"utilization":null,"resets_at":null},"seven_day":{"utilization":3,"resets_at":null}}`))
	})
	withCred(credJSON(3600_000, "max"))
	snap, err := Provider{}.FetchQuota(context.Background(), req())
	if err != nil || len(snap.Windows) != 1 || snap.Windows[0].Label != "Weekly (7 day)" || snap.Windows[0].ResetsAtUnix != 0 {
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
	f.Fuzz(func(t *testing.T, b []byte) {
		u, err := decodeUsage(b)
		if err == nil {
			_ = overlayWindows(u, "max")
			_ = overlayWindows(u, "pro")
		}
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
	snap, err := (Provider{}).FetchQuota(context.Background(), req())
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
	snap, err := (Provider{}).FetchQuota(context.Background(), req())
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
