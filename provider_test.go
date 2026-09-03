// Copyright (c) the go-aiquota authors.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-aiquota/proto/quotapb"
)

// useTestClient points baseURL and newHTTPClient at srv for the life of the
// test: a plain client against a plain httptest.Server, since browserhttp's
// Chrome-fingerprinted TLS dialer is irrelevant (and slower to build) here
// — that machinery is what production talks to the real claude.ai with,
// not something this provider's own logic needs proven again per test.
func useTestClient(t *testing.T, srv *httptest.Server) {
	t.Helper()
	prevBase, prevClient := baseURL, newHTTPClient
	baseURL = srv.URL
	newHTTPClient = func() *http.Client { return &http.Client{} }
	t.Cleanup(func() { baseURL, newHTTPClient = prevBase, prevClient })
}

func TestDescribe(t *testing.T) {
	info, err := Provider{}.Describe(context.Background(), &quotapb.DescribeRequest{})
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	if info.Name != "claude" {
		t.Errorf("Name = %q, want %q", info.Name, "claude")
	}
	if info.LoginUrl != "https://claude.ai/login" {
		t.Errorf("LoginUrl = %q, want the real claude.ai login page", info.LoginUrl)
	}
	if info.CookieDomain != "claude.ai" {
		t.Errorf("CookieDomain = %q, want %q", info.CookieDomain, "claude.ai")
	}
}

func TestFetchQuotaMissingOrgUUID(t *testing.T) {
	_, err := Provider{}.FetchQuota(context.Background(), &quotapb.FetchQuotaRequest{
		AccountLabel: "acct-1",
		Credential:   map[string]string{"session": "abc"},
	})
	if err == nil || !strings.Contains(err.Error(), "org_uuid") {
		t.Fatalf("err = %v, want a clear error naming org_uuid", err)
	}
}

// usageFixture is a synthetic response shaped like the real one this
// provider was built against — three limits, one with a null resets_at, no
// real account data anywhere in it.
const usageFixture = `{
  "limits": [
    {"kind": "session", "group": "session", "percent": 46, "severity": "normal", "resets_at": "2026-09-03T19:30:00.000000+00:00", "is_active": true},
    {"kind": "weekly_all", "group": "weekly", "percent": 10, "severity": "normal", "resets_at": "2026-09-05T19:00:00.000000+00:00", "is_active": false},
    {"kind": "weekly_scoped", "group": "weekly", "percent": 0, "severity": "normal", "resets_at": null, "is_active": false}
  ]
}`

func TestFetchQuotaSuccess(t *testing.T) {
	var gotPath, gotCookie, gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAccept = r.Header.Get("Accept")
		for _, c := range r.Cookies() {
			gotCookie += c.Name + "=" + c.Value + ";"
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(usageFixture))
	}))
	defer srv.Close()
	useTestClient(t, srv)

	snap, err := Provider{}.FetchQuota(context.Background(), &quotapb.FetchQuotaRequest{
		AccountLabel: "work@example.com",
		Credential:   map[string]string{"org_uuid": "org-123", "session": "tok-abc"},
	})
	if err != nil {
		t.Fatalf("FetchQuota: %v", err)
	}

	if want := "/api/organizations/org-123/usage"; gotPath != want {
		t.Errorf("request path = %q, want %q", gotPath, want)
	}
	if gotAccept != "application/json" {
		t.Errorf("Accept header = %q, want application/json", gotAccept)
	}
	if !strings.Contains(gotCookie, "session=tok-abc") {
		t.Errorf("cookies sent = %q, want it to include session=tok-abc", gotCookie)
	}
	if strings.Contains(gotCookie, "org_uuid=") {
		t.Errorf("cookies sent = %q, want org_uuid NOT sent as a cookie", gotCookie)
	}

	if snap.AccountLabel != "work@example.com" {
		t.Errorf("AccountLabel = %q, want it echoed back", snap.AccountLabel)
	}
	if snap.FetchedAtUnix == 0 {
		t.Error("FetchedAtUnix was not set")
	}
	if len(snap.Windows) != 3 {
		t.Fatalf("len(Windows) = %d, want 3", len(snap.Windows))
	}
	w0 := snap.Windows[0]
	if w0.Label != "session" || w0.Used != 46 || w0.Limit != 100 || w0.Unit != "%" {
		t.Errorf("Windows[0] = %+v, want session/46/100/%%", w0)
	}
	if w0.ResetsAtUnix == 0 {
		t.Error("Windows[0].ResetsAtUnix was not parsed")
	}
	w2 := snap.Windows[2]
	if w2.Label != "weekly_scoped" || w2.ResetsAtUnix != 0 {
		t.Errorf("Windows[2] = %+v, want weekly_scoped with ResetsAtUnix=0 (null resets_at)", w2)
	}
}

func TestFetchQuotaUnauthorized(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
		}))
		useTestClient(t, srv)

		_, err := Provider{}.FetchQuota(context.Background(), &quotapb.FetchQuotaRequest{
			AccountLabel: "a", Credential: map[string]string{"org_uuid": "o", "session": "s"},
		})
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), "session has likely expired") {
			t.Fatalf("status %d: err = %v, want an expired-session message", status, err)
		}
	}
}

func TestFetchQuotaChallengePage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><title>Just a moment...</title></html>"))
	}))
	defer srv.Close()
	useTestClient(t, srv)

	_, err := Provider{}.FetchQuota(context.Background(), &quotapb.FetchQuotaRequest{
		AccountLabel: "a", Credential: map[string]string{"org_uuid": "o", "session": "s"},
	})
	if err == nil || !strings.Contains(err.Error(), "bot-challenge") {
		t.Fatalf("err = %v, want a bot-challenge-specific message", err)
	}
}

func TestFetchQuotaMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()
	useTestClient(t, srv)

	_, err := Provider{}.FetchQuota(context.Background(), &quotapb.FetchQuotaRequest{
		AccountLabel: "a", Credential: map[string]string{"org_uuid": "o", "session": "s"},
	})
	if err == nil || !strings.Contains(err.Error(), "parsing usage response") {
		t.Fatalf("err = %v, want a parse-failure message", err)
	}
}

func TestFetchQuotaOtherErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()
	useTestClient(t, srv)

	_, err := Provider{}.FetchQuota(context.Background(), &quotapb.FetchQuotaRequest{
		AccountLabel: "a", Credential: map[string]string{"org_uuid": "o", "session": "s"},
	})
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("err = %v, want the status code surfaced", err)
	}
}

func TestFetchQuotaNoLimits(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"limits":[]}`))
	}))
	defer srv.Close()
	useTestClient(t, srv)

	snap, err := Provider{}.FetchQuota(context.Background(), &quotapb.FetchQuotaRequest{
		AccountLabel: "a", Credential: map[string]string{"org_uuid": "o", "session": "s"},
	})
	if err != nil {
		t.Fatalf("FetchQuota: %v", err)
	}
	if len(snap.Windows) != 0 {
		t.Errorf("Windows = %v, want empty for an empty limits[]", snap.Windows)
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate([]byte("short"), 10); got != "short" {
		t.Errorf("truncate(short) = %q, want unchanged", got)
	}
	if got := truncate([]byte("a very long string indeed"), 5); got != "a ver…" {
		t.Errorf("truncate(long, 5) = %q, want %q", got, "a ver…")
	}
}
