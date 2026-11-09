// Copyright (c) the go-aiquota authors.
// SPDX-License-Identifier: BSD-3-Clause

package main

// The "Claude Code" credential source: the quota of the account Claude Code
// (CLI and VS Code extension) is signed in with, read exactly as Claude Code's
// own "Account & usage" panel reads it.
//
// Every fact below was read in the installed extension (anthropic.claude-code
// 2.1.319, resources/native-binary/claude, extension.js, webview/index.js) and
// in https://code.claude.com/docs/en/authentication.md ("Credential
// management"):
//
//   - Storage. macOS: login-keychain generic password, service
//     "Claude Code-credentials" (+ "-<sha256(configDir)[:8]>" when
//     CLAUDE_CONFIG_DIR is set), account = $USER; the extension reads it with
//     `security find-generic-password -a USER -w -s SERVICE` (extension.js,
//     functions yc/bc/vwe). Elsewhere, and on macOS when the Keychain refuses
//     the write: $CLAUDE_CONFIG_DIR or ~/.claude /.credentials.json, mode 0600.
//     Value: JSON {"claudeAiOauth":{accessToken, refreshToken, expiresAt (ms),
//     scopes, subscriptionType, ...}}.
//   - Request. GET https://api.anthropic.com/api/oauth/usage with
//     "Authorization: Bearer <accessToken>", "anthropic-beta: oauth-2025-04-20",
//     "User-Agent: claude-code/<version>" (extension.js BASE_API_URL, cg;
//     the binary's fetchUtilization and ne()).
//   - Response (binary, schema Ft): five_hour, seven_day, seven_day_opus,
//     seven_day_sonnet, ... each {utilization: percent|null, resets_at: ISO
//     string|null}, plus limits[] ({kind, group, percent, resets_at, severity,
//     is_active, scope:{model:{display_name}}}).
//   - Panel rows (webview/index.js, function WDn): "Session (5hr)",
//     "Weekly (7 day)", "Weekly Sonnet" (plans max/team/unknown), then
//     "Weekly <display_name>" per model-scoped limit; a row whose utilization
//     is null is not shown. The percentage shown is floor(utilization).
//
// What this file must NOT do: refresh or rotate the token. Claude Code
// refreshes its own login (refreshOAuthToken, and refreshOAuth on a 401); a
// second holder of the refresh token that rotates it would sign Claude Code
// out. An expired or rejected access token is therefore reported, never
// renewed: "token expired, open Claude Code".
//
// The token is read at fetch time, held in a secret.Secret, sent in one
// header, and never written to disk, environment or argv.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/go-aiquota/proto/quotapb"
	"github.com/go-aiquota/proto/redact"
	"github.com/go-aiquota/proto/secret"
)

const (
	// sourceKey / sourceClaudeCode select this credential source in
	// FetchQuotaRequest.Credential. Neither is secret.
	sourceKey        = "source"
	sourceClaudeCode = "claude-code"
	// viewKey selects which windows the Claude Code source returns: every
	// window the endpoint reports (the default), or exactly the panel's rows
	// (viewOverlay), for the equality check against the extension.
	viewKey     = "view"
	viewOverlay = "overlay"

	claudeCodeHost = "api.anthropic.com"
	usagePath      = "/api/oauth/usage"
	oauthBeta      = "oauth-2025-04-20"
	claudeCodeUA   = "claude-code/2.1.319"

	keychainService = "Claude Code-credentials"
	maxUsageBody    = 1 << 20
	maxCredential   = 1 << 20
	// errSecItemNotFound exit status of `security find-generic-password`.
	securityNotFound = 44
)

// apiBase is the only host a Claude Code token may be sent to. A var so a test
// can aim at an httptest TLS server; allowAnyHost is set only by tests.
var (
	apiBase      = "https://" + claudeCodeHost
	allowAnyHost = false
)

// claudeCodeClient builds the HTTP client: TLS 1.2+, the system trust store,
// and NO redirects (a redirect would carry the bearer token to another URL).
var claudeCodeClient = func() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{
		Transport:     tr,
		Timeout:       requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// readCredential returns the raw credential JSON; replaceable by tests.
var readCredential = readClaudeCodeCredential

var accountNameRe = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// claudeCodeService mirrors extension.js yc(): the keychain service name.
func claudeCodeService() string {
	dir := os.Getenv("CLAUDE_CONFIG_DIR")
	if dir == "" {
		return keychainService
	}
	sum := sha256.Sum256([]byte(dir))
	return keychainService + "-" + hex.EncodeToString(sum[:])[:8]
}

// claudeCodeAccount mirrors extension.js bc().
func claudeCodeAccount() string {
	name := os.Getenv("USER")
	if name == "" {
		if u, err := user.Current(); err == nil {
			name = u.Username
		}
	}
	if !accountNameRe.MatchString(name) {
		return "claude-code-user"
	}
	return name
}

func claudeConfigDir() (string, error) {
	if d := os.Getenv("CLAUDE_CONFIG_DIR"); d != "" {
		return d, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".claude"), nil
}

func errNoClaudeCode() error {
	return status.Error(codes.NotFound, "no Claude Code login found (sign in with Claude Code first)")
}

// readClaudeCodeCredential reads the credential from the macOS Keychain
// through /usr/bin/security (the same program Claude Code uses, which the
// item's ACL trusts without a prompt) and falls back to the credentials file.
func readClaudeCodeCredential(ctx context.Context) ([]byte, error) {
	if runtime.GOOS == "darwin" {
		cmd := exec.CommandContext(ctx, "/usr/bin/security", "find-generic-password", "-a", claudeCodeAccount(), "-w", "-s", claudeCodeService())
		var out bytes.Buffer
		cmd.Stdout = &out // the secret travels on a pipe, never argv or env
		if err := cmd.Run(); err == nil {
			if b := bytes.TrimSpace(out.Bytes()); len(b) > 0 {
				return b, nil
			}
		} else {
			var ee *exec.ExitError
			if errors.As(err, &ee) && ee.ExitCode() != securityNotFound {
				return nil, status.Errorf(codes.Unavailable, "reading the Claude Code keychain item failed (exit %d)", ee.ExitCode())
			}
			if ctx.Err() != nil {
				return nil, status.Error(codes.DeadlineExceeded, "reading the Claude Code keychain item timed out")
			}
		}
	}
	dir, err := claudeConfigDir()
	if err != nil {
		return nil, errNoClaudeCode()
	}
	f, err := os.Open(filepath.Join(dir, ".credentials.json"))
	if err != nil {
		return nil, errNoClaudeCode()
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxCredential+1))
	if err != nil || len(b) > maxCredential {
		return nil, status.Error(codes.DataLoss, "the Claude Code credentials file is unreadable or oversized")
	}
	return bytes.TrimSpace(b), nil
}

// claudeCodeLogin is what the credential JSON yields. The token is wrapped at
// once; nothing else here is secret.
type claudeCodeLogin struct {
	token     secret.Secret
	expiresAt time.Time // zero: unknown
	plan      string
	scopes    []string
	// planSource / planVerifiedAt are Claude Code's own bookkeeping of where
	// the stored plan came from ("sign_in" or "profile") and when it last
	// checked it against the profile (binary: IL, DL).
	planSource     string
	planVerifiedAt time.Time // zero: never
}

// Format masks the whole struct for every verb: fmt reaches an UNEXPORTED
// secret.Secret field by reflection without calling its Format, so %+v of the
// login would otherwise print the token (found by FuzzDecodeCredential).
func (l claudeCodeLogin) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("claudeCodeLogin{" + secret.Mask + "}"))
}

// decodeCredential parses the credential JSON ({"claudeAiOauth":{...}}).
func decodeCredential(raw []byte) (claudeCodeLogin, error) {
	var top struct {
		OAuth *struct {
			AccessToken      string   `json:"accessToken"`
			ExpiresAt        *float64 `json:"expiresAt"`
			Scopes           []string `json:"scopes"`
			SubscriptionType *string  `json:"subscriptionType"`
			PlanSource       *string  `json:"subscriptionTypeSource"`
			PlanVerifiedAt   *float64 `json:"subscriptionTypeVerifiedAt"`
		} `json:"claudeAiOauth"`
	}
	if err := json.Unmarshal(raw, &top); err != nil {
		return claudeCodeLogin{}, status.Error(codes.DataLoss, "the Claude Code credential is not valid JSON")
	}
	if top.OAuth == nil || top.OAuth.AccessToken == "" {
		return claudeCodeLogin{}, status.Error(codes.FailedPrecondition, "Claude Code is not signed in with a claude.ai account (no OAuth login stored)")
	}
	l := claudeCodeLogin{token: secret.New(top.OAuth.AccessToken), scopes: top.OAuth.Scopes}
	if top.OAuth.ExpiresAt != nil && *top.OAuth.ExpiresAt > 0 {
		l.expiresAt = time.UnixMilli(int64(*top.OAuth.ExpiresAt))
	}
	if top.OAuth.SubscriptionType != nil {
		l.plan = *top.OAuth.SubscriptionType
	}
	if top.OAuth.PlanSource != nil {
		l.planSource = *top.OAuth.PlanSource
	}
	if top.OAuth.PlanVerifiedAt != nil && *top.OAuth.PlanVerifiedAt > 0 {
		l.planVerifiedAt = time.UnixMilli(int64(*top.OAuth.PlanVerifiedAt))
	}
	return l, nil
}

// oauthWindow is one {utilization, resets_at} window of /api/oauth/usage.
type oauthWindow struct {
	Utilization *float64 `json:"utilization"`
	ResetsAt    *string  `json:"resets_at"`
}

// oauthLimit is one limits[] entry. Percent and every scope field may be null.
type oauthLimit struct {
	Kind     string   `json:"kind"`
	Group    string   `json:"group"`
	Percent  *float64 `json:"percent"`
	Severity string   `json:"severity"`
	ResetsAt *string  `json:"resets_at"`
	IsActive bool     `json:"is_active"`
	Scope    *struct {
		Model *struct {
			DisplayName string `json:"display_name"`
		} `json:"model"`
		Surface json.RawMessage `json:"surface"`
	} `json:"scope"`
}

// maxWindows bounds what one response may make of itself.
const maxWindows = 64

// usageWindow is one window the endpoint returned, whatever its name.
type usageWindow struct {
	// Key identifies the window across the two places the endpoint reports it
	// (a top-level field and a limits[] entry), so the pair is drawn once. It
	// is explicit, never derived from the label: "session" and "weekly_all"
	// for the two standard windows, "weekly_scoped/<model>" for a model, the
	// limit's own kind otherwise, "top/<field>" for an unknown field.
	Key      string
	Label    string
	Percent  *float64 // nil: the endpoint reports no value
	ResetsAt int64    // unix seconds, 0 unknown
	Severity string   // limits[] only
	Source   string   // the top-level field name, or "limits[]"
	Model    string   // model display name of a model-scoped limit
	FromList bool     // came from limits[]
}

type oauthUsage struct {
	Windows []usageWindow
}

// The panel's labels and keys for the top-level fields it knows, in its order.
var knownTop = []struct{ field, key, label string }{
	{"five_hour", "session", "Session (5hr)"},
	{"seven_day", "weekly_all", "Weekly (7 day)"},
	{"seven_day_sonnet", "weekly_scoped/sonnet", "Weekly Sonnet"},
	{"seven_day_opus", "weekly_scoped/opus", "Weekly Opus"},
}

// fieldLabel derives a label for a top-level field the panel has no row for:
// seven_day_oauth_apps -> "Weekly (7 day) oauth apps".
func fieldLabel(field string) string {
	words := strings.Split(field, "_")
	switch {
	case len(words) >= 2 && words[0] == "five" && words[1] == "hour":
		return joinLabel("Session (5hr)", words[2:])
	case len(words) >= 2 && words[0] == "seven" && words[1] == "day":
		return joinLabel("Weekly (7 day)", words[2:])
	}
	s := strings.Join(words, " ")
	if strings.TrimSpace(s) == "" {
		return "(unnamed window)"
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func joinLabel(base string, rest []string) string {
	if len(rest) == 0 {
		return base
	}
	return base + " " + strings.Join(rest, " ")
}

// limitLabel and limitKey describe a limits[] entry from its kind, group and
// scope. The key is the same as the top-level window's when it is the same
// window, so the pair is drawn once.
func limitKey(l oauthLimit) string {
	if l.Scope != nil {
		if l.Scope.Model != nil && l.Scope.Model.DisplayName != "" {
			return l.Kind + "/" + strings.ToLower(l.Scope.Model.DisplayName)
		}
		if s := surfaceName(l.Scope.Surface); s != "" {
			return l.Kind + "/surface:" + strings.ToLower(s)
		}
	}
	return l.Kind
}

func surfaceName(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return strings.Trim(string(raw), `"`)
}

func limitLabel(l oauthLimit) string {
	scope := ""
	if l.Scope != nil {
		if l.Scope.Model != nil && l.Scope.Model.DisplayName != "" {
			scope = l.Scope.Model.DisplayName
		} else if s := surfaceName(l.Scope.Surface); s != "" {
			scope = s
		}
	}
	var base string
	switch {
	case l.Group == "session" || l.Kind == "session":
		base = "Session (5hr)"
	case l.Group == "weekly" || strings.HasPrefix(l.Kind, "weekly"):
		base = "Weekly"
		if scope == "" {
			base = "Weekly (7 day)"
		}
	default:
		g := l.Group
		if g == "" {
			g = l.Kind
		}
		base = fieldLabel(g)
	}
	if scope != "" {
		return base + " " + scope
	}
	return base
}

// shaped reports whether raw is an object carrying both utilization and
// resets_at: the shape of a window.
func shaped(raw json.RawMessage) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	_, a := m["utilization"]
	_, b := m["resets_at"]
	return a && b
}

// decodeUsage parses a /api/oauth/usage body into every window it carries,
// whatever their names: each top-level value shaped {utilization, resets_at},
// then each limits[] entry the top level did not already report. Unknown
// fields of any other shape are ignored. A known window that is malformed is
// an error; an unknown or limits[] one that is malformed is skipped (the
// extension's schema does the same, with .catch). At most maxWindows.
func decodeUsage(body []byte) (oauthUsage, error) {
	if len(body) > maxUsageBody {
		return oauthUsage{}, errors.New("usage response too large")
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil || top == nil {
		return oauthUsage{}, errors.New("usage response is not the expected JSON object")
	}
	var u oauthUsage
	at := map[string]int{} // key -> index in u.Windows
	add := func(w usageWindow) {
		if i, dup := at[w.Key]; dup {
			// The same window reported twice: keep the first, unless it
			// carries no value and this one does.
			if u.Windows[i].Percent == nil && w.Percent != nil {
				u.Windows[i] = w
			}
			return
		}
		if len(u.Windows) < maxWindows {
			at[w.Key] = len(u.Windows)
			u.Windows = append(u.Windows, w)
		}
	}
	parse := func(raw json.RawMessage) (oauthWindow, bool) {
		var w oauthWindow
		return w, json.Unmarshal(raw, &w) == nil
	}
	known := map[string]bool{}
	for _, k := range knownTop {
		known[k.field] = true
		raw, ok := top[k.field]
		if !ok {
			continue
		}
		if string(raw) == "null" { // a known window the endpoint reports as null: not available
			add(usageWindow{Key: k.key, Label: k.label, Source: k.field})
			continue
		}
		w, ok := parse(raw)
		if !ok {
			return oauthUsage{}, errors.New("usage response has a malformed " + k.field + " window")
		}
		add(usageWindow{Key: k.key, Label: k.label, Percent: w.Utilization, ResetsAt: unixOf(w.ResetsAt), Source: k.field})
	}
	fields := make([]string, 0, len(top))
	for f := range top {
		if f != "limits" && !known[f] {
			fields = append(fields, f)
		}
	}
	sort.Strings(fields)
	for _, f := range fields {
		if !shaped(top[f]) {
			continue
		}
		if w, ok := parse(top[f]); ok {
			add(usageWindow{Key: "top/" + f, Label: fieldLabel(f), Percent: w.Utilization, ResetsAt: unixOf(w.ResetsAt), Source: f})
		}
	}
	if raw, ok := top["limits"]; ok {
		var ls []json.RawMessage
		if json.Unmarshal(raw, &ls) == nil {
			for _, lr := range ls {
				var l oauthLimit
				if json.Unmarshal(lr, &l) != nil || l.Kind == "" {
					continue
				}
				w := usageWindow{Key: limitKey(l), Label: limitLabel(l), Percent: l.Percent, ResetsAt: unixOf(l.ResetsAt), Severity: l.Severity, Source: "limits[]", FromList: true}
				if l.Scope != nil && l.Scope.Model != nil {
					w.Model = l.Scope.Model.DisplayName
				}
				add(w)
			}
		}
	}
	return u, nil
}

func unixOf(s *string) int64 {
	if s == nil {
		return 0
	}
	t, err := time.Parse(time.RFC3339, *s)
	if err != nil {
		return 0
	}
	return t.Unix()
}

// overlayWindows returns the windows in the order, with the labels, and with
// the omissions of the "Account & usage" panel (webview/index.js, WDn).
func overlayWindows(u oauthUsage, plan string) []*quotapb.QuotaWindow {
	var out []*quotapb.QuotaWindow
	add := func(w usageWindow) {
		if w.Percent == nil {
			return
		}
		out = append(out, &quotapb.QuotaWindow{Label: w.Label, Used: *w.Percent, Limit: 100, Unit: "%", ResetsAtUnix: w.ResetsAt})
	}
	byKey := map[string]usageWindow{}
	for _, w := range u.Windows {
		if !w.FromList {
			byKey[w.Key] = w
		}
	}
	add(byKey["session"])
	add(byKey["weekly_all"])
	if plan == "max" || plan == "team" || plan == "" {
		add(byKey["weekly_scoped/sonnet"])
	}
	for _, w := range u.Windows {
		if !w.FromList || w.Model == "" {
			continue
		}
		if n := strings.ToLower(w.Model); n == "sonnet" || n == "opus" {
			continue // already carried by seven_day_sonnet / seven_day_opus
		}
		add(usageWindow{Label: "Weekly " + w.Model, Percent: w.Percent, ResetsAt: w.ResetsAt})
	}
	return out
}

// allWindows returns every window the endpoint reported, known labels first
// in the panel's order, then the others; a window without a value is returned
// as "n/a" (Unit "n/a", no limit) rather than hidden. The reason is in
// notAvailableNote, which the snapshot's warnings carry.
func allWindows(u oauthUsage) []*quotapb.QuotaWindow {
	var out []*quotapb.QuotaWindow
	for _, w := range u.Windows {
		if w.Percent == nil {
			out = append(out, &quotapb.QuotaWindow{Label: w.Label, Unit: unitNotAvailable, ResetsAtUnix: w.ResetsAt})
			continue
		}
		out = append(out, &quotapb.QuotaWindow{Label: w.Label, Used: *w.Percent, Limit: 100, Unit: "%", ResetsAtUnix: w.ResetsAt})
	}
	return out
}

// unitNotAvailable marks a window the endpoint listed without a value.
const unitNotAvailable = "n/a"

// windowNotes are the snapshot warnings that explain what the windows cannot
// say by themselves: why a window has no value, and any severity the endpoint
// attached beyond "normal".
func windowNotes(u oauthUsage) []string {
	var notes []string
	for _, w := range u.Windows {
		if w.Percent == nil {
			notes = append(notes, fmt.Sprintf("%s: not available (%s reports no utilization for it, null: not part of this plan or account, or not measured)", w.Label, w.Source))
		}
		if s := w.Severity; s != "" && s != "normal" && s != "ok" {
			notes = append(notes, fmt.Sprintf("%s: severity %s", w.Label, s))
		}
	}
	return notes
}

func checkAPIBase() (*url.URL, error) {
	u, err := url.Parse(apiBase)
	if err != nil || u.Scheme != "https" {
		return nil, status.Error(codes.Internal, "usage endpoint is not an https URL")
	}
	if !allowAnyHost && u.Hostname() != claudeCodeHost {
		return nil, status.Error(codes.Internal, "refusing to send a Claude Code token to a host other than "+claudeCodeHost)
	}
	return u, nil
}

// usageFetch is what one authenticated GET of the usage endpoint yields: the
// body (which holds no credential), the login for the plan and scopes, and
// what the follow-up profile read needs.
type usageFetch struct {
	body  []byte
	login claudeCodeLogin
	base  *url.URL
	red   *redact.Redactor
}

// fetchUsageBody reads the credential and GETs the usage endpoint. Every
// error is redacted of the token.
func fetchUsageBody(ctx context.Context) (*usageFetch, error) {
	raw, err := readCredential(ctx)
	if err != nil {
		return nil, err
	}
	login, err := decodeCredential(raw)
	if err != nil {
		return nil, err
	}
	// Redact the token in every error that leaves this function.
	var tok string
	login.token.Reveal(func(v string) { tok = v })
	red := redact.New(tok)
	fail := func(c codes.Code, format string, a ...any) error {
		return status.Error(c, red.String(fmt.Sprintf(format, a...)))
	}

	if !login.expiresAt.IsZero() && !login.expiresAt.After(time.Now()) {
		return nil, fail(codes.FailedPrecondition, "token expired, open Claude Code (it renews its own login; this tool never refreshes it)")
	}
	base, err := checkAPIBase()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+usagePath, nil)
	if err != nil {
		return nil, fail(codes.Internal, "building the usage request: %v", err)
	}
	login.token.Reveal(func(v string) { req.Header.Set("Authorization", "Bearer "+v) })
	req.Header.Set("anthropic-beta", oauthBeta)
	req.Header.Set("User-Agent", claudeCodeUA)
	req.Header.Set("Content-Type", "application/json")

	resp, err := claudeCodeClient().Do(req)
	if err != nil {
		return nil, fail(codes.Unavailable, "usage request failed: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxUsageBody+1))
	if err != nil {
		return nil, fail(codes.Unavailable, "reading the usage response: %v", err)
	}
	if len(body) > maxUsageBody {
		return nil, fail(codes.ResourceExhausted, "usage response larger than %d bytes, refused", maxUsageBody)
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, fail(codes.FailedPrecondition, "token rejected (%d): open Claude Code so it renews its login", resp.StatusCode)
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, fail(codes.Unavailable, "the usage endpoint is rate limited (Retry-After %q)", resp.Header.Get("Retry-After"))
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return nil, fail(codes.Unavailable, "unexpected redirect (%d) refused", resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return nil, fail(codes.Unavailable, "usage request returned %d", resp.StatusCode)
	}
	return &usageFetch{body: body, login: login, base: base, red: red}, nil
}

// RawUsage is `plugin-claude --raw-usage`: the usage response as the endpoint
// returned it, indented, for a person to see everything Claude returns. The
// body holds no credential; the token is never part of the output.
func RawUsage(ctx context.Context) ([]byte, error) {
	f, err := fetchUsageBody(ctx)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, f.body, "", "  "); err != nil {
		return nil, errors.New("usage response is not JSON")
	}
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}

// fetchClaudeCode is FetchQuota for the Claude Code source.
func fetchClaudeCode(ctx context.Context, accountLabel string, overlay bool) (*quotapb.QuotaSnapshot, error) {
	f, err := fetchUsageBody(ctx)
	if err != nil {
		return nil, err
	}
	login, base, red := f.login, f.base, f.red
	usage, err := decodeUsage(f.body)
	if err != nil {
		return nil, status.Error(codes.DataLoss, red.String(err.Error()))
	}
	snap := &quotapb.QuotaSnapshot{
		AccountLabel:  accountLabel,
		PlanKind:      login.plan,
		FetchedAtUnix: time.Now().Unix(),
	}
	if overlay {
		snap.Windows = overlayWindows(usage, login.plan)
	} else {
		snap.Windows = allWindows(usage)
		snap.Warnings = append(snap.Warnings, windowNotes(usage)...)
	}
	if note := planNote(ctx, login, base, red); note != "" {
		snap.Warnings = append(snap.Warnings, note)
	}
	if len(login.scopes) > 0 && !contains(login.scopes, "user:profile") {
		snap.Warnings = append(snap.Warnings, "the Claude Code login lacks the user:profile scope; plan usage may be unavailable")
	}
	return snap, nil
}

// profilePlans maps organization.organization_type of GET /api/oauth/profile
// to the stored subscriptionType (binary: iEo, _Or).
var profilePlans = map[string]string{
	"claude_max":        "max",
	"claude_pro":        "pro",
	"claude_enterprise": "enterprise",
	"claude_team":       "team",
}

// decodeProfilePlan extracts the plan ("" if unknown) from a profile body.
func decodeProfilePlan(body []byte) string {
	var p struct {
		Organization struct {
			Type string `json:"organization_type"`
		} `json:"organization"`
	}
	if len(body) > maxUsageBody || json.Unmarshal(body, &p) != nil {
		return ""
	}
	return profilePlans[p.Organization.Type]
}

// planNote compares the plan Claude Code STORED with the account's live
// profile (the source Claude Code itself reconciles from, binary: Fon/DL) and
// returns a sentence when they differ or cannot be compared, "" when they
// agree. The panel's Plan row shows the stored value, which Claude Code only
// rewrites when it re-reads the profile or on a new sign-in (a token refresh
// carries it forward unchanged: extension.js doRefreshOAuthToken), so right
// after a plan change it can be stale. Nothing is cached.
func planNote(ctx context.Context, login claudeCodeLogin, base *url.URL, red *redact.Redactor) string {
	stored := login.plan
	if stored == "" {
		stored = "unknown"
	}
	since := "never re-verified against the profile"
	if !login.planVerifiedAt.IsZero() {
		since = "last verified " + login.planVerifiedAt.Local().Format("2006-01-02 15:04 MST")
	}
	src := login.planSource
	if src == "" {
		src = "unrecorded source"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+"/api/oauth/profile", nil)
	if err != nil {
		return ""
	}
	login.token.Reveal(func(v string) { req.Header.Set("Authorization", "Bearer "+v) })
	req.Header.Set("anthropic-beta", oauthBeta)
	req.Header.Set("User-Agent", claudeCodeUA)
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := claudeCodeClient().Do(req)
	if err != nil {
		return red.String(fmt.Sprintf("plan %q is the stored login's (%s, %s); the account profile could not be read to confirm it", stored, src, since))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxUsageBody+1))
	if err != nil || resp.StatusCode != http.StatusOK {
		return fmt.Sprintf("plan %q is the stored login's (%s, %s); the account profile could not be read to confirm it (HTTP %d)", stored, src, since, resp.StatusCode)
	}
	live := decodeProfilePlan(body)
	if live == "" || live == login.plan {
		return ""
	}
	return fmt.Sprintf("plan mismatch: Claude Code's stored login says %q (%s, %s) but the account profile says %q; Claude Code has not refreshed its stored plan (it does on its next profile check or a new sign-in)", stored, src, since, live)
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
