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
	return l, nil
}

// oauthWindow is one {utilization, resets_at} window of /api/oauth/usage.
type oauthWindow struct {
	Utilization *float64 `json:"utilization"`
	ResetsAt    *string  `json:"resets_at"`
}

type oauthLimit struct {
	Kind     string  `json:"kind"`
	Group    string  `json:"group"`
	Percent  float64 `json:"percent"`
	ResetsAt *string `json:"resets_at"`
	IsActive bool    `json:"is_active"`
	Scope    struct {
		Model *struct {
			DisplayName string `json:"display_name"`
		} `json:"model"`
	} `json:"scope"`
}

type oauthUsage struct {
	FiveHour       *oauthWindow
	SevenDay       *oauthWindow
	SevenDayOpus   *oauthWindow
	SevenDaySonnet *oauthWindow
	Limits         []oauthLimit
}

// decodeUsage parses a /api/oauth/usage body. Unknown fields are ignored; a
// malformed limits[] is dropped (the extension's schema does the same, with
// .catch) while a malformed window is an error.
func decodeUsage(body []byte) (oauthUsage, error) {
	if len(body) > maxUsageBody {
		return oauthUsage{}, errors.New("usage response too large")
	}
	var raw struct {
		FiveHour       *oauthWindow    `json:"five_hour"`
		SevenDay       *oauthWindow    `json:"seven_day"`
		SevenDayOpus   *oauthWindow    `json:"seven_day_opus"`
		SevenDaySonnet *oauthWindow    `json:"seven_day_sonnet"`
		Limits         json.RawMessage `json:"limits"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return oauthUsage{}, errors.New("usage response is not the expected JSON object")
	}
	u := oauthUsage{FiveHour: raw.FiveHour, SevenDay: raw.SevenDay, SevenDayOpus: raw.SevenDayOpus, SevenDaySonnet: raw.SevenDaySonnet}
	if len(raw.Limits) > 0 {
		var ls []oauthLimit
		if json.Unmarshal(raw.Limits, &ls) == nil {
			u.Limits = ls
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
	add := func(label string, w *oauthWindow) {
		if w == nil || w.Utilization == nil {
			return
		}
		out = append(out, &quotapb.QuotaWindow{Label: label, Used: *w.Utilization, Limit: 100, Unit: "%", ResetsAtUnix: unixOf(w.ResetsAt)})
	}
	add("Session (5hr)", u.FiveHour)
	add("Weekly (7 day)", u.SevenDay)
	if plan == "max" || plan == "team" || plan == "" {
		add("Weekly Sonnet", u.SevenDaySonnet)
	}
	for _, l := range u.Limits {
		if l.Scope.Model == nil || l.Scope.Model.DisplayName == "" {
			continue
		}
		name := l.Scope.Model.DisplayName
		if n := strings.ToLower(name); n == "sonnet" || n == "opus" {
			continue // already carried by seven_day_sonnet / seven_day_opus
		}
		out = append(out, &quotapb.QuotaWindow{Label: "Weekly " + name, Used: l.Percent, Limit: 100, Unit: "%", ResetsAtUnix: unixOf(l.ResetsAt)})
	}
	return out
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

// fetchClaudeCode is FetchQuota for the Claude Code source.
func fetchClaudeCode(ctx context.Context, accountLabel string) (*quotapb.QuotaSnapshot, error) {
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
	usage, err := decodeUsage(body)
	if err != nil {
		return nil, fail(codes.DataLoss, "%v", err)
	}
	snap := &quotapb.QuotaSnapshot{
		AccountLabel:  accountLabel,
		PlanKind:      login.plan,
		FetchedAtUnix: time.Now().Unix(),
		Windows:       overlayWindows(usage, login.plan),
	}
	if len(login.scopes) > 0 && !contains(login.scopes, "user:profile") {
		snap.Warnings = append(snap.Warnings, "the Claude Code login lacks the user:profile scope; plan usage may be unavailable")
	}
	return snap, nil
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
