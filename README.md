<p align="center"><img src="https://raw.githubusercontent.com/go-aiquota/brand/main/social/go-aiquota.png" alt="go-aiquota/plugin-claude" width="720"></p>

# plugin-claude

[![CI](https://github.com/go-aiquota/plugin-claude/actions/workflows/ci.yml/badge.svg)](https://github.com/go-aiquota/plugin-claude/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-aiquota/plugin-claude.svg)](https://pkg.go.dev/github.com/go-aiquota/plugin-claude)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD--3--Clause-blue.svg)](LICENSE)

go-aiquota's [QuotaProvider](https://github.com/go-aiquota/proto) plugin for
Claude (Max / Team Premium / Team Standard): a
[hashicorp/go-plugin](https://github.com/hashicorp/go-plugin) subprocess,
launched and dialed by [go-aiquota/tray](https://github.com/go-aiquota/tray)'s
`quota.Manager`, that turns an account's claude.ai session cookies into a
`QuotaSnapshot`.

## Credential source "Claude Code" (preferred)

With `Credential = {"source": "claude-code"}` the plugin reads **Claude Code's
own login** at fetch time and shows the same account, plan, windows and
percentages as the VS Code extension's *Account & usage* panel. It never
refreshes or rotates that token (Claude Code renews its own login; a second
holder rotating the refresh token would sign it out): an expired token is
reported as `token expired, open Claude Code`.

- Storage (extension.js `yc`/`bc`, authentication docs "Credential
  management"): macOS Keychain item `Claude Code-credentials`, account `$USER`
  (+ `-<sha256(CLAUDE_CONFIG_DIR)[:8]>` when that variable is set), read with
  `/usr/bin/security find-generic-password -w`, which the item's ACL trusts, so
  there is no prompt and nothing to re-approve after a reinstall; otherwise
  `~/.claude/.credentials.json`. The secret travels on a pipe — never argv,
  environment or disk — and is held in a `secret.Secret`.
- Request: `GET https://api.anthropic.com/api/oauth/usage`,
  `Authorization: Bearer …`, `anthropic-beta: oauth-2025-04-20`,
  `User-Agent: claude-code/2.1.319`; TLS 1.2+, that host only, no redirects,
  1 MiB response cap. Errors are redacted of the token.
- **Every window the endpoint returns, by default.** The body is decoded as a
  map: each top-level value shaped `{utilization, resets_at}` is a window
  (known keys keep the panel's labels and order, `seven_day_opus` included;
  an unknown key gets a label derived from it, `seven_day_oauth_apps` becomes
  `Weekly (7 day) oauth apps`), then each `limits[]` entry the top level did
  not already report (label from its kind, group and scope: a model, or
  another scope). The pair of places is de-duplicated by an explicit key
  (`session`, `weekly_all`, `weekly_scoped/<model>`, the limit's own kind,
  `top/<field>`), not by label. A window with `utilization: null` is kept as
  `Unit: "n/a"` with a snapshot warning saying why; bare `null` fields of no
  known shape are not windows. A limit's severity other than `normal`/`ok` is
  a snapshot warning. At most 64 windows; the body is capped at 1 MiB.
  `Credential = {"source": "claude-code", "view": "overlay"}` returns exactly
  the panel's rows (below), for the equality check against the extension.
  `plugin-claude --raw-usage` prints the response body, indented (it holds no
  credential), and exits: `aiquota status -o json --raw` runs it.
- The overlay view's rows and labels as the panel (webview `WDn`): `Session (5hr)`,
  `Weekly (7 day)`, `Weekly Sonnet` (max/team/unknown plans), then
  `Weekly <model>` per model-scoped limit; a null window is not shown.
  Known approximation: the panel filters model-scoped rows through a remote
  allowlist (`tengu_usage_overage_included_models`) that this plugin cannot
  read, so it shows every model-scoped limit other than Sonnet/Opus.
- Fuzz targets: `FuzzDecodeUsage`, `FuzzDecodeCredential`.

## What it calls (claude.ai cookie source, the fallback)

`GET https://claude.ai/api/organizations/{org_uuid}/usage`, authenticated
purely by the account's claude.ai session cookies (no separate API key or
bearer token). This is the same endpoint claude.ai's own web app calls to
show the usage bar under Settings → Usage — found by watching a real,
authenticated browsing session's own network traffic (see
`go-aiquota/tray/capture`), not documented anywhere public.

The response's `limits[]` array — one entry per rate-limit window
(`session`, `weekly_all`, `weekly_scoped`, ...), each with a `percent` and a
`resets_at` — maps directly onto `quotapb.QuotaWindow`.

## Credential shape

`FetchQuotaRequest.Credential` needs:

- Every cookie name → value pair for the `claude.ai` domain (go-aiquota/tray's
  onboarding hands back the *whole* jar it captured; this plugin doesn't
  need to know which one cookie actually matters).
- `org_uuid`: the account's organization UUID. There is no page a scripted
  client can hit to rediscover this from cookies alone the way the real web
  app does on load — that path itself needs a real browser — so it must be
  captured once, at onboarding time, from the login response itself
  (`memberships[].organization.uuid`), and stored alongside the cookies.

A credential missing `org_uuid` fails clearly rather than guessing.

## Why claude.ai needs a real browser to onboard

claude.ai's own login page is behind Cloudflare's interactive JS challenge
(`cf-mitigated: challenge`, the "Just a moment..." interstitial), which a
scripted HTTP client — however TLS-fingerprint-conformant — cannot pass.
go-aiquota/tray's onboarding therefore drives a **real** browser engine
(WKWebView on macOS; go-webengine elsewhere, which works for providers
without this kind of protection) for the interactive login itself. Once
login completes, only the resulting cookies (and the org UUID) ever reach
this plugin — the plugin itself talks a plain, TLS-fingerprinted
(`go-browserhttp/browserhttp`) HTTP client to one authenticated JSON
endpoint, nothing more.

## Building and running standalone

```
go build -o go-aiquota-plugin-claude .
```

`go-aiquota/tray`'s `quota.Manager` looks for exactly that binary name on
`PATH`.
