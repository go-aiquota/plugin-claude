# plugin-claude

go-aiquota's [QuotaProvider](https://github.com/go-aiquota/proto) plugin for
Claude (Max / Team Premium / Team Standard): a
[hashicorp/go-plugin](https://github.com/hashicorp/go-plugin) subprocess,
launched and dialed by [go-aiquota/tray](https://github.com/go-aiquota/tray)'s
`quota.Manager`, that turns an account's claude.ai session cookies into a
`QuotaSnapshot`.

## What it calls

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
