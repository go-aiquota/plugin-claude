// Command plugin-claude is go-aiquota's QuotaProvider plugin for Claude
// (Max / Team Premium / Team Standard): a hashicorp/go-plugin subprocess,
// launched and dialed by go-aiquota/tray's quota.Manager, that turns an
// account's claude.ai session cookies into a QuotaSnapshot.
//
// The endpoint it calls (GET /api/organizations/{org_uuid}/usage) was found
// by watching claude.ai's own web app in a real WKWebView session — its own
// login page is behind Cloudflare's interactive JS challenge, which a
// scripted client cannot pass, so the account is onboarded through a real
// browser engine and only the resulting cookies (plus the org UUID the
// login response reveals) ever reach this plugin. See provider.go's own
// doc comment for the credential shape this expects.
package main

import (
	hcplugin "github.com/hashicorp/go-plugin"

	"github.com/go-aiquota/proto/plugin"
)

func main() {
	hcplugin.Serve(&hcplugin.ServeConfig{
		HandshakeConfig: plugin.Handshake,
		Plugins:         plugin.Map(&Provider{}),
		GRPCServer:      hcplugin.DefaultGRPCServer,
	})
}
