// Copyright (c) the go-aiquota authors.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"

	hcplugin "github.com/hashicorp/go-plugin"

	"github.com/go-aiquota/proto/plugin"
	"github.com/go-aiquota/proto/quotapb"
)

// reexecEnv lets this same test binary act as the real plugin subprocess:
// go-plugin's own recommended pattern for testing a real client/subprocess
// round trip without a separately built binary — established in
// go-aiquota/proto/plugin's own poison-credential test.
const reexecEnv = "PLUGIN_CLAUDE_TEST_SERVE"

func TestMain(m *testing.M) {
	if os.Getenv(reexecEnv) == "1" {
		main() // the real subprocess entrypoint, completely unmodified
		return
	}
	os.Exit(m.Run())
}

// TestLiveSubprocessFetchesQuota launches THIS test binary as a genuine
// go-plugin subprocess and dials it exactly the way go-aiquota/tray's
// quota.Manager does — real handshake, real AutoMTLS gRPC — proving
// main.go's actual wiring (not just the Provider struct in isolation)
// works end to end, including reaching a real HTTP server. The subprocess
// is a separate process and cannot see this one's baseURL variable, so it
// is redirected via PLUGIN_CLAUDE_BASE_URL instead (see provider.go's
// init).
func TestLiveSubprocessFetchesQuota(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(usageFixture))
	}))
	defer srv.Close()

	exePath, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(exePath, "-test.run=^TestMain$")
	cmd.Env = append(os.Environ(), reexecEnv+"=1", baseURLEnv+"="+srv.URL)

	client := hcplugin.NewClient(&hcplugin.ClientConfig{
		HandshakeConfig:  plugin.Handshake,
		Plugins:          plugin.Map(nil),
		Cmd:              cmd,
		AllowedProtocols: []hcplugin.Protocol{hcplugin.ProtocolGRPC},
		AutoMTLS:         true,
	})
	defer client.Kill()

	rpcClient, err := client.Client()
	if err != nil {
		t.Fatalf("client.Client: %v", err)
	}
	raw, err := rpcClient.Dispense(plugin.Key)
	if err != nil {
		t.Fatalf("Dispense: %v", err)
	}
	quotaClient, ok := raw.(quotapb.QuotaProviderClient)
	if !ok {
		t.Fatalf("Dispense returned %T, want quotapb.QuotaProviderClient", raw)
	}

	info, err := quotaClient.Describe(context.Background(), &quotapb.DescribeRequest{})
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	if info.Name != "claude" {
		t.Fatalf("Describe().Name = %q, want %q", info.Name, "claude")
	}

	resp, err := quotaClient.FetchQuota(context.Background(), &quotapb.FetchQuotaRequest{
		AccountLabel: "acct-1",
		Credential:   map[string]string{"org_uuid": "org-123", "session": "tok-abc"},
	})
	if err != nil {
		t.Fatalf("FetchQuota: %v", err)
	}
	if resp.AccountLabel != "acct-1" || len(resp.Windows) != 3 {
		t.Fatalf("unexpected response shape: %+v", resp)
	}
}
