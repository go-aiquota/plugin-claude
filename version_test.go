package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestVersionLinePrefersTheLinkTimeVersion(t *testing.T) {
	old := version
	t.Cleanup(func() { version = old })
	version = "v9.9.9"
	if got := versionLine(); got != "go-aiquota-plugin-claude v9.9.9" {
		t.Fatalf("got %q", got)
	}
	version = ""
	if got := versionLine(); !strings.HasPrefix(got, "go-aiquota-plugin-claude ") || len(got) <= len("go-aiquota-plugin-claude ") {
		t.Fatalf("got %q", got)
	}
}

// The built program, started as a user would, answers --version and exits 0
// without serving the plugin protocol.
func TestVersionFlagOfTheBuiltProgram(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "plugin")
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	if out, err := exec.Command("go", "build", "-ldflags=-X main.version=v1.2.3", "-o", exe, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	cmd := exec.Command(exe, "--version")
	cmd.Env = append(os.Environ(), "PATH=")
	out, err := cmd.Output()
	if err != nil || string(out) != "go-aiquota-plugin-claude v1.2.3\n" {
		t.Fatalf("got %q, %v", out, err)
	}
}
