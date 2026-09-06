package buildinfo

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestVersionCommandsReportLinkerInjectedMetadata(t *testing.T) {
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(testFile), "..", ".."))

	const (
		version = "v1.0.0-beta.test"
		commit  = "0123456789abcdef0123456789abcdef01234567"
		date    = "2026-08-09T12:34:56Z"
	)
	for _, test := range []struct {
		name string
		path string
	}{
		{name: "antinat-agent", path: "./cmd/antinat-agent"},
	} {
		t.Run(test.name, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), test.name)
			if runtime.GOOS == "windows" {
				binary += ".exe"
			}
			ldflags := fmt.Sprintf("-X github.com/gxbrave/AntiNAT-Agent/internal/buildinfo.Version=%s -X github.com/gxbrave/AntiNAT-Agent/internal/buildinfo.Commit=%s -X github.com/gxbrave/AntiNAT-Agent/internal/buildinfo.Date=%s", version, commit, date)
			build := exec.Command("go", "build", "-trimpath", "-ldflags", ldflags, "-o", binary, test.path)
			build.Dir = repoRoot
			if output, err := build.CombinedOutput(); err != nil {
				t.Fatalf("go build %s: %v\n%s", test.name, err, output)
			}

			run := exec.Command(binary, "version")
			output, err := run.CombinedOutput()
			if err != nil {
				t.Fatalf("%s version: %v\n%s", test.name, err, output)
			}
			want := fmt.Sprintf("%s version=%s commit=%s date=%s\n", test.name, version, commit, date)
			if string(output) != want {
				t.Fatalf("%s version output = %q, want %q", test.name, strings.TrimSpace(string(output)), strings.TrimSpace(want))
			}
		})
	}
}
