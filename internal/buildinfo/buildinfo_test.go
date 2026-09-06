package buildinfo

import "testing"

func TestFormatIncludesInjectedBuildMetadata(t *testing.T) {
	got := Format(Info{
		Version: "v1.0.0-beta.1",
		Commit:  "abc123",
		Date:    "2026-08-09T08:00:00Z",
	})
	want := "version=v1.0.0-beta.1 commit=abc123 date=2026-08-09T08:00:00Z"
	if got != want {
		t.Fatalf("Format() = %q, want %q", got, want)
	}
}
