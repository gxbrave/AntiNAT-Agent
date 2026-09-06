// Package buildinfo exposes build metadata injected by the release build.
package buildinfo

import "fmt"

// These variables are deliberately exported so release builds can inject values
// with -ldflags -X without adding a runtime configuration dependency.
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// Info is the immutable build metadata presented by a binary.
type Info struct {
	Version string
	Commit  string
	Date    string
}

// Current returns the metadata compiled into this process.
func Current() Info {
	return Info{Version: Version, Commit: Commit, Date: Date}
}

// Format renders build metadata in a stable, log-safe form for version commands.
func Format(info Info) string {
	return fmt.Sprintf("version=%s commit=%s date=%s", info.Version, info.Commit, info.Date)
}
