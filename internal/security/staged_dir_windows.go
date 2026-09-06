//go:build windows

package security

// Windows rename/remove operations are durable through the filesystem API;
// there is no portable directory fsync equivalent for this sidecar cleanup.
func syncDirForStaging(string) error { return nil }
